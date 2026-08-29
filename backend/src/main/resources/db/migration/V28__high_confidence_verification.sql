-- V28__high_confidence_verification.sql
-- Adds the schema needed for the high-confidence AI verification step (docs/spec/known-limitations.md
-- "registry match's confidence is lent to an independently-derived CPE" gap): a backstop AI+web_search
-- check for Stage1 items that reached IDENTIFIED_CPE status purely via Tier1 static logic (registry +
-- CPE dictionary) at high confidence, without ever going through Tier2/Tier3 AI disambiguation.
--
-- Feature is off by default (app.high-confidence-verification.enabled=false in application.yml), so
-- these columns stay NULL for every existing row and every row written while the feature is disabled.

-- Outcome of the verification call for this identified product, or NULL when verification never ran
-- (feature disabled, item not eligible, no Claude key, budget exhausted, or the call itself failed —
-- all of which degrade to "trust the static match as-is", same as every other AI tier in this app).
--   CONFIRMED  -- AI agrees the static CPE vendor:product is correct. No other field changes.
--   INCORRECT  -- AI is reasonably confident the static CPE is simply wrong. Confidence is downgraded
--                 (and the CPE dropped) per HighConfidenceVerificationService's configurable rule.
--   AMBIGUOUS  -- AI found multiple genuinely plausible variants (e.g. a Windows vs. Mac build of the
--                 same product) and could not tell which one the static match should have picked.
--                 Distinct from INCORRECT: the existing match is not necessarily wrong, so confidence
--                 is left untouched -- this is a "needs human selection" flag, not a downgrade.
ALTER TABLE identified_products ADD COLUMN verification_status VARCHAR(20)
    CHECK (verification_status IN ('CONFIRMED', 'INCORRECT', 'AMBIGUOUS'));

-- Free-text explanation behind verification_status: the AI's reasoning (CONFIRMED/INCORRECT) or a
-- human-readable list of the plausible candidate variants (AMBIGUOUS) -- shown in the job detail view
-- so a human reviewing an AMBIGUOUS/INCORRECT item has something to act on, not just a bare label.
ALTER TABLE identified_products ADD COLUMN verification_note TEXT;

-- New call site for job_cost_ledger.call_site (V27's CHECK constraint) -- this verification step is
-- its own llm-service endpoint (/v1/identify/verify-high-confidence), tracked against the same
-- always-on MAIN ledger as TIER2/TIER3/STAGE4 (see JobCostBudgetService#HIGH_CONFIDENCE_VERIFICATION_COST_USD).
ALTER TABLE job_cost_ledger DROP CONSTRAINT job_cost_ledger_call_site_check;
ALTER TABLE job_cost_ledger ADD CONSTRAINT job_cost_ledger_call_site_check
    CHECK (call_site IN ('TIER2', 'TIER3', 'STAGE4', 'BUNDLED_CHANGELOG', 'BUNDLED_EXTRACT', 'VERIFICATION'));
