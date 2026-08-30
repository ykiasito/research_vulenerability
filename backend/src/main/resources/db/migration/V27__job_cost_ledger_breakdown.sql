-- V27__job_cost_ledger_breakdown.sql
-- Adds per-call breakdown columns to job_cost_ledger so the reservation constants in
-- JobCostBudgetService (TIER2_DISAMBIGUATE_COST_USD / TIER3_WEB_SEARCH_IDENTIFY_COST_USD /
-- STAGE4_WEB_SEARCH_RESEARCH_COST_USD / BUNDLED_COMPONENT_*_COST_USD) can be re-derived straight
-- from SQL (e.g. percentile input/output tokens and web_search_requests per call_site) instead of
-- grepping llm-service log files, which is how the job 185 cost investigation (2026-08-29,
-- ~2.57x-over-estimate scare, see docs/spec/nfr-status-2026-08.md's cost section) had to be done
-- the first time.
--
-- Previously job_cost_ledger (V23) only stored the aggregate reserved_cost_usd/actual_cost_usd in
-- dollars, with no way to tell which call site (Tier2 disambiguate vs Tier3 web-search-identify
-- vs Stage4 web-search-research vs the two bundled-component-detection calls) a row came from, nor
-- the raw token/web-search counts computeActualCost derived actual_cost_usd from.
--
-- Additive-only, nullable (same rollback posture as V26): rows written by a pre-V27 application
-- JAR (there are currently zero rows in this table — no live Claude API spend has occurred yet,
-- see nfr-status-2026-08.md) have no breakdown to backfill from and stay NULL forever; nothing
-- downstream reads these columns as NOT NULL.
ALTER TABLE job_cost_ledger ADD COLUMN input_tokens INTEGER;
ALTER TABLE job_cost_ledger ADD COLUMN output_tokens INTEGER;
ALTER TABLE job_cost_ledger ADD COLUMN web_search_requests INTEGER;

-- Distinct from `ledger` (MAIN/BUNDLED_COMPONENT, which budget this call drew against) — this is
-- *which AI call site within that budget* actually made the call, matching llm-service/main.py's
-- endpoints one-to-one:
--   TIER2              -> POST /v1/identify/disambiguate            (ledger=MAIN)
--   TIER3              -> POST /v1/identify/web-search               (ledger=MAIN)
--   STAGE4             -> POST /v1/research/web-search                (ledger=MAIN)
--   BUNDLED_CHANGELOG  -> POST /v1/bundled-components/discover-changelog (ledger=BUNDLED_COMPONENT)
--   BUNDLED_EXTRACT    -> POST /v1/bundled-components/extract         (ledger=BUNDLED_COMPONENT)
ALTER TABLE job_cost_ledger ADD COLUMN call_site VARCHAR(30)
    CHECK (call_site IN ('TIER2', 'TIER3', 'STAGE4', 'BUNDLED_CHANGELOG', 'BUNDLED_EXTRACT'));
