-- V29__verification_ledger.sql
-- REVISE item 1 (senior review 2026-08-29): splits the high-confidence AI verification backstop
-- (HighConfidenceVerificationService) off of job_cost_ledger's always-on MAIN ledger into its own
-- VERIFICATION ledger, mirroring the existing BUNDLED_COMPONENT ledger's structure exactly (see
-- JobCostBudgetService#verificationCostCapPerItemUsd's javadoc for why: job 191 real data found
-- 108/300 items eligible for verification, whose demand ($3.78) was 2.5x a 300-item job's own MAIN
-- budget ($1.50) -- sharing MAIN meant enabling this feature could exhaust a job's entire AI
-- allowance from the first CSV rows alone, silently starving every later item's Tier2/Tier3 calls).
--
-- V28 already added 'VERIFICATION' to job_cost_ledger.call_site's CHECK constraint (which endpoint
-- made the call) -- that is unaffected here. This migration only widens the separate `ledger` column
-- (V23's CHECK constraint; which budget the call drew against) to also allow 'VERIFICATION', so a
-- call_site='VERIFICATION' row can now be persisted with ledger='VERIFICATION' instead of
-- ledger='MAIN'. V28 cannot be edited in place to make this same change (Flyway checksum
-- validation), hence a new migration.
--
-- Additive-only (same rollback posture as V27/V28): existing MAIN-ledger rows with
-- call_site='VERIFICATION', if any were written before this migration ran, are left as-is -- no
-- backfill, since this app has not yet had the feature enabled against real Claude API traffic (see
-- docs/spec/nfr-status-2026-08.md).
ALTER TABLE job_cost_ledger DROP CONSTRAINT job_cost_ledger_ledger_check;
ALTER TABLE job_cost_ledger ADD CONSTRAINT job_cost_ledger_ledger_check
    CHECK (ledger IN ('MAIN', 'BUNDLED_COMPONENT', 'VERIFICATION'));
