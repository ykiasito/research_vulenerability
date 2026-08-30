-- V23__job_cost_ledger.sql
-- Persists JobCostBudgetService's reserve/reconcile outcomes so a completed job's actual Claude
-- API spend can be queried after the fact (docs/spec/infra-rollout-plan.md item 5). Previously
-- this lived only in an in-memory ConcurrentHashMap, which made the $5/1,000-item cost target
-- unmeasurable rather than merely "not yet measured".
--
-- One row per reconcile() call (i.e. per AI call attempt whose outcome, success or failure, is
-- now known), not per reservation: a reservation still in flight has no actual cost yet to record,
-- and every successful reservation is always followed by exactly one reconcile call (see
-- LlmServiceClient#reconcile/#reconcileBundled), so this table ends up a complete record of
-- realized spend. job_item_id lets "$/item average" be computed either from this table's own rows
-- (COUNT(DISTINCT job_item_id) among items that made at least one AI call) or, more accurately for
-- comparing against the $5/1,000-item target, against the job's total item count via a join with
-- research_job_items.
--
-- Additive-only per the Flyway Community Edition rollback constraint (see
-- infra-rollout-plan.md item 5, "rollback procedure" section): this migration only creates a new
-- table, with foreign keys pointing at existing tables — it does not alter any existing table, so
-- rolling the application JAR back to a pre-V23 version remains safe (the old JAR simply never
-- reads or writes this table).
CREATE TABLE job_cost_ledger (
    id                BIGSERIAL PRIMARY KEY,
    job_id            BIGINT NOT NULL REFERENCES research_jobs (id) ON DELETE CASCADE,
    job_item_id       BIGINT REFERENCES research_job_items (id) ON DELETE CASCADE,
    -- 'MAIN' = the always-on per-item budget (JobCostBudgetService#tryReserve/#reconcile);
    -- 'BUNDLED_COMPONENT' = the separate opt-in bundled-package-detection budget
    -- (#tryReserveBundledComponent/#reconcileBundledComponent). Kept as two ledger values in one
    -- table (not two tables) so both can be queried/summed together per job when needed, while
    -- still being filterable back apart — mirrors the two-ledgers-in-one-class shape the service
    -- itself already uses (see JobCostBudgetService's class javadoc).
    ledger            VARCHAR(30) NOT NULL CHECK (ledger IN ('MAIN', 'BUNDLED_COMPONENT')),
    reserved_cost_usd NUMERIC(12, 6) NOT NULL,
    actual_cost_usd   NUMERIC(12, 6) NOT NULL,
    recorded_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Every "$/item average for this job" query filters/aggregates by job_id.
CREATE INDEX idx_job_cost_ledger_job_id ON job_cost_ledger (job_id);
