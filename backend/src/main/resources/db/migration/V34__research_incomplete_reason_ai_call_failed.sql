-- V34__research_incomplete_reason_ai_call_failed.sql
-- research_incomplete_reason (V12, CHECK constraint added by V33) covered Stage4's two orderly
-- "never actually ran" skips (AI_NOT_AVAILABLE, BUDGET_EXHAUSTED) but not the case where Stage4 was
-- attempted -- a Claude key is configured and budget was available -- but the call itself did not run
-- to completion (LLM service down, timeout, network error, ...). ResearchJobProcessingService's
-- Stage4 try/catch only logged that exception, leaving researchIncompleteReason at the null Stage2
-- already set, so the item rendered identically to a genuine, fully-verified all-clear -- same class
-- of bug as V33, but on a condition (LLM service unavailability) that is more common in practice than
-- a fully exhausted budget.
--   - AI_CALL_FAILED: Stage4 was attempted but did not run to completion; the reservation made for
--     the attempt is refunded in full regardless (JobCostBudgetService#reconcile treats a failed
--     call's actual cost as $0), so this reason is about a verification gap, not a spend.
-- See ResearchJobProcessingService's Stage4 catch block and ResearchJobItem
-- #INCOMPLETE_REASON_AI_CALL_FAILED.

ALTER TABLE research_job_items DROP CONSTRAINT research_job_items_research_incomplete_reason_check;

ALTER TABLE research_job_items ADD CONSTRAINT research_job_items_research_incomplete_reason_check
    CHECK (research_incomplete_reason IN
        ('SOURCES_FAILED', 'IDENTIFICATION_TOO_WEAK', 'AI_NOT_AVAILABLE', 'BUDGET_EXHAUSTED', 'AI_CALL_FAILED'));
