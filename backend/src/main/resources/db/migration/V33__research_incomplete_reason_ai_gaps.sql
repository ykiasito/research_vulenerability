-- V33__research_incomplete_reason_ai_gaps.sql
-- research_incomplete_reason (V12) previously covered only two causes (SOURCES_FAILED,
-- IDENTIFICATION_TOO_WEAK), both of which happen after Stage2. It never distinguished Stage4's own
-- two "never actually ran" exits -- no Claude API key configured for the job owner, or the job's AI
-- cost budget already exhausted -- from a genuine, fully-verified all-clear. Since an unconfigured
-- API key is this app's default state, every item whose Stage2 pass found zero collapsed into the
-- same "checked, nothing found" rendering as a real clean result, even though the AI verification
-- pass never ran at all.
--   - AI_NOT_AVAILABLE: Stage4 skipped because no Claude API key is registered for the job owner.
--   - BUDGET_EXHAUSTED: Stage4 skipped because the job's AI cost budget was already used up.
-- See Stage4WebSearchResearchService#research and ResearchJobItem's INCOMPLETE_REASON_* constants.
--
-- No existing CHECK constraint covered this column (V12 added it as a plain nullable VARCHAR), so
-- this adds the first one, covering both the two pre-existing values and the two new ones.

ALTER TABLE research_job_items ADD CONSTRAINT research_job_items_research_incomplete_reason_check
    CHECK (research_incomplete_reason IN
        ('SOURCES_FAILED', 'IDENTIFICATION_TOO_WEAK', 'AI_NOT_AVAILABLE', 'BUDGET_EXHAUSTED'));
