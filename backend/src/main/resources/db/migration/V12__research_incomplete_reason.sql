-- V12__research_incomplete_reason.sql
-- Replaces the single vulnerability_research_incomplete boolean (V11) with a nullable reason code,
-- because "not fully verified" turned out to have more than one distinct cause that the UI needs to
-- tell apart:
--   - SOURCES_FAILED: Stage2 ran but every VulnerabilitySource failed (rate limit, network error,
--     ...), so nothing was actually checked. This is what V11 captured.
--   - IDENTIFICATION_TOO_WEAK: Stage2 genuinely found zero (every source that ran succeeded), but
--     Stage4's AI web-search fallback was deliberately skipped because the item's identification
--     confidence was at/below STAGE4_MIN_IDENTIFICATION_CONFIDENCE (see
--     ResearchJobProcessingService). Collapsing this into the same "clean" bucket as a true all-clear
--     re-introduced the exact false-negative rendering bug V11 fixed, one file away: a weak guess at
--     the product, combined with a deliberately-skipped verification pass, rendered identically to a
--     verified all-clear.
-- NULL means fully verified (or verification wasn't applicable, e.g. the item was never Stage2'd).

ALTER TABLE research_job_items ADD COLUMN research_incomplete_reason VARCHAR(30);

UPDATE research_job_items
SET research_incomplete_reason = 'SOURCES_FAILED'
WHERE vulnerability_research_incomplete = true;

ALTER TABLE research_job_items DROP COLUMN vulnerability_research_incomplete;
