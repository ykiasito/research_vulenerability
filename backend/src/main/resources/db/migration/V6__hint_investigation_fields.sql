-- V6__hint_investigation_fields.sql
-- Structured platform/identifier behind identification_hint's display text, so that a follow-up
-- vulnerability investigation can be run using the identifier even though the item never got a
-- queryable ecosystem/CPE match.

ALTER TABLE research_job_items ADD COLUMN hint_platform TEXT;
ALTER TABLE research_job_items ADD COLUMN hint_identifier TEXT;
