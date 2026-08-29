-- V4__identification_hint.sql
-- Supplementary human-readable hint for items Tier3 could not fully resolve into a queryable
-- ecosystem/CPE, but for which the AI still recognized a platform-specific identifier (e.g. a
-- VS Code Marketplace extension id) that a person could use to verify/install manually.

ALTER TABLE research_job_items ADD COLUMN identification_hint TEXT;
