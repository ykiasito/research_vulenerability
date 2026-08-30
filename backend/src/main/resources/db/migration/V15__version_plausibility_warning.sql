-- V15__version_plausibility_warning.sql
-- Job-level flag, computed once at job completion (see ResearchJobProcessingService), warning the
-- user that this job's CSV version values may not correspond to real published releases: fires
-- when >=30 items resolved to a registry (ecosystem+purl both set) AND fewer than half of those
-- had version_confirmed=true. Surfaced alongside results in the job-detail view — never a hard
-- failure or a block on job completion.
ALTER TABLE research_jobs ADD COLUMN version_plausibility_warning boolean NOT NULL DEFAULT false;
