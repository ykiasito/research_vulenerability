-- V40__vulnerabilities_cvss_score_and_max_fixed_version.sql
-- Closed-mode backlog item 251 (B4, NvdVulnerabilitySource mirror-only cutover) + senior-reviewer
-- REVISE items 3/5/6 on this task's design: display-cap ranking needs a numeric CVSS score
-- (severity alone is a 4-value band, not a sortable score), and the "recommended upgrade version"
-- feature (JobController's old highestFixedVersion) moves to Stage2VulnerabilityResearchService,
-- computed once per item from that item's own in-memory findings rather than re-derived from the
-- rendered/exported (now display-capped) findings list.

-- cvss_score: numeric CVSS base score, populated by NvdVulnerabilitySource's mirror path from
-- nvd_cve_records.cvss_score (other sources -- OSV/GHSA/CVE.org/CSAF/bundled -- leave this NULL;
-- VulnerabilityRepository#upsertAndGetId/VulnerabilityBatchWriter's ON CONFLICT COALESCE never lets
-- a NULL write clobber an existing non-NULL score written by an earlier NVD-sourced upsert for the
-- same cve_or_ghsa_id). Ranking expressions treat NULL as severity-band-equivalent (see
-- NvdVulnerabilitySource/JobItemVulnerabilityRepository's own SQL, not this migration) rather than
-- NULLS LAST, so an as-yet-unscored CVE isn't structurally pushed to the bottom of a display cap.
ALTER TABLE vulnerabilities ADD COLUMN cvss_score NUMERIC;

-- Backfill from the already-synced NVD mirror -- without this, every pre-existing job's display-cap
-- ranking would see NULL cvss_score for its NVD-sourced findings and, in a single fresh backfill,
-- surface "whichever 10 rows happen to sort first" rather than a genuinely CVSS-ordered top 10.
-- Measured live (2026-09-03, closed-mode backlog item 251 design review): 5,958 of 7,854 existing
-- vulnerabilities rows (76%) have a cve_or_ghsa_id that matches an nvd_cve_records row and fills in
-- immediately. A brand-new deployment has an empty nvd_cve_records (mirror backfill not run yet),
-- so this UPDATE simply matches zero rows there -- safe no-op, not an error.
UPDATE vulnerabilities v
SET cvss_score = r.cvss_score
FROM nvd_cve_records r
WHERE r.cve_id = v.cve_or_ghsa_id
  AND v.cvss_score IS NULL
  AND r.cvss_score IS NOT NULL;

-- max_fixed_version: the single highest recommended-upgrade version across an item's own Stage2
-- findings (union of every non-CSAF source, computed once by Stage2VulnerabilityResearchService
-- from its own in-memory VulnFinding list -- see that class's javadoc for why this is safer than
-- JobController's old approach of re-deriving it from the persisted, globally-shared
-- vulnerabilities.fixed_version column at render time). NULL when Stage2 hasn't run for this item
-- yet, or none of its findings carry a fixedVersion.
ALTER TABLE research_job_items ADD COLUMN max_fixed_version TEXT;
