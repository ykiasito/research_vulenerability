-- V41__backfill_max_fixed_version.sql
-- Closed-mode backlog item 251 (B4), second senior-reviewer REVISE round, item 5: V40 added
-- research_job_items.max_fixed_version but only backfilled vulnerabilities.cvss_score, not this new
-- column. JobController#highestFixedVersion (which used to compute this at render time, scanning
-- every item's persisted findings) was removed in the same PR and detail.html now reads
-- item.max_fixed_version directly -- without this backfill, every item processed before V40 would
-- permanently show no "推奨アップデート版" (recommended upgrade version) at all unless the job is
-- re-processed from scratch.

-- Same exclusion rules the removed JobController#highestFixedVersion applied: bundled-component
-- findings never contribute (a bundled component's own fix version is not the product's), and a
-- CSAF-only new row (discovered_via_tier starting with "csaf_") never carries a real fixed_version
-- write on vulnerabilities itself (Stage2's path-2 always inserts NULL there -- see
-- Stage2VulnerabilityResearchService's class javadoc), so excluding it here is defense-in-depth
-- matching that invariant, not a behavior change.
--
-- IMPORTANT CAVEAT (documented here, not silently accepted): MAX(v.fixed_version) below is a plain
-- SQL string MAX over a TEXT column -- lexical ("10.0.0" < "9.0.0" would be simply wrong under
-- lexical ordering, since '1' < '9' as characters) -- NOT the numeric-segment-aware comparison
-- Stage2VulnerabilityResearchService#highestFixedVersion actually uses via VersionUtils.compare.
-- For the overwhelmingly common "X.Y.Z"-shaped version strings this is usually correct anyway (SQL
-- MAX still resolves ties/most real-world sequences correctly at equal segment-count and width), but
-- it is only an approximation, not the exact algorithm the application uses going forward for any
-- item Stage2 (re-)processes. The only exact path for an existing item is a real re-run of that job
-- (or the item) through Stage2, which recomputes max_fixed_version via VersionUtils.compare from
-- scratch and overwrites whatever this migration wrote. This backfill exists purely so pre-V40 jobs
-- don't silently lose the recommended-upgrade-version feature entirely while they wait for that.
UPDATE research_job_items rji
SET max_fixed_version = backfill.max_fixed_version
FROM (
    SELECT jiv.job_item_id, MAX(v.fixed_version) AS max_fixed_version
    FROM job_item_vulnerabilities jiv
    JOIN vulnerabilities v ON v.id = jiv.vulnerability_id
    WHERE jiv.bundled_component_name IS NULL
      AND LEFT(jiv.discovered_via_tier, 5) <> 'csaf_'
      AND v.fixed_version IS NOT NULL
    GROUP BY jiv.job_item_id
) backfill
WHERE rji.id = backfill.job_item_id
  AND rji.max_fixed_version IS NULL;
