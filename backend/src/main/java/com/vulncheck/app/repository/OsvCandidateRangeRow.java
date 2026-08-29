package com.vulncheck.app.repository;

/** One row of {@link OsvVulnerabilityLookupRepository#findCandidateRanges}'s result — advisory
 *  fields are repeated per range row (denormalized join). {@code rangeType}/{@code
 *  introducedVersion}/{@code fixedVersion}/{@code lastAffectedVersion} are always non-null (the
 *  underlying query is an INNER JOIN against {@code osv_affected_ranges}); a package with no range
 *  rows at all simply never produces a row here, and is instead covered independently by {@link
 *  OsvCandidateVersionRow}'s exact-version-list query.
 *
 * @param findingId the id to emit as this finding's {@code cveOrGhsaId}, already resolved in SQL
 *                  via {@code COALESCE(o.cve_id, g.cve_id, o.ghsa_id, o.osv_id)} — see {@code
 *                  docs/spec/osv-mirror-plan.md} §5-2/§7-1 for why the {@code ghsa_advisories} LEFT
 *                  JOIN is needed here (an OSV record's own {@code aliases[]} can be missing a
 *                  CVE-ID that the GHSA mirror's copy of the same advisory does carry). */
public record OsvCandidateRangeRow(
        Long affectedPackageId,
        String osvId,
        String findingId,
        String summary,
        String severity,
        String htmlUrl,
        String rangeType,
        String introducedVersion,
        String fixedVersion,
        String lastAffectedVersion) {
}
