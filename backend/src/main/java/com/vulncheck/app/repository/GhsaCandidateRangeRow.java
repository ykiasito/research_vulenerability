package com.vulncheck.app.repository;

/** One row of {@link GhsaVulnerabilityLookupRepository#findCandidateRanges}'s result — advisory
 *  fields are repeated per range row (denormalized join). {@code rangeType}/{@code
 *  introducedVersion}/{@code fixedVersion}/{@code lastAffectedVersion} are always non-null (the
 *  underlying query is an INNER JOIN against {@code ghsa_affected_ranges} — see that method's own
 *  javadoc); a package with no range rows at all simply never produces a row here, and is instead
 *  covered independently by {@link GhsaCandidateVersionRow}'s exact-version-list query. */
public record GhsaCandidateRangeRow(
        Long affectedPackageId,
        String ghsaId,
        String cveId,
        String summary,
        String severity,
        String htmlUrl,
        String rangeType,
        String introducedVersion,
        String fixedVersion,
        String lastAffectedVersion) {
}
