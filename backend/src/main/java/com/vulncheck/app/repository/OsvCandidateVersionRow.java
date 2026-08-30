package com.vulncheck.app.repository;

/** One row of {@link OsvVulnerabilityLookupRepository#findCandidateVersions}'s result — the exact-
 *  version-list side of candidate matching, independent of {@link OsvCandidateRangeRow}'s range
 *  evaluation (see V25's migration comment on {@code osv_affected_versions}). {@code findingId} is
 *  the same COALESCE-resolved id as {@link OsvCandidateRangeRow#findingId()}. */
public record OsvCandidateVersionRow(
        Long affectedPackageId,
        String osvId,
        String findingId,
        String summary,
        String severity,
        String htmlUrl,
        String version) {
}
