package com.vulncheck.app.repository;

/** One row of {@link GhsaVulnerabilityLookupRepository#findCandidateVersions}'s result — the exact-
 *  version-list side of candidate matching, independent of {@link GhsaCandidateRangeRow}'s range
 *  evaluation (see V19's migration comment on {@code ghsa_affected_versions}). */
public record GhsaCandidateVersionRow(
        Long affectedPackageId,
        String ghsaId,
        String cveId,
        String summary,
        String severity,
        String htmlUrl,
        String version) {
}
