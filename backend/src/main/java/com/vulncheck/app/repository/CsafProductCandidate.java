package com.vulncheck.app.repository;

/** One trgm-candidate row from {@link CsafProductRepositoryCustom#findCandidateProducts}. */
public record CsafProductCandidate(
        String vendor,
        String advisoryId,
        String csafProductId,
        String componentName,
        String componentVersion,
        String platformName) {
}
