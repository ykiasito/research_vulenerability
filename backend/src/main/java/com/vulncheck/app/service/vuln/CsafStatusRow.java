package com.vulncheck.app.service.vuln;

/** One (CVE, product) status row joined with its parent advisory's own metadata — the shape {@link
 *  com.vulncheck.app.repository.CsafProductStatusRepositoryCustom#findFinalStatuses} returns.
 *
 *  @param vendor which CSAF vendor this row came from (REVISE item 8, senior review 2026-08-27) —
 *                needed once {@link com.vulncheck.app.repository.CsafProductStatusRepositoryCustom
 *                #findFinalStatuses} became a single batched query across every surviving candidate
 *                (potentially several vendors at once, in a future multi-vendor phase), so the caller
 *                can no longer assume "whichever vendor I was iterating when I called this".
 *  @param fixedVersion vendor-native free-text remediation ({@code csaf_product_status.fixed_version}
 *                — despite the name, NOT a clean parseable version; see V17's migration comment).
 *                Never used for version comparison — see {@code productComponentVersion} below for
 *                that.
 *  @param productComponentVersion the underlying {@code csaf_products.component_version} for this
 *                row's specific product node (REVISE item 2, senior review 2026-08-27) — unlike
 *                {@code fixedVersion} above, this IS the clean, purl-derived (for Red Hat) EVR-shaped
 *                version string {@link com.vulncheck.app.service.vuln.RpmEvrComparator} can compare.
 *                Needed because a single product node can carry DIFFERENT statuses for different CVEs
 *                (see {@code CsafDocumentUpsertServiceTest}'s real RHEA-2014:1175 fixture), so the
 *                real-RPM-version gate has to apply per STATUS ROW, not per candidate — see {@code
 *                CsafVulnerabilitySource#passesRedHatFixedVersionGate}. */
public record CsafStatusRow(
        String vendor,
        String cveId,
        String status,
        String fixedVersion,
        String remediationUrl,
        String advisoryId,
        String advisoryTitle,
        String advisoryCvssSeverity,
        String productComponentVersion) {
}
