package com.vulncheck.app.service.vuln;

import java.math.BigDecimal;

/**
 * A single vulnerability found by one Stage2 source for one job item. {@code source} identifies
 * which API produced it (nvd/osv/ghsa) — stored as {@code job_item_vulnerabilities.discovered_via_tier}.
 *
 * @param fixedVersion the version this vulnerability is fixed in, when the source's own
 *                      structured data says so (NVD's {@code versionEndExcluding}, OSV's
 *                      {@code fixed} range event, GHSA's {@code patched_versions}) — free,
 *                      no extra API call. Null when the source didn't provide one (e.g. no fix
 *                      released yet, or the source's range shape didn't have a clean answer).
 *                      For a CSAF finding this instead carries the vendor's own (often NEVRA,
 *                      non-semver) fixed-version text — see {@code csafAdvisoryId}'s javadoc for
 *                      why that's safe.
 * @param csafAdvisoryId non-null only for a finding from {@code CsafVulnerabilitySource} — the
 *                        CSAF {@code tracking.id} the status/fixedVersion came from.
 *                        {@code Stage2VulnerabilityResearchService} routes any finding with a
 *                        non-null value here through the CSAF annotation path (plan §8-2) instead
 *                        of the ordinary competing-finding {@code putIfAbsent} path, and never
 *                        lets its {@code fixedVersion} reach {@code vulnerabilities.fixed_version}.
 * @param csafStatus non-null only alongside {@code csafAdvisoryId} — one of
 *                    'fixed'/'known_affected'/'known_not_affected'/'under_investigation'.
 * @param cvssScore numeric CVSS base score (V40, closed-mode backlog item 251) — populated only by
 *                   {@code NvdVulnerabilitySource}'s mirror-backed path, from {@code
 *                   nvd_cve_records.cvss_score}. Every other source passes null via the 6-arg
 *                   convenience constructor below; {@code VulnerabilityRepository}/{@code
 *                   VulnerabilityBatchWriter}'s upsert COALESCEs it so a null write never regresses
 *                   an existing non-null score for the same {@code cveOrGhsaId}. Drives the
 *                   write-safety cap's CVSS-priority truncation and the read-side display cap's
 *                   ranking (see {@code JobItemVulnerabilityRepository}).
 */
public record VulnFinding(
        String cveOrGhsaId,
        String source,
        String severity,
        String description,
        String url,
        String fixedVersion,
        String csafAdvisoryId,
        String csafStatus,
        BigDecimal cvssScore) {

    /** Convenience constructor for every non-CSAF, non-CVSS-scored source (OSV/GHSA/CVE.org/
     *  bundled-component adjudication's OSV leg) — fills the two CSAF-only fields and cvssScore with
     *  null so none of those call sites need to change. */
    public VulnFinding(String cveOrGhsaId, String source, String severity, String description, String url, String fixedVersion) {
        this(cveOrGhsaId, source, severity, description, url, fixedVersion, null, null, null);
    }

    /** Convenience constructor for {@link CsafVulnerabilitySource} — the existing 8-field shape,
     *  preserved unchanged so that class's call sites don't need to change; cvssScore is null (CSAF
     *  advisories don't carry a CVSS score in this app's current data model). */
    public VulnFinding(String cveOrGhsaId, String source, String severity, String description, String url,
            String fixedVersion, String csafAdvisoryId, String csafStatus) {
        this(cveOrGhsaId, source, severity, description, url, fixedVersion, csafAdvisoryId, csafStatus, null);
    }

    /** Convenience constructor for {@code NvdVulnerabilitySource}'s mirror-backed path only — the
     *  one non-CSAF source that has a real CVSS score to report. Csaf-only fields are null. */
    public VulnFinding(String cveOrGhsaId, String source, String severity, String description, String url,
            String fixedVersion, BigDecimal cvssScore) {
        this(cveOrGhsaId, source, severity, description, url, fixedVersion, null, null, cvssScore);
    }
}
