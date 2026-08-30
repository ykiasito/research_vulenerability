package com.vulncheck.app.service.vuln;

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
 */
public record VulnFinding(
        String cveOrGhsaId,
        String source,
        String severity,
        String description,
        String url,
        String fixedVersion,
        String csafAdvisoryId,
        String csafStatus) {

    /** Convenience constructor for every non-CSAF source (NVD/OSV/GHSA/CVE.org/bundled-component) —
     *  fills the two CSAF-only fields with null so none of those call sites need to change. */
    public VulnFinding(String cveOrGhsaId, String source, String severity, String description, String url, String fixedVersion) {
        this(cveOrGhsaId, source, severity, description, url, fixedVersion, null, null);
    }
}
