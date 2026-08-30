package com.vulncheck.app.service.vuln;

import java.util.Locale;

/**
 * Per-ecosystem package name normalization applied identically at ingest time ({@code
 * GhsaDocumentUpsertService}, writing {@code ghsa_affected_packages.package_name_normalized}) and
 * query time ({@code GhsaVulnerabilitySource#find}) — see {@code
 * docs/spec/ghsa-mirror-plan.md} §3-1(D). GitHub's server used to absorb this spelling variance for
 * the old per-item live implementation (the {@code affects=} query parameter); mirroring locally
 * makes it this app's own responsibility.
 *
 * <p>Ecosystem keys here are this app's own internal keys (npm/pypi/maven/...), the same ones
 * {@code GhsaVulnerabilitySource}'s {@code ECOSYSTEM_MAP} and {@code IdentifiedProduct#getEcosystem}
 * use — not GHSA/OSV's own ecosystem strings (PyPI/NuGet/...).
 */
public final class OsvPackageNameNormalizer {

    private OsvPackageNameNormalizer() {
    }

    /**
     * PyPI gets PEP 503 normalization (runs of {@code -}/{@code _}/{@code .} collapse to a single
     * {@code -}, then lowercased) — e.g. {@code "Foo__Bar.Baz"} and {@code "foo-bar-baz"} both
     * normalize to {@code "foo-bar-baz"}. crates.io gets the equivalent {@code -}/{@code _} folding
     * (senior review item 10) — crates.io's own registry treats {@code -} and {@code _} as
     * equivalent when reserving a crate name (you cannot register both {@code serde-json} and {@code
     * serde_json} as distinct crates), so a bare-lowercase-only normalization would miss an advisory
     * filed under the other spelling, a silent false negative. Every other ecosystem (including
     * NuGet/Maven, which the plan calls out explicitly, and npm, plus the remaining registries this
     * app supports) gets a plain case-fold to lowercase — the plan only prescribes PEP 503 and
     * case-folding, and a lowercase fold is a safe, conservative default for the ecosystems it
     * doesn't call out by name individually (go/rubygems/packagist/hex/pub — see {@code
     * docs/spec/known-limitations.md} for why this lowercasing was deliberately widened beyond what
     * the design doc originally prescribed, including a note on Go's case-sensitive module paths).
     */
    public static String normalize(String ecosystem, String rawPackageName) {
        if (rawPackageName == null) {
            return null;
        }
        String trimmed = rawPackageName.trim();
        if ("pypi".equals(ecosystem)) {
            return trimmed.replaceAll("[-_.]+", "-").toLowerCase(Locale.ROOT);
        }
        if ("crates.io".equals(ecosystem)) {
            return trimmed.replaceAll("[-_]+", "-").toLowerCase(Locale.ROOT);
        }
        return trimmed.toLowerCase(Locale.ROOT);
    }
}
