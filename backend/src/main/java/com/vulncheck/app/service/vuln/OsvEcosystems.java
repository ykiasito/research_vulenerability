package com.vulncheck.app.service.vuln;

import java.util.Map;
import java.util.Set;

/**
 * Single source of truth for the mapping between this app's own internal ecosystem keys
 * (npm/pypi/maven/go/nuget/rubygems/crates.io/packagist/hex/pub) and OSV's own native ecosystem
 * strings (as they appear in {@code affected[].package.ecosystem}/OSV.dev's {@code
 * package.ecosystem} query field) — previously duplicated independently across {@link
 * OsvVulnerabilitySource}, {@code GhsaDocumentUpsertService}, and {@link GhsaVulnerabilitySource}.
 * An ecosystem not present here has no internal key/candidate-query path in this app and is
 * skipped by every caller.
 */
public final class OsvEcosystems {

    /** OSV-native ecosystem string (e.g. {@code "PyPI"}) → this app's internal ecosystem key
     *  (e.g. {@code "pypi"}). */
    public static final Map<String, String> OSV_TO_INTERNAL = Map.ofEntries(
            Map.entry("npm", "npm"),
            Map.entry("PyPI", "pypi"),
            Map.entry("Maven", "maven"),
            Map.entry("Go", "go"),
            Map.entry("NuGet", "nuget"),
            Map.entry("RubyGems", "rubygems"),
            Map.entry("crates.io", "crates.io"),
            Map.entry("Packagist", "packagist"),
            Map.entry("Hex", "hex"),
            Map.entry("Pub", "pub"));

    /** This app's internal ecosystem key → OSV-native ecosystem string. The exact inverse of
     *  {@link #OSV_TO_INTERNAL}. */
    public static final Map<String, String> INTERNAL_TO_OSV = Map.ofEntries(
            Map.entry("npm", "npm"),
            Map.entry("pypi", "PyPI"),
            Map.entry("maven", "Maven"),
            Map.entry("go", "Go"),
            Map.entry("nuget", "NuGet"),
            Map.entry("rubygems", "RubyGems"),
            Map.entry("crates.io", "crates.io"),
            Map.entry("packagist", "Packagist"),
            Map.entry("hex", "Hex"),
            Map.entry("pub", "Pub"));

    /** This app's internal ecosystem keys that are supported by the OSV-schema ecosystem
     *  mapping above — the same as {@link #INTERNAL_TO_OSV}'s (and {@link #OSV_TO_INTERNAL}'s)
     *  key/value sets. */
    public static final Set<String> SUPPORTED_INTERNAL_KEYS = INTERNAL_TO_OSV.keySet();

    private OsvEcosystems() {
    }
}
