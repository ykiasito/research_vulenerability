package com.vulncheck.app.service.registry;

import java.math.BigDecimal;
import java.util.List;

/**
 * Result of a successful package-registry lookup for Stage1 Tier1 identification.
 *
 * @param exactVersionConfirmed true if the registry confirmed the item's exact version string is
 *                              a real published release (not just that the package/module
 *                              exists); false if the package exists but this exact version could
 *                              not be confirmed there (e.g. a typo, or an unreleased/future
 *                              version) — surfaced to the user as a warning rather than silently
 *                              treating an unconfirmed version identically to a confirmed one.
 * @param versions every published version this lookup's own API call happened to return, when
 *                  the registry's response shape already contains the full list "for free" (most
 *                  {@link PackageRegistryLookup} implementations check {@code exactVersionConfirmed}
 *                  by scanning exactly this list, then previously discarded it). Empty when the
 *                  implementation doesn't have one in hand (e.g. Maven Central's search API only
 *                  returns a version count/matching rows per query, not a full list) — {@link
 *                  RegistryLookupCache} falls back to its pre-existing per-version caching for those
 *                  rather than fetching an extra page just to populate this field.
 */
public record RegistryMatch(String ecosystem, String packageName, String purl, BigDecimal confidence,
        boolean exactVersionConfirmed, List<String> versions) {

    /** Convenience constructor for lookups that don't have a version list in hand (see {@code
     *  versions}'s javadoc) — defaults to empty. */
    public RegistryMatch(String ecosystem, String packageName, String purl, BigDecimal confidence, boolean exactVersionConfirmed) {
        this(ecosystem, packageName, purl, confidence, exactVersionConfirmed, List.of());
    }
}
