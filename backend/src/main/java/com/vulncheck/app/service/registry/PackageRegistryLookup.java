package com.vulncheck.app.service.registry;

import java.util.Optional;

/**
 * A Stage1 Tier1 static lookup against one package registry (npm, PyPI, Maven Central, ...).
 * Implementations must be best-effort: any network/parse failure should be swallowed and
 * reported as an empty result rather than propagated, since Tier1 tries every registry and a
 * single registry being down must not abort identification.
 */
public interface PackageRegistryLookup {

    Optional<RegistryMatch> lookup(String productName, String version);

    /** The ecosystem string this lookup serves (matches {@link RegistryMatch#ecosystem()} and the
     *  {@code ecosystem_registries} table), so callers can target one specific registry directly
     *  instead of the "try every registry with this literal name" scan {@code bestRegistryMatch}
     *  does — used by Stage1 Tier3 to act on an AI-guessed ecosystem+package name pair. */
    String ecosystem();
}
