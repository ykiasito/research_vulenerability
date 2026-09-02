package com.vulncheck.app.service.registry;

import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Closed-mode backlog item 193 (B3, {@code docs/spec/closed-mode-plan.md} §3-2/§5-4): Maven
 * Central is the one registry of the original 10 that never got a closed-mode mirror (§5-4 —
 * unlike crates.io/RubyGems/Packagist/Hex/npm/PyPI/NuGet/pub.dev/Go, there is no {@code
 * MavenCentralMirrorSyncService} and no {@code registry_package_mirror} rows for {@code
 * ecosystem = 'maven'}). This class used to be a live Solr-search + maven-metadata.xml lookup
 * against search.maven.org/repo1.maven.org (see {@code MavenCentralRegistryClientTest}'s git
 * history for the removed implementation) — closed mode has no network to make either call over,
 * and with no mirror to answer from instead, {@link #lookup} is gutted to the same fixed
 * "unavailable" no-op shape closed-mode B2 already used for every AI-dependent collaborator (see
 * e.g. {@link com.vulncheck.app.service.Stage4WebSearchResearchService}'s own javadoc): it always
 * returns empty, same as the pre-existing "registry has nothing for this product" outcome every
 * caller already handles. Left wired in as a {@code @Component} (not deleted outright) so {@link
 * Stage1RegistryIdentification}'s {@code List<PackageRegistryLookup>} injection point and {@link
 * RegistryRoutingPolicy}'s Maven-coordinate routing rule need no changes.
 */
@Component
@Slf4j
public class MavenCentralRegistryClient implements PackageRegistryLookup {

    private static final String ECOSYSTEM = "maven";

    @Override
    public Optional<RegistryMatch> lookup(String productName, String version) {
        log.debug("Maven Central lookup skipped for productName={}: no closed-mode mirror exists for "
                + "this registry (docs/spec/closed-mode-plan.md §5-4)", productName);
        return Optional.empty();
    }

    @Override
    public String ecosystem() {
        return ECOSYSTEM;
    }
}
