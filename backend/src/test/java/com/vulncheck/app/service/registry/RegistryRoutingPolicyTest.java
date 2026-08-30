package com.vulncheck.app.service.registry;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class RegistryRoutingPolicyTest {

    private final RegistryRoutingPolicy policy = new RegistryRoutingPolicy();

    private PackageRegistryLookup lookupFor(String ecosystem) {
        return new PackageRegistryLookup() {
            @Override
            public Optional<RegistryMatch> lookup(String productName, String version) {
                return Optional.empty();
            }

            @Override
            public String ecosystem() {
                return ecosystem;
            }
        };
    }

    @Test
    void aWhitespaceContainingNameRoutesToNothing() {
        // No registry here permits a whitespace-containing package name — a provable "ask no
        // registry at all" (a CPE-only case), not a fall-through to "ask everyone".
        List<PackageRegistryLookup> all = List.of(lookupFor("npm"), lookupFor("maven"));

        List<PackageRegistryLookup> routed = policy.route("OBS Studio", all);

        assertThat(routed).isEmpty();
    }

    @Test
    void npmScopedPackageNameIsRoutedToNpmOnly() {
        PackageRegistryLookup npm = lookupFor("npm");
        PackageRegistryLookup maven = lookupFor("maven");

        List<PackageRegistryLookup> routed = policy.route("@babel/core", List.of(npm, maven));

        assertThat(routed).containsExactly(npm);
    }

    @Test
    void goModulePathIsRoutedToGoOnly() {
        PackageRegistryLookup go = lookupFor("go");
        PackageRegistryLookup npm = lookupFor("npm");

        List<PackageRegistryLookup> routed = policy.route("github.com/gin-gonic/gin", List.of(go, npm));

        assertThat(routed).containsExactly(go);
    }

    @Test
    void vendorSlashPackageIsRoutedToPackagistOnly() {
        PackageRegistryLookup packagist = lookupFor("packagist");
        PackageRegistryLookup npm = lookupFor("npm");

        List<PackageRegistryLookup> routed = policy.route("monolog/monolog", List.of(packagist, npm));

        assertThat(routed).containsExactly(packagist);
    }

    @Test
    void mavenCoordinateIsRoutedToMavenOnly() {
        PackageRegistryLookup maven = lookupFor("maven");
        PackageRegistryLookup npm = lookupFor("npm");

        List<PackageRegistryLookup> routed = policy.route("com.google.guava:guava", List.of(maven, npm));

        assertThat(routed).containsExactly(maven);
    }

    @Test
    void aBareAmbiguousNameIsRoutedToEveryRegistry() {
        PackageRegistryLookup npm = lookupFor("npm");
        PackageRegistryLookup pypi = lookupFor("pypi");
        List<PackageRegistryLookup> all = List.of(npm, pypi);

        List<PackageRegistryLookup> routed = policy.route("lodash", all);

        assertThat(routed).containsExactlyElementsOf(all);
    }

    @Test
    void mavenCoordinateWithSurroundingWhitespaceIsStillRoutedToMavenOnly() {
        // A colon still identifies an unambiguous Maven coordinate even when the name also
        // contains whitespace (e.g. spaces typed around the colon) — this must not fall into the
        // whitespace "ask nothing" rule.
        PackageRegistryLookup maven = lookupFor("maven");
        PackageRegistryLookup npm = lookupFor("npm");

        List<PackageRegistryLookup> routed =
                policy.route("com.google.guava : guava", List.of(maven, npm));

        assertThat(routed).containsExactly(maven);
    }

    @Test
    void goModulePathWithSpaceInFinalSegmentIsStillRoutedToGoOnly() {
        PackageRegistryLookup go = lookupFor("go");
        PackageRegistryLookup npm = lookupFor("npm");

        List<PackageRegistryLookup> routed =
                policy.route("github.com/gin-gonic/gin extra", List.of(go, npm));

        assertThat(routed).containsExactly(go);
    }

    @Test
    void npmScopedPackageWithSpaceInsideIsStillRoutedToNpmOnly() {
        PackageRegistryLookup npm = lookupFor("npm");
        PackageRegistryLookup maven = lookupFor("maven");

        List<PackageRegistryLookup> routed = policy.route("@my org/my package", List.of(npm, maven));

        assertThat(routed).containsExactly(npm);
    }

    @Test
    void slashPackageWithEmptyVendorRoutesToNothing() {
        // Not a legal Composer identifier (vendor required) and not a Go module path (no
        // host.tld/ prefix) either — no registry's own grammar admits this shape.
        List<PackageRegistryLookup> all = List.of(lookupFor("packagist"), lookupFor("npm"));

        List<PackageRegistryLookup> routed = policy.route("/monolog", all);

        assertThat(routed).isEmpty();
    }

    @Test
    void blankOrNullNameRoutesToNothing() {
        List<PackageRegistryLookup> all = List.of(lookupFor("npm"));

        assertThat(policy.route("", all)).isEmpty();
        assertThat(policy.route(null, all)).isEmpty();
        assertThat(policy.route("   ", all)).isEmpty();
    }
}
