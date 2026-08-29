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
    void aWhitespaceContainingNameIsRoutedToChocolateyOnlyNotEveryRegistry() {
        // Regression guard for the exact bug this class's whitespace rule used to have: once
        // ChocolateyRegistryClient was added, "no registry allows whitespace" stopped being true,
        // but the fix must still not fall back to asking every HTTP registry — only Chocolatey can
        // actually hold a multi-word desktop product name like this.
        PackageRegistryLookup npm = lookupFor("npm");
        PackageRegistryLookup maven = lookupFor("maven");
        PackageRegistryLookup chocolatey = lookupFor("chocolatey");
        List<PackageRegistryLookup> all = List.of(npm, maven, chocolatey);

        List<PackageRegistryLookup> routed = policy.route("OBS Studio", all);

        assertThat(routed).containsExactly(chocolatey);
    }

    @Test
    void aWhitespaceContainingNameRoutesToNothingWhenChocolateyItselfIsNotWired() {
        // Deliberately does NOT fall back to "ask everyone" the way only() does for its other
        // targeted ecosystems — the other nine registries provably can't hold a whitespace name,
        // so silently re-opening the request to all of them would reintroduce the original bug.
        List<PackageRegistryLookup> all = List.of(lookupFor("npm"), lookupFor("maven"));

        List<PackageRegistryLookup> routed = policy.route("Adobe Acrobat Reader", all);

        assertThat(routed).isEmpty();
    }

    @Test
    void theOtherNineRegistriesAreStillNotIndividuallyTargetableForAWhitespaceName() {
        PackageRegistryLookup npm = lookupFor("npm");
        PackageRegistryLookup chocolatey = lookupFor("chocolatey");

        List<PackageRegistryLookup> routed = policy.route("Advanced IP Scanner", List.of(npm, chocolatey));

        assertThat(routed).doesNotContain(npm);
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
    void mavenCoordinateWithSurroundingWhitespaceIsStillRoutedToMavenOnlyNotChocolatey() {
        // Regression guard (job 167 chocolatey-routing fix): a colon still identifies an
        // unambiguous Maven coordinate even when the name also contains whitespace (e.g. spaces
        // typed around the colon) — this must not fall into the whitespace/chocolatey rule, since
        // chocolatey's own id grammar can never admit a colon anyway.
        PackageRegistryLookup maven = lookupFor("maven");
        PackageRegistryLookup chocolatey = lookupFor("chocolatey");

        List<PackageRegistryLookup> routed =
                policy.route("com.google.guava : guava", List.of(maven, chocolatey));

        assertThat(routed).containsExactly(maven);
    }

    @Test
    void goModulePathWithSpaceInFinalSegmentIsStillRoutedToGoOnlyNotChocolatey() {
        PackageRegistryLookup go = lookupFor("go");
        PackageRegistryLookup chocolatey = lookupFor("chocolatey");

        List<PackageRegistryLookup> routed =
                policy.route("github.com/gin-gonic/gin extra", List.of(go, chocolatey));

        assertThat(routed).containsExactly(go);
    }

    @Test
    void npmScopedPackageWithSpaceInsideIsStillRoutedToNpmOnlyNotChocolatey() {
        PackageRegistryLookup npm = lookupFor("npm");
        PackageRegistryLookup chocolatey = lookupFor("chocolatey");

        List<PackageRegistryLookup> routed = policy.route("@my org/my package", List.of(npm, chocolatey));

        assertThat(routed).containsExactly(npm);
    }

    @Test
    void slashPackageWithEmptyVendorRoutesToNothing() {
        // Not a legal Composer identifier (vendor required), not a Go module path (no host.tld/
        // prefix), and not chocolatey either (its id grammar forbids '/') — no registry's own
        // grammar admits this shape.
        List<PackageRegistryLookup> all = List.of(lookupFor("packagist"), lookupFor("chocolatey"), lookupFor("npm"));

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
