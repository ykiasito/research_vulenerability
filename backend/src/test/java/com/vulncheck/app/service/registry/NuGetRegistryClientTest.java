package com.vulncheck.app.service.registry;

import static org.assertj.core.api.Assertions.assertThat;

import com.vulncheck.app.repository.RegistryPackageMirrorRepository;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

/**
 * Closed-mode B3 (backlog item 193, {@code docs/spec/closed-mode-plan.md} §3-2): the live-HTTP
 * tests this file used to have (MockRestServiceServer against the real NuGet flat-container API)
 * tested a fallback path that no longer exists — {@link NuGetRegistryClient#lookup} now always
 * answers from {@link RegistryPackageMirrorRepository}. What remains is that mirror-only contract.
 */
class NuGetRegistryClientTest {

    private NuGetRegistryClient client;
    private RegistryPackageMirrorRepository mirrorRepository;

    @BeforeEach
    void setUp() {
        mirrorRepository = Mockito.mock(RegistryPackageMirrorRepository.class);
        client = new NuGetRegistryClient(mirrorRepository);
    }

    @Test
    void confirmsAnExactVersionFromTheMirror() {
        Mockito.when(mirrorRepository.findVersions("nuget", "newtonsoft.json"))
                .thenReturn(List.of("13.0.2", "13.0.3"));

        Optional<RegistryMatch> result = client.lookup("Newtonsoft.Json", "13.0.3");

        assertThat(result).isPresent();
        // Keeps the caller's original casing for packageName — OSV.dev and GitHub Advisories are
        // both case-sensitive on the NuGet package name (confirmed live: querying
        // "newtonsoft.json" finds nothing, "Newtonsoft.Json" does). The mirror has no canonically-
        // cased id to recover either, so purl is built off the lowercase-folded storage key.
        assertThat(result.get().packageName()).isEqualTo("Newtonsoft.Json");
        assertThat(result.get().purl()).isEqualTo("pkg:nuget/newtonsoft.json@13.0.3");
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.95");
        assertThat(result.get().versions()).containsExactlyInAnyOrder("13.0.2", "13.0.3");
    }

    @Test
    void mirrorHasThePackageButNotTheRequestedVersion() {
        // Same shape as the real "cURL"/"OpenSSL"/"7-Zip" collisions found live: a NuGet package
        // exists under the literal name but isn't the real desktop tool the CSV row meant.
        Mockito.when(mirrorRepository.findVersions("nuget", "curl")).thenReturn(List.of("1.0.0"));

        Optional<RegistryMatch> result = client.lookup("curl", "8.4.0");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isFalse();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.5");
    }

    @Test
    void versionMatchIsCaseInsensitive() {
        Mockito.when(mirrorRepository.findVersions("nuget", "somepackage"))
                .thenReturn(List.of("1.0.0-Beta1"));

        Optional<RegistryMatch> result = client.lookup("SomePackage", "1.0.0-beta1");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isTrue();
    }

    @Test
    void returnsEmptyWhenTheMirrorHasNoEntryForThisPackage() {
        Mockito.when(mirrorRepository.findVersions("nuget", "totally-unknown-package"))
                .thenReturn(List.of());

        Optional<RegistryMatch> result = client.lookup("totally-unknown-package", "1.0.0");

        assertThat(result).isEmpty();
    }
}
