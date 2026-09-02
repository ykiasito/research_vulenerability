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
 * tests this file used to have (MockRestServiceServer against the real crates.io API, plus the
 * mirror-on/mirror-off/never-synced routing tests) tested a fallback path that no longer exists —
 * {@link CratesIoRegistryClient#lookup} now always answers from {@link
 * RegistryPackageMirrorRepository}. What remains is that mirror-only contract.
 */
class CratesIoRegistryClientTest {

    private CratesIoRegistryClient client;
    private RegistryPackageMirrorRepository registryPackageMirrorRepository;

    @BeforeEach
    void setUp() {
        registryPackageMirrorRepository = Mockito.mock(RegistryPackageMirrorRepository.class);
        client = new CratesIoRegistryClient(registryPackageMirrorRepository);
    }

    @Test
    void confirmsAnExactVersionFromTheMirror() {
        Mockito.when(registryPackageMirrorRepository.findVersions("crates.io", "serde"))
                .thenReturn(List.of("1.0.229", "1.0.228"));

        Optional<RegistryMatch> result = client.lookup("serde", "1.0.229");

        assertThat(result).isPresent();
        assertThat(result.get().packageName()).isEqualTo("serde");
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.95");
        assertThat(result.get().versions()).containsExactlyInAnyOrder("1.0.229", "1.0.228");
    }

    @Test
    void mirrorHasThePackageButNotTheRequestedVersion() {
        Mockito.when(registryPackageMirrorRepository.findVersions("crates.io", "serde"))
                .thenReturn(List.of("0.1.0"));

        Optional<RegistryMatch> result = client.lookup("serde", "1.0.229");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isFalse();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.5");
    }

    @Test
    void returnsEmptyWhenTheMirrorHasNoEntryForThisPackage() {
        Mockito.when(registryPackageMirrorRepository.findVersions("crates.io", "totally-unknown-crate"))
                .thenReturn(List.of());

        Optional<RegistryMatch> result = client.lookup("totally-unknown-crate", "1.0.0");

        assertThat(result).isEmpty();
    }

    @Test
    void normalizesTheQueryNameLikeOsvPackageNameNormalizerDoes() {
        // Sync-time storage keys are normalized (see OsvPackageNameNormalizer#normalize's crates.io
        // "-"/"_" folding), so a query for the "_" spelling must still look up the "-" mirror key.
        Mockito.when(registryPackageMirrorRepository.findVersions("crates.io", "serde-json"))
                .thenReturn(List.of("1.0.0"));

        Optional<RegistryMatch> result = client.lookup("serde_json", "1.0.0");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isTrue();
    }
}
