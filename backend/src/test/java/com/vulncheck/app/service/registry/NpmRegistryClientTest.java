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
 * tests this file used to have (MockRestServiceServer against the real npm API, plus the
 * mirror-on/mirror-off/never-synced routing tests) tested a fallback path that no longer exists —
 * {@link NpmRegistryClient#lookup} now always answers from {@link RegistryPackageMirrorRepository}.
 * What remains is that mirror-only contract.
 */
class NpmRegistryClientTest {

    private NpmRegistryClient client;
    private RegistryPackageMirrorRepository mirrorRepository;

    @BeforeEach
    void setUp() {
        mirrorRepository = Mockito.mock(RegistryPackageMirrorRepository.class);
        client = new NpmRegistryClient(mirrorRepository);
    }

    @Test
    void confirmsAnExactVersionFromTheMirror() {
        Mockito.when(mirrorRepository.findVersions("npm", "lodash"))
                .thenReturn(List.of("4.17.21", "4.17.20"));

        Optional<RegistryMatch> result = client.lookup("lodash", "4.17.21");

        assertThat(result).isPresent();
        assertThat(result.get().packageName()).isEqualTo("lodash");
        assertThat(result.get().purl()).isEqualTo("pkg:npm/lodash@4.17.21");
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.95");
        // Captured for RegistryLookupCache to re-derive a different version's answer without a
        // second lookup — see RegistryMatch#versions().
        assertThat(result.get().versions()).containsExactlyInAnyOrder("4.17.21", "4.17.20");
    }

    @Test
    void mirrorHasThePackageButNotTheRequestedVersion() {
        // Same shape as the real "gson"/"junit"/"cobra" collisions found live: an unrelated
        // package happens to share the literal name, so it exists but never at this version.
        Mockito.when(mirrorRepository.findVersions("npm", "gson")).thenReturn(List.of("0.1.5"));

        Optional<RegistryMatch> result = client.lookup("gson", "2.10.1");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isFalse();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.5");
    }

    @Test
    void returnsEmptyWhenTheMirrorHasNoEntryForThisPackage() {
        Mockito.when(mirrorRepository.findVersions("npm", "totally-unknown-package"))
                .thenReturn(List.of());

        Optional<RegistryMatch> result = client.lookup("totally-unknown-package", "1.0.0");

        assertThat(result).isEmpty();
    }
}
