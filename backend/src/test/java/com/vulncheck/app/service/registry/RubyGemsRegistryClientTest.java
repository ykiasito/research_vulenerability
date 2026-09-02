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
 * tests this file used to have (MockRestServiceServer against the real RubyGems API, plus the
 * mirror-on/mirror-off/never-synced routing tests) tested a fallback path that no longer exists —
 * {@link RubyGemsRegistryClient#lookup} now always answers from {@link
 * RegistryPackageMirrorRepository}. What remains is that mirror-only contract.
 */
class RubyGemsRegistryClientTest {

    private RubyGemsRegistryClient client;
    private RegistryPackageMirrorRepository registryPackageMirrorRepository;

    @BeforeEach
    void setUp() {
        registryPackageMirrorRepository = Mockito.mock(RegistryPackageMirrorRepository.class);
        client = new RubyGemsRegistryClient(registryPackageMirrorRepository);
    }

    @Test
    void confirmsAnExactVersionFromTheMirror() {
        Mockito.when(registryPackageMirrorRepository.findVersions("rubygems", "rails"))
                .thenReturn(List.of("7.0.1", "7.0.0"));

        Optional<RegistryMatch> result = client.lookup("rails", "7.0.1");

        assertThat(result).isPresent();
        assertThat(result.get().packageName()).isEqualTo("rails");
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.95");
        assertThat(result.get().versions()).containsExactlyInAnyOrder("7.0.1", "7.0.0");
    }

    @Test
    void mirrorHasThePackageButNotTheRequestedVersion() {
        Mockito.when(registryPackageMirrorRepository.findVersions("rubygems", "rails"))
                .thenReturn(List.of("0.1.0"));

        Optional<RegistryMatch> result = client.lookup("rails", "7.0.1");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isFalse();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.5");
    }

    @Test
    void returnsEmptyWhenTheMirrorHasNoEntryForThisPackage() {
        Mockito.when(registryPackageMirrorRepository.findVersions("rubygems", "totally-unknown-gem"))
                .thenReturn(List.of());

        Optional<RegistryMatch> result = client.lookup("totally-unknown-gem", "1.0.0");

        assertThat(result).isEmpty();
    }

    @Test
    void normalizesTheQueryNameLikeOsvPackageNameNormalizerDoes() {
        // Sync-time storage keys are normalized (see OsvPackageNameNormalizer#normalize's plain
        // lowercase folding for rubygems), so a query for the mixed-case spelling must still look up
        // the lowercased mirror key.
        Mockito.when(registryPackageMirrorRepository.findVersions("rubygems", "rails"))
                .thenReturn(List.of("7.0.1"));

        Optional<RegistryMatch> result = client.lookup("Rails", "7.0.1");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isTrue();
    }
}
