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
 * tests this file used to have (MockRestServiceServer against the real pub.dev API) tested a
 * fallback path that no longer exists — {@link PubRegistryClient#lookup} now always answers from
 * {@link RegistryPackageMirrorRepository}. What remains is that mirror-only contract.
 */
class PubRegistryClientTest {

    private PubRegistryClient client;
    private RegistryPackageMirrorRepository mirrorRepository;

    @BeforeEach
    void setUp() {
        mirrorRepository = Mockito.mock(RegistryPackageMirrorRepository.class);
        client = new PubRegistryClient(mirrorRepository);
    }

    @Test
    void confirmsAnExactVersionFromTheMirror() {
        Mockito.when(mirrorRepository.findVersions("pub", "http"))
                .thenReturn(List.of("1.2.0", "1.1.0"));

        Optional<RegistryMatch> result = client.lookup("http", "1.2.0");

        assertThat(result).isPresent();
        assertThat(result.get().packageName()).isEqualTo("http");
        assertThat(result.get().purl()).isEqualTo("pkg:pub/http@1.2.0");
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.95");
        assertThat(result.get().versions()).containsExactlyInAnyOrder("1.2.0", "1.1.0");
    }

    @Test
    void mirrorHasThePackageButNotTheRequestedVersion() {
        Mockito.when(mirrorRepository.findVersions("pub", "http")).thenReturn(List.of("0.1.0"));

        Optional<RegistryMatch> result = client.lookup("http", "1.2.0");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isFalse();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.5");
    }

    @Test
    void returnsEmptyWhenTheMirrorHasNoEntryForThisPackage() {
        Mockito.when(mirrorRepository.findVersions("pub", "totally-unknown-pub-pkg"))
                .thenReturn(List.of());

        Optional<RegistryMatch> result = client.lookup("totally-unknown-pub-pkg", "1.0.0");

        assertThat(result).isEmpty();
    }
}
