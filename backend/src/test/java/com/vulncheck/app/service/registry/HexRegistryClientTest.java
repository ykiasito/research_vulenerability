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
 * tests this file used to have (MockRestServiceServer against the real Hex API) tested a fallback
 * path that no longer exists — {@link HexRegistryClient#lookup} now always answers from {@link
 * RegistryPackageMirrorRepository}. What remains is that mirror-only contract.
 */
class HexRegistryClientTest {

    private HexRegistryClient client;
    private RegistryPackageMirrorRepository registryPackageMirrorRepository;

    @BeforeEach
    void setUp() {
        registryPackageMirrorRepository = Mockito.mock(RegistryPackageMirrorRepository.class);
        client = new HexRegistryClient(registryPackageMirrorRepository);
    }

    @Test
    void confirmsAnExactVersionFromTheMirror() {
        Mockito.when(registryPackageMirrorRepository.findVersions("hex", "phoenix"))
                .thenReturn(List.of("1.8.12", "1.8.11"));

        Optional<RegistryMatch> result = client.lookup("phoenix", "1.8.12");

        assertThat(result).isPresent();
        assertThat(result.get().packageName()).isEqualTo("phoenix");
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.95");
        assertThat(result.get().versions()).containsExactlyInAnyOrder("1.8.12", "1.8.11");
    }

    @Test
    void mirrorHasThePackageButNotTheRequestedVersion() {
        Mockito.when(registryPackageMirrorRepository.findVersions("hex", "phoenix"))
                .thenReturn(List.of("0.1.0"));

        Optional<RegistryMatch> result = client.lookup("phoenix", "1.8.12");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isFalse();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.5");
    }

    @Test
    void returnsEmptyWhenTheMirrorHasNoEntryForThisPackage() {
        Mockito.when(registryPackageMirrorRepository.findVersions("hex", "totally-unknown-hex-pkg"))
                .thenReturn(List.of());

        Optional<RegistryMatch> result = client.lookup("totally-unknown-hex-pkg", "1.0.0");

        assertThat(result).isEmpty();
    }
}
