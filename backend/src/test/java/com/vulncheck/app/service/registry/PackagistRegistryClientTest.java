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
 * tests this file used to have (MockRestServiceServer against the real Packagist API) tested a
 * fallback path that no longer exists — {@link PackagistRegistryClient#lookup} now always answers
 * from {@link RegistryPackageMirrorRepository}. What remains is that mirror-only contract.
 */
class PackagistRegistryClientTest {

    private PackagistRegistryClient client;
    private RegistryPackageMirrorRepository registryPackageMirrorRepository;

    @BeforeEach
    void setUp() {
        registryPackageMirrorRepository = Mockito.mock(RegistryPackageMirrorRepository.class);
        client = new PackagistRegistryClient(registryPackageMirrorRepository);
    }

    @Test
    void confirmsAnExactVersionFromTheMirror() {
        Mockito.when(registryPackageMirrorRepository.findVersions("packagist", "monolog/monolog"))
                .thenReturn(List.of("3.5.0", "3.4.0"));

        Optional<RegistryMatch> result = client.lookup("monolog/monolog", "3.5.0");

        assertThat(result).isPresent();
        assertThat(result.get().packageName()).isEqualTo("monolog/monolog");
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.95");
        assertThat(result.get().versions()).containsExactlyInAnyOrder("3.5.0", "3.4.0");
    }

    @Test
    void mirrorHasThePackageButNotTheRequestedVersion() {
        Mockito.when(registryPackageMirrorRepository.findVersions("packagist", "monolog/monolog"))
                .thenReturn(List.of("0.1.0"));

        Optional<RegistryMatch> result = client.lookup("monolog/monolog", "3.5.0");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isFalse();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.5");
    }

    @Test
    void returnsEmptyWhenTheMirrorHasNoEntryForThisPackage() {
        Mockito.when(registryPackageMirrorRepository.findVersions("packagist", "totally/unknown-package"))
                .thenReturn(List.of());

        Optional<RegistryMatch> result = client.lookup("totally/unknown-package", "1.0.0");

        assertThat(result).isEmpty();
    }

    @Test
    void returnsEmptyWithoutConsultingTheMirrorWhenProductNameHasNoVendorSlash() {
        // Packagist has no lookup-by-bare-name endpoint — "monolog" alone (not "monolog/monolog")
        // has nothing to query. A real, structural limitation of this ecosystem, not a bug.
        Optional<RegistryMatch> result = client.lookup("monolog", "3.5.0");

        assertThat(result).isEmpty();
        Mockito.verifyNoInteractions(registryPackageMirrorRepository);
    }
}
