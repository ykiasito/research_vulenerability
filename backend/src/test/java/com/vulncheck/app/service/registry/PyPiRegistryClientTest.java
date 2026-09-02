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
 * tests this file used to have (MockRestServiceServer against the real PyPI API) tested a fallback
 * path that no longer exists — {@link PyPiRegistryClient#lookup} now always answers from {@link
 * RegistryPackageMirrorRepository}. What remains is that mirror-only contract.
 */
class PyPiRegistryClientTest {

    private PyPiRegistryClient client;
    private RegistryPackageMirrorRepository mirrorRepository;

    @BeforeEach
    void setUp() {
        mirrorRepository = Mockito.mock(RegistryPackageMirrorRepository.class);
        client = new PyPiRegistryClient(mirrorRepository);
    }

    @Test
    void confirmsAnExactVersionFromTheMirror() {
        Mockito.when(mirrorRepository.findVersions("pypi", "requests"))
                .thenReturn(List.of("2.31.0", "2.30.0"));

        Optional<RegistryMatch> result = client.lookup("requests", "2.31.0");

        assertThat(result).isPresent();
        assertThat(result.get().packageName()).isEqualTo("requests");
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.95");
        assertThat(result.get().versions()).containsExactlyInAnyOrder("2.31.0", "2.30.0");
    }

    @Test
    void mirrorHasThePackageButNotTheRequestedVersion() {
        // Same shape as the real "PuTTY" collision found live: PyPI has an unrelated package
        // literally named "Putty" that is not the real Windows terminal client.
        Mockito.when(mirrorRepository.findVersions("pypi", "putty")).thenReturn(List.of("0.1.0"));

        Optional<RegistryMatch> result = client.lookup("PuTTY", "0.79");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isFalse();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.5");
    }

    @Test
    void returnsEmptyWhenTheMirrorHasNoEntryForThisPackage() {
        Mockito.when(mirrorRepository.findVersions("pypi", "totally-unknown-package"))
                .thenReturn(List.of());

        Optional<RegistryMatch> result = client.lookup("totally-unknown-package", "1.0.0");

        assertThat(result).isEmpty();
    }
}
