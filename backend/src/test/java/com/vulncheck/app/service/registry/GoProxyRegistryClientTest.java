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
 * tests this file used to have (MockRestServiceServer against the real Go module proxy, including
 * the module-path-escaping test — escaping only ever mattered for the live proxy URL) tested a
 * fallback path that no longer exists — {@link GoProxyRegistryClient#lookup} now always answers
 * from {@link RegistryPackageMirrorRepository}. What remains is that mirror-only contract.
 */
class GoProxyRegistryClientTest {

    private GoProxyRegistryClient client;
    private RegistryPackageMirrorRepository mirrorRepository;

    @BeforeEach
    void setUp() {
        mirrorRepository = Mockito.mock(RegistryPackageMirrorRepository.class);
        client = new GoProxyRegistryClient(mirrorRepository);
    }

    @Test
    void confirmsAnExactVersionFromTheMirror() {
        Mockito.when(mirrorRepository.findVersions("go", "github.com/gin-gonic/gin"))
                .thenReturn(List.of("v1.8.0", "v1.9.1"));

        Optional<RegistryMatch> result = client.lookup("github.com/gin-gonic/gin", "v1.9.1");

        assertThat(result).isPresent();
        // Unlike NuGet, the caller's original-case module path is preserved in the purl (see the
        // class javadoc) — only the mirror's storage key is lowercase-folded.
        assertThat(result.get().purl()).isEqualTo("pkg:golang/github.com/gin-gonic/gin@v1.9.1");
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.95");
    }

    @Test
    void mirrorHasTheModuleButNotTheRequestedVersion() {
        Mockito.when(mirrorRepository.findVersions("go", "github.com/gin-gonic/gin"))
                .thenReturn(List.of("v1.8.0", "v1.9.1"));

        Optional<RegistryMatch> result = client.lookup("github.com/gin-gonic/gin", "v99.0.0");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isFalse();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.5");
    }

    @Test
    void returnsEmptyWhenTheMirrorHasNoEntryForThisModule() {
        Mockito.when(mirrorRepository.findVersions("go", "github.com/nobody/nothing"))
                .thenReturn(List.of());

        Optional<RegistryMatch> result = client.lookup("github.com/nobody/nothing", "v1.0.0");

        assertThat(result).isEmpty();
    }

    @Test
    void returnsEmptyWithoutConsultingTheMirrorWhenProductNameIsNotAModulePath() {
        Optional<RegistryMatch> result = client.lookup("gson", "2.10.1");

        assertThat(result).isEmpty();
        Mockito.verifyNoInteractions(mirrorRepository);
    }
}
