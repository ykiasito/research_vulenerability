package com.vulncheck.app.service.registry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.vulncheck.app.repository.RegistryPackageMirrorRepository;
import com.vulncheck.app.service.ratelimit.ExternalRegistryRateLimiter;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

class GoProxyRegistryClientTest {

    private MockRestServiceServer server;
    private GoProxyRegistryClient client;
    private RegistryPackageMirrorRepository mirrorRepository;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        // mirrorEnabled defaults to false (this @Value field is never injected outside a Spring
        // context), so every test below (unless it explicitly flips the field, see the mirror-path
        // tests) exercises the pre-existing live path -- no need to stub the mock's
        // hasAnyEntries/findVersions.
        mirrorRepository = Mockito.mock(RegistryPackageMirrorRepository.class);
        client = new GoProxyRegistryClient(builder.build(), ExternalRegistryRateLimiter.disabledForTesting(), mirrorRepository);
    }

    @Test
    void confirmsWhenTheExactVersionIsInTheModulesVersionList() {
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess("v1.8.0\nv1.9.1\nv1.9.0\n", MediaType.TEXT_PLAIN));

        Optional<RegistryMatch> result = client.lookup("github.com/gin-gonic/gin", "v1.9.1");

        assertThat(result).isPresent();
        assertThat(result.get().purl()).isEqualTo("pkg:golang/github.com/gin-gonic/gin@v1.9.1");
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.95");
        assertThat(result.get().versions()).containsExactlyInAnyOrder("v1.8.0", "v1.9.1", "v1.9.0");
        server.verify();
    }

    @Test
    void moduleExistsButRequestedVersionIsNotInTheVersionList() {
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess("v1.8.0\nv1.9.1\n", MediaType.TEXT_PLAIN));

        Optional<RegistryMatch> result = client.lookup("github.com/gin-gonic/gin", "v99.0.0");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isFalse();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.5");
        server.verify();
    }

    @Test
    void returnsEmptyWhenTheModuleDoesNotExistAtAll() {
        server.expect(method(HttpMethod.GET)).andRespond(withStatus(HttpStatus.NOT_FOUND));

        Optional<RegistryMatch> result = client.lookup("github.com/nobody/nothing", "v1.0.0");

        assertThat(result).isEmpty();
        server.verify();
    }

    @Test
    void returnsEmptyWithoutAnyHttpCallWhenProductNameIsNotAModulePath() {
        Optional<RegistryMatch> result = client.lookup("gson", "2.10.1");

        assertThat(result).isEmpty();
        server.verify();
    }

    @Test
    void escapesUppercaseSegmentsOfTheModulePathRatherThanLowercasingThem() {
        // Go's own worked example (https://go.dev/ref/mod#goproxy-protocol): "BurntSushi" escapes
        // to "!burnt!sushi", it does not just get lowercased to "burntsushi" -- lowercasing first
        // (the previous implementation's bug) would silently send the wrong path whenever escaping
        // is actually load-bearing for a module whose real path has uppercase segments.
        // RestClient's single {module} URI template variable percent-encodes "/" and "!" (same
        // trap the npm rollout hit with scoped package names -- see NpmMirrorSyncServiceTest) --
        // confirmed live 2026-09-02 that proxy.golang.org accepts this fully-percent-encoded form
        // and returns the same content as the literal, unencoded path.
        server.expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://proxy.golang.org/github.com%2F%21burnt%21sushi%2Ftoml/@v/list"))
                .andRespond(withSuccess("v1.3.0\n", MediaType.TEXT_PLAIN));

        Optional<RegistryMatch> result = client.lookup("github.com/BurntSushi/toml", "v1.3.0");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        server.verify();
    }

    @Test
    void mirrorEnabledButNotYetSyncedFallsBackToLiveLookup() {
        ReflectionTestUtils.setField(client, "mirrorEnabled", true);
        Mockito.when(mirrorRepository.hasAnyEntries("go")).thenReturn(false);
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess("v1.9.1\n", MediaType.TEXT_PLAIN));

        Optional<RegistryMatch> result = client.lookup("github.com/gin-gonic/gin", "v1.9.1");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        server.verify();
    }

    @Test
    void mirrorEnabledAndSyncedAnswersFromTheMirrorWithoutAnyHttpCall() {
        ReflectionTestUtils.setField(client, "mirrorEnabled", true);
        Mockito.when(mirrorRepository.hasAnyEntries("go")).thenReturn(true);
        Mockito.when(mirrorRepository.findVersions("go", "github.com/gin-gonic/gin"))
                .thenReturn(List.of("v1.8.0", "v1.9.1"));

        Optional<RegistryMatch> result = client.lookup("github.com/gin-gonic/gin", "v1.9.1");

        assertThat(result).isPresent();
        // Unlike NuGet, the caller's original-case module path is preserved in the purl in both
        // paths (see the class javadoc) -- only the mirror's storage key is lowercase-folded.
        assertThat(result.get().purl()).isEqualTo("pkg:golang/github.com/gin-gonic/gin@v1.9.1");
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.95");
        server.verify();
    }

    @Test
    void mirrorEnabledAndSyncedButModuleNotInMirrorReturnsEmptyWithoutAnyHttpCall() {
        ReflectionTestUtils.setField(client, "mirrorEnabled", true);
        Mockito.when(mirrorRepository.hasAnyEntries("go")).thenReturn(true);
        Mockito.when(mirrorRepository.findVersions("go", "github.com/nobody/nothing"))
                .thenReturn(List.of());

        Optional<RegistryMatch> result = client.lookup("github.com/nobody/nothing", "v1.0.0");

        assertThat(result).isEmpty();
        server.verify();
    }
}
