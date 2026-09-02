package com.vulncheck.app.service.registry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.vulncheck.app.repository.RegistryPackageMirrorRepository;
import com.vulncheck.app.service.ratelimit.ExternalRegistryRateLimiter;
import com.vulncheck.app.service.registry.GoMirrorSyncService.SyncOutcome;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

class GoMirrorSyncServiceTest {

    private MockRestServiceServer server;
    private GoMirrorSyncService service;
    private RegistryPackageMirrorRepository registryPackageMirrorRepository;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        registryPackageMirrorRepository = Mockito.mock(RegistryPackageMirrorRepository.class);
        service = new GoMirrorSyncService(builder.build(), ExternalRegistryRateLimiter.disabledForTesting(),
                registryPackageMirrorRepository);
    }

    @Test
    void syncsAModuleAndUpsertsItsFullVersionList() {
        // RestClient's single {module} URI template variable percent-encodes "/" (same trap the
        // npm rollout hit with scoped package names -- see NpmMirrorSyncServiceTest) -- confirmed
        // live 2026-09-02 that proxy.golang.org accepts this fully-percent-encoded form and returns
        // the same content as the literal, unencoded path.
        server.expect(requestTo("https://proxy.golang.org/github.com%2Fgin-gonic%2Fgin/@v/list"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("v1.8.0\nv1.9.1\n", MediaType.TEXT_PLAIN));

        SyncOutcome outcome = service.syncModules(List.of("github.com/gin-gonic/gin"));

        assertThat(outcome.synced()).isEqualTo(1);
        assertThat(outcome.unresolved()).isEqualTo(0);
        server.verify();

        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("go"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).containsOnlyKeys("github.com/gin-gonic/gin");
        assertThat(batchCaptor.getValue().get("github.com/gin-gonic/gin"))
                .containsExactlyInAnyOrder("v1.8.0", "v1.9.1");
    }

    @Test
    void escapesUppercaseSegmentsOfTheModulePathInTheRequestUrl() {
        // Go's own worked example (https://go.dev/ref/mod#goproxy-protocol): "BurntSushi" escapes
        // to "!burnt!sushi" in the proxy URL, while the mirror's stored key still lowercase-folds
        // (same as GoProxyRegistryClient -- see its class javadoc for the accepted tradeoff).
        server.expect(requestTo("https://proxy.golang.org/github.com%2F%21burnt%21sushi%2Ftoml/@v/list"))
                .andRespond(withSuccess("v1.3.0\n", MediaType.TEXT_PLAIN));

        service.syncModules(List.of("github.com/BurntSushi/toml"));

        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("go"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).containsOnlyKeys("github.com/burntsushi/toml");
    }

    @Test
    void countsA404AsUnresolvedAndDoesNotWriteThatModuleIntoTheBatch() {
        server.expect(requestTo("https://proxy.golang.org/github.com%2Fnobody%2Fnothing/@v/list"))
                .andRespond(withStatus(HttpStatus.NOT_FOUND));

        SyncOutcome outcome = service.syncModules(List.of("github.com/nobody/nothing"));

        assertThat(outcome.synced()).isEqualTo(0);
        assertThat(outcome.unresolved()).isEqualTo(1);
        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("go"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).isEmpty();
    }

    @Test
    void treatsAnEmptyBodyAsUnresolved() {
        server.expect(requestTo("https://proxy.golang.org/github.com%2Fnobody%2Fempty/@v/list"))
                .andRespond(withSuccess("", MediaType.TEXT_PLAIN));

        SyncOutcome outcome = service.syncModules(List.of("github.com/nobody/empty"));

        assertThat(outcome.synced()).isEqualTo(0);
        assertThat(outcome.unresolved()).isEqualTo(1);
    }

    @Test
    void skipsBlankModulePathsWithoutMakingARequest() {
        SyncOutcome outcome = service.syncModules(List.of("  ", ""));

        assertThat(outcome.synced()).isEqualTo(0);
        assertThat(outcome.unresolved()).isEqualTo(0);
        server.verify();
    }
}
