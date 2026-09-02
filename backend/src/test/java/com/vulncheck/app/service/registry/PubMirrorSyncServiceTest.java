package com.vulncheck.app.service.registry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.vulncheck.app.repository.RegistryPackageMirrorRepository;
import com.vulncheck.app.service.ratelimit.ExternalRegistryRateLimiter;
import com.vulncheck.app.service.registry.PubMirrorSyncService.SyncOutcome;
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

class PubMirrorSyncServiceTest {

    private MockRestServiceServer server;
    private PubMirrorSyncService service;
    private RegistryPackageMirrorRepository registryPackageMirrorRepository;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        registryPackageMirrorRepository = Mockito.mock(RegistryPackageMirrorRepository.class);
        service = new PubMirrorSyncService(builder.build(), ExternalRegistryRateLimiter.disabledForTesting(),
                registryPackageMirrorRepository);
    }

    @Test
    void syncsAPackageAndUpsertsItsFullVersionList() {
        server.expect(requestTo("https://pub.dev/api/packages/http"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(
                        "{\"versions\":[{\"version\":\"1.2.0\"},{\"version\":\"1.1.0\"}]}",
                        MediaType.APPLICATION_JSON));

        SyncOutcome outcome = service.syncPackages(List.of("http"));

        assertThat(outcome.synced()).isEqualTo(1);
        assertThat(outcome.unresolved()).isEqualTo(0);
        server.verify();

        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("pub"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).containsOnlyKeys("http");
        assertThat(batchCaptor.getValue().get("http")).containsExactlyInAnyOrder("1.2.0", "1.1.0");
    }

    @Test
    void normalizesTheStorageKeyToLowercase() {
        server.expect(requestTo("https://pub.dev/api/packages/HttpPackage"))
                .andRespond(withSuccess("{\"versions\":[{\"version\":\"1.0.0\"}]}", MediaType.APPLICATION_JSON));

        service.syncPackages(List.of("HttpPackage"));

        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("pub"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).containsOnlyKeys("httppackage");
    }

    @Test
    void countsA404AsUnresolvedAndDoesNotWriteThatPackageIntoTheBatch() {
        server.expect(requestTo("https://pub.dev/api/packages/totally-unknown-pub-pkg"))
                .andRespond(withStatus(HttpStatus.NOT_FOUND));

        SyncOutcome outcome = service.syncPackages(List.of("totally-unknown-pub-pkg"));

        assertThat(outcome.synced()).isEqualTo(0);
        assertThat(outcome.unresolved()).isEqualTo(1);
        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("pub"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).isEmpty();
    }

    @Test
    void treatsAMissingVersionsArrayAsUnresolved() {
        server.expect(requestTo("https://pub.dev/api/packages/empty-pkg"))
                .andRespond(withSuccess("{\"name\":\"empty-pkg\"}", MediaType.APPLICATION_JSON));

        SyncOutcome outcome = service.syncPackages(List.of("empty-pkg"));

        assertThat(outcome.synced()).isEqualTo(0);
        assertThat(outcome.unresolved()).isEqualTo(1);
    }

    @Test
    void skipsBlankPackageNamesWithoutMakingARequest() {
        SyncOutcome outcome = service.syncPackages(List.of("  ", ""));

        assertThat(outcome.synced()).isEqualTo(0);
        assertThat(outcome.unresolved()).isEqualTo(0);
        server.verify();
    }
}
