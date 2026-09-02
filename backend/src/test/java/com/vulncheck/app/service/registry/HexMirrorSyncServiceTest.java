package com.vulncheck.app.service.registry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.vulncheck.app.repository.RegistryPackageMirrorRepository;
import com.vulncheck.app.service.ratelimit.ExternalRegistryRateLimiter;
import com.vulncheck.app.service.registry.HexMirrorSyncService.SyncOutcome;
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

class HexMirrorSyncServiceTest {

    private MockRestServiceServer server;
    private HexMirrorSyncService service;
    private RegistryPackageMirrorRepository registryPackageMirrorRepository;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        registryPackageMirrorRepository = Mockito.mock(RegistryPackageMirrorRepository.class);
        service = new HexMirrorSyncService(builder.build(), ExternalRegistryRateLimiter.disabledForTesting(),
                registryPackageMirrorRepository);
    }

    @Test
    void syncsAPackageAndUpsertsItsFullVersionList() {
        server.expect(requestTo("https://hex.pm/api/packages/phoenix"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(
                        "{\"releases\":[{\"version\":\"1.8.12\"},{\"version\":\"1.8.11\"}]}",
                        MediaType.APPLICATION_JSON));

        SyncOutcome outcome = service.syncPackages(List.of("phoenix"));

        assertThat(outcome.synced()).isEqualTo(1);
        assertThat(outcome.unresolved()).isEqualTo(0);
        server.verify();

        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("hex"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).containsEntry("phoenix", List.of("1.8.12", "1.8.11"));
    }

    @Test
    void normalizesTheStorageKeyToLowercase() {
        server.expect(requestTo("https://hex.pm/api/packages/Phoenix"))
                .andRespond(withSuccess("{\"releases\":[{\"version\":\"1.0.0\"}]}", MediaType.APPLICATION_JSON));

        service.syncPackages(List.of("Phoenix"));

        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("hex"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).containsOnlyKeys("phoenix");
    }

    @Test
    void countsA404AsUnresolvedAndDoesNotWriteThatPackageIntoTheBatch() {
        server.expect(requestTo("https://hex.pm/api/packages/totally-unknown-hex-pkg"))
                .andRespond(withStatus(HttpStatus.NOT_FOUND));

        SyncOutcome outcome = service.syncPackages(List.of("totally-unknown-hex-pkg"));

        assertThat(outcome.synced()).isEqualTo(0);
        assertThat(outcome.unresolved()).isEqualTo(1);
        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("hex"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).isEmpty();
    }

    @Test
    void treatsAnEmptyReleasesArrayAsUnresolved() {
        server.expect(requestTo("https://hex.pm/api/packages/empty-pkg"))
                .andRespond(withSuccess("{\"releases\":[]}", MediaType.APPLICATION_JSON));

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
