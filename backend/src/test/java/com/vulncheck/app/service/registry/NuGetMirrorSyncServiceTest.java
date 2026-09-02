package com.vulncheck.app.service.registry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.vulncheck.app.repository.RegistryPackageMirrorRepository;
import com.vulncheck.app.service.ratelimit.ExternalRegistryRateLimiter;
import com.vulncheck.app.service.registry.NuGetMirrorSyncService.SyncOutcome;
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

class NuGetMirrorSyncServiceTest {

    private MockRestServiceServer server;
    private NuGetMirrorSyncService service;
    private RegistryPackageMirrorRepository registryPackageMirrorRepository;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        registryPackageMirrorRepository = Mockito.mock(RegistryPackageMirrorRepository.class);
        service = new NuGetMirrorSyncService(builder.build(), ExternalRegistryRateLimiter.disabledForTesting(),
                registryPackageMirrorRepository);
    }

    @Test
    void syncsAPackageAndUpsertsItsFullVersionList() {
        server.expect(requestTo("https://api.nuget.org/v3-flatcontainer/newtonsoft.json/index.json"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(
                        "{\"versions\":[\"13.0.2\",\"13.0.3\"]}", MediaType.APPLICATION_JSON));

        SyncOutcome outcome = service.syncPackages(List.of("Newtonsoft.Json"));

        assertThat(outcome.synced()).isEqualTo(1);
        assertThat(outcome.unresolved()).isEqualTo(0);
        server.verify();

        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("nuget"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).containsOnlyKeys("newtonsoft.json");
        assertThat(batchCaptor.getValue().get("newtonsoft.json")).containsExactlyInAnyOrder("13.0.2", "13.0.3");
    }

    @Test
    void lowercasesThePackageIdInTheRequestUrl() {
        // Flat-container URLs require the lowercase id (confirmed live 2026-09-02, the response's
        // own "X-CDN-Rewrite: Lowercase blobs in v3-flatcontainer" header) -- same as
        // NuGetRegistryClient's pre-existing live path.
        server.expect(requestTo("https://api.nuget.org/v3-flatcontainer/automapper/index.json"))
                .andRespond(withSuccess("{\"versions\":[\"16.2.0\"]}", MediaType.APPLICATION_JSON));

        service.syncPackages(List.of("AutoMapper"));

        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("nuget"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).containsOnlyKeys("automapper");
    }

    @Test
    void countsA404AsUnresolvedAndDoesNotWriteThatPackageIntoTheBatch() {
        server.expect(requestTo("https://api.nuget.org/v3-flatcontainer/totally-unknown-nuget-pkg/index.json"))
                .andRespond(withStatus(HttpStatus.NOT_FOUND));

        SyncOutcome outcome = service.syncPackages(List.of("totally-unknown-nuget-pkg"));

        assertThat(outcome.synced()).isEqualTo(0);
        assertThat(outcome.unresolved()).isEqualTo(1);
        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("nuget"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).isEmpty();
    }

    @Test
    void treatsAMissingVersionsArrayAsUnresolved() {
        server.expect(requestTo("https://api.nuget.org/v3-flatcontainer/empty-pkg/index.json"))
                .andRespond(withSuccess("{}", MediaType.APPLICATION_JSON));

        SyncOutcome outcome = service.syncPackages(List.of("empty-pkg"));

        assertThat(outcome.synced()).isEqualTo(0);
        assertThat(outcome.unresolved()).isEqualTo(1);
    }

    @Test
    void treatsAnEmptyVersionsArrayAsUnresolved() {
        server.expect(requestTo("https://api.nuget.org/v3-flatcontainer/no-releases-pkg/index.json"))
                .andRespond(withSuccess("{\"versions\":[]}", MediaType.APPLICATION_JSON));

        SyncOutcome outcome = service.syncPackages(List.of("no-releases-pkg"));

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
