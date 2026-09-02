package com.vulncheck.app.service.registry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.vulncheck.app.repository.RegistryPackageMirrorRepository;
import com.vulncheck.app.service.ratelimit.ExternalRegistryRateLimiter;
import com.vulncheck.app.service.registry.NpmMirrorSyncService.SyncOutcome;
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

class NpmMirrorSyncServiceTest {

    private MockRestServiceServer server;
    private NpmMirrorSyncService service;
    private RegistryPackageMirrorRepository registryPackageMirrorRepository;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        registryPackageMirrorRepository = Mockito.mock(RegistryPackageMirrorRepository.class);
        service = new NpmMirrorSyncService(builder.build(), ExternalRegistryRateLimiter.disabledForTesting(),
                registryPackageMirrorRepository);
    }

    @Test
    void syncsAPackageAndUpsertsItsFullVersionList() {
        server.expect(requestTo("https://registry.npmjs.org/lodash"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(
                        "{\"name\":\"lodash\",\"versions\":{\"4.17.21\":{},\"4.17.20\":{}}}",
                        MediaType.APPLICATION_JSON));

        SyncOutcome outcome = service.syncPackages(List.of("lodash"));

        assertThat(outcome.synced()).isEqualTo(1);
        assertThat(outcome.unresolved()).isEqualTo(0);
        server.verify();

        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("npm"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).containsOnlyKeys("lodash");
        assertThat(batchCaptor.getValue().get("lodash")).containsExactlyInAnyOrder("4.17.21", "4.17.20");
    }

    @Test
    void syncsAScopedPackageNameWithThePercentEncodedSlash() {
        // @scope/name is one logical path segment to the npm registry's per-package document
        // endpoint. RestClient's single {name} template variable percent-encodes both the "@" and
        // the "/" (%40, %2F) -- confirmed live 2026-09-02 that the real registry accepts this fully
        // percent-encoded form -- not the same "must be a raw, unencoded multi-segment path" trap
        // the Packagist p2 mirror hit.
        server.expect(requestTo("https://registry.npmjs.org/%40types%2Fnode"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(
                        "{\"name\":\"@types/node\",\"versions\":{\"22.10.1\":{}}}", MediaType.APPLICATION_JSON));

        SyncOutcome outcome = service.syncPackages(List.of("@types/node"));

        assertThat(outcome.synced()).isEqualTo(1);
        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("npm"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).containsEntry("@types/node", List.of("22.10.1"));
    }

    @Test
    void normalizesTheStorageKeyToLowercase() {
        server.expect(requestTo("https://registry.npmjs.org/Lodash"))
                .andRespond(withSuccess("{\"name\":\"Lodash\",\"versions\":{\"1.0.0\":{}}}", MediaType.APPLICATION_JSON));

        service.syncPackages(List.of("Lodash"));

        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("npm"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).containsOnlyKeys("lodash");
    }

    @Test
    void countsA404AsUnresolvedAndDoesNotWriteThatPackageIntoTheBatch() {
        server.expect(requestTo("https://registry.npmjs.org/totally-unknown-npm-pkg"))
                .andRespond(withStatus(HttpStatus.NOT_FOUND));

        SyncOutcome outcome = service.syncPackages(List.of("totally-unknown-npm-pkg"));

        assertThat(outcome.synced()).isEqualTo(0);
        assertThat(outcome.unresolved()).isEqualTo(1);
        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("npm"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).isEmpty();
    }

    @Test
    void treatsAMissingVersionsObjectAsUnresolved() {
        server.expect(requestTo("https://registry.npmjs.org/empty-pkg"))
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
