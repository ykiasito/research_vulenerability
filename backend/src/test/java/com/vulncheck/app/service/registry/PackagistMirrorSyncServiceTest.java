package com.vulncheck.app.service.registry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.vulncheck.app.repository.RegistryPackageMirrorRepository;
import com.vulncheck.app.service.ratelimit.ExternalRegistryRateLimiter;
import com.vulncheck.app.service.registry.PackagistMirrorSyncService.SyncOutcome;
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

class PackagistMirrorSyncServiceTest {

    private MockRestServiceServer server;
    private PackagistMirrorSyncService service;
    private RegistryPackageMirrorRepository registryPackageMirrorRepository;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        registryPackageMirrorRepository = Mockito.mock(RegistryPackageMirrorRepository.class);
        service = new PackagistMirrorSyncService(
                builder.build(), ExternalRegistryRateLimiter.disabledForTesting(), registryPackageMirrorRepository);
    }

    @Test
    void syncsAPackageAndUpsertsItsFullVersionListNormalized() {
        server.expect(requestTo("https://repo.packagist.org/p2/monolog/monolog.json"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(
                        "{\"packages\":{\"monolog/monolog\":["
                                + "{\"version\":\"3.10.0\"},{\"version\":\"3.9.0\"}]}}",
                        MediaType.APPLICATION_JSON));

        SyncOutcome outcome = service.syncPackages(List.of("monolog/monolog"));

        assertThat(outcome.synced()).isEqualTo(1);
        assertThat(outcome.unresolved()).isEqualTo(0);
        server.verify();

        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("packagist"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).containsEntry("monolog/monolog", List.of("3.10.0", "3.9.0"));
    }

    @Test
    void keepsAVTaggedVersionAsIsMatchingTheLiveClientsExistingBehavior() {
        server.expect(requestTo("https://repo.packagist.org/p2/symfony/console.json"))
                .andRespond(withSuccess(
                        "{\"packages\":{\"symfony/console\":[{\"version\":\"v8.1.5\"}]}}",
                        MediaType.APPLICATION_JSON));

        service.syncPackages(List.of("symfony/console"));

        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("packagist"), batchCaptor.capture());
        assertThat(batchCaptor.getValue().get("symfony/console")).containsExactly("v8.1.5");
    }

    @Test
    void normalizesTheStorageKeyLikeOsvPackageNameNormalizerDoes() {
        server.expect(requestTo("https://repo.packagist.org/p2/Monolog/Monolog.json"))
                .andRespond(withSuccess(
                        "{\"packages\":{\"Monolog/Monolog\":[{\"version\":\"3.10.0\"}]}}",
                        MediaType.APPLICATION_JSON));

        service.syncPackages(List.of("Monolog/Monolog"));

        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("packagist"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).containsOnlyKeys("monolog/monolog");
    }

    @Test
    void countsA404AsUnresolvedAndDoesNotWriteThatPackageIntoTheBatch() {
        server.expect(requestTo("https://repo.packagist.org/p2/totally/unknown-package.json"))
                .andRespond(withStatus(HttpStatus.NOT_FOUND));

        SyncOutcome outcome = service.syncPackages(List.of("totally/unknown-package"));

        assertThat(outcome.synced()).isEqualTo(0);
        assertThat(outcome.unresolved()).isEqualTo(1);
        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("packagist"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).isEmpty();
    }

    @Test
    void countsAPackageNameWithNoVendorSlashAsUnresolvedWithoutAnyHttpCall() {
        // Same structural limitation as PackagistRegistryClient.lookup -- "monolog" alone (not
        // "monolog/monolog") has no p2 endpoint to query.
        SyncOutcome outcome = service.syncPackages(List.of("monolog"));

        assertThat(outcome.synced()).isEqualTo(0);
        assertThat(outcome.unresolved()).isEqualTo(1);
        server.verify();
        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("packagist"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).isEmpty();
    }

    @Test
    void rejectsATraversalShapedVendorSegmentWithoutAnyHttpCallAndCountsItAsUnresolved() {
        // Closed-mode backlog item 184: contains exactly one "/" (so it passes syncPackages' own
        // coarse precheck above) but the vendor side is a ".." traversal segment.
        SyncOutcome outcome = service.syncPackages(List.of("../monolog"));

        assertThat(outcome.synced()).isEqualTo(0);
        assertThat(outcome.unresolved()).isEqualTo(1);
        server.verify();
        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("packagist"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).isEmpty();
    }

    @Test
    void rejectsAPackageNameWithMoreThanOneSlashWithoutAnyHttpCallAndCountsItAsUnresolved() {
        SyncOutcome outcome = service.syncPackages(List.of("monolog/monolog/extra"));

        assertThat(outcome.synced()).isEqualTo(0);
        assertThat(outcome.unresolved()).isEqualTo(1);
        server.verify();
        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("packagist"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).isEmpty();
    }

    @Test
    void rejectsAPackageNameWithDisallowedCharactersWithoutAnyHttpCallAndCountsItAsUnresolved() {
        SyncOutcome outcome = service.syncPackages(List.of("mono$log/monolog"));

        assertThat(outcome.synced()).isEqualTo(0);
        assertThat(outcome.unresolved()).isEqualTo(1);
        server.verify();
        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("packagist"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).isEmpty();
    }

    @Test
    void neverConsumesARateLimitSlotForAnInvalidPackageName() {
        // Closed-mode backlog item 184 REVISE: the name-grammar check must run before
        // rateLimiter.awaitTurn, not just before the HTTP call -- otherwise a name that's going to
        // be rejected anyway still delays the next name in the batch by Packagist's ~500ms pacing.
        ExternalRegistryRateLimiter mockRateLimiter = Mockito.mock(ExternalRegistryRateLimiter.class);
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer mockServer = MockRestServiceServer.bindTo(builder).build();
        PackagistMirrorSyncService serviceWithMockedLimiter = new PackagistMirrorSyncService(
                builder.build(), mockRateLimiter, registryPackageMirrorRepository);

        SyncOutcome outcome = serviceWithMockedLimiter.syncPackages(List.of("../monolog"));

        assertThat(outcome.unresolved()).isEqualTo(1);
        mockServer.verify();
        Mockito.verify(mockRateLimiter, Mockito.never()).awaitTurn(Mockito.anyString());
    }
}
