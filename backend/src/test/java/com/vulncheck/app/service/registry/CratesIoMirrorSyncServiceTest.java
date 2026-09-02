package com.vulncheck.app.service.registry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulncheck.app.repository.RegistryPackageMirrorRepository;
import com.vulncheck.app.service.registry.CratesIoMirrorSyncService.SyncOutcome;
import com.vulncheck.app.service.ratelimit.ExternalRegistryRateLimiter;
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

class CratesIoMirrorSyncServiceTest {

    private MockRestServiceServer server;
    private CratesIoMirrorSyncService service;
    private RegistryPackageMirrorRepository registryPackageMirrorRepository;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        registryPackageMirrorRepository = Mockito.mock(RegistryPackageMirrorRepository.class);
        service = new CratesIoMirrorSyncService(builder.build(), ExternalRegistryRateLimiter.disabledForTesting(),
                registryPackageMirrorRepository, new ObjectMapper());
    }

    @Test
    void syncsAPackageAndUpsertsItsFullVersionListNormalized() {
        server.expect(requestTo("https://index.crates.io/se/rd/serde"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(
                        "{\"name\":\"serde\",\"vers\":\"1.0.228\",\"yanked\":false}\n"
                                + "{\"name\":\"serde\",\"vers\":\"1.0.229\",\"yanked\":false}\n",
                        MediaType.TEXT_PLAIN));

        SyncOutcome outcome = service.syncPackages(List.of("serde"));

        assertThat(outcome.synced()).isEqualTo(1);
        assertThat(outcome.unresolved()).isEqualTo(0);
        server.verify();

        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("crates.io"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).containsEntry("serde", List.of("1.0.228", "1.0.229"));
    }

    @Test
    void includesYankedVersionsMatchingTheLiveClientsExistingBehavior() {
        server.expect(requestTo("https://index.crates.io/se/rd/serde"))
                .andRespond(withSuccess(
                        "{\"name\":\"serde\",\"vers\":\"0.0.1\",\"yanked\":true}\n", MediaType.TEXT_PLAIN));

        service.syncPackages(List.of("serde"));

        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("crates.io"), batchCaptor.capture());
        assertThat(batchCaptor.getValue().get("serde")).containsExactly("0.0.1");
    }

    @Test
    void normalizesTheStorageKeyLikeOsvPackageNameNormalizerDoes() {
        server.expect(requestTo("https://index.crates.io/se/rd/serde_json"))
                .andRespond(withSuccess("{\"name\":\"serde_json\",\"vers\":\"1.0.0\"}\n", MediaType.TEXT_PLAIN));

        service.syncPackages(List.of("serde_json"));

        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("crates.io"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).containsOnlyKeys("serde-json");
    }

    @Test
    void countsA404AsUnresolvedAndDoesNotWriteThatPackageIntoTheBatch() {
        server.expect(requestTo("https://index.crates.io/to/ta/totally-unknown-crate"))
                .andRespond(withStatus(HttpStatus.NOT_FOUND));

        SyncOutcome outcome = service.syncPackages(List.of("totally-unknown-crate"));

        assertThat(outcome.synced()).isEqualTo(0);
        assertThat(outcome.unresolved()).isEqualTo(1);
        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("crates.io"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).isEmpty();
    }

    @Test
    void rejectsATraversalShapedPackageNameWithoutAnyHttpCallAndCountsItAsUnresolved() {
        // Closed-mode backlog item 184: a name whose length would map to a real sparse-index path
        // (see sparseIndexPathFollowsTheConfirmedLiveConvention below) but that also contains a ".."
        // segment must never reach the HTTP client.
        SyncOutcome outcome = service.syncPackages(List.of(".."));

        assertThat(outcome.synced()).isEqualTo(0);
        assertThat(outcome.unresolved()).isEqualTo(1);
        server.verify();
        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("crates.io"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).isEmpty();
    }

    @Test
    void rejectsAPackageNameWithDisallowedCharactersWithoutAnyHttpCallAndCountsItAsUnresolved() {
        SyncOutcome outcome = service.syncPackages(List.of("serde;rm -rf"));

        assertThat(outcome.synced()).isEqualTo(0);
        assertThat(outcome.unresolved()).isEqualTo(1);
        server.verify();
        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("crates.io"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).isEmpty();
    }

    @Test
    void rejectsAFourDotNameWhoseDerivedPathWouldTraverseEvenThoughTheWholeNameIsNotADotOrDotDot() {
        // Closed-mode backlog item 184 REVISE: sparseIndexPath("....") == "../../....", which climbs
        // two directories, but the name "...." itself is neither "." nor ".." as a whole segment --
        // a check that only asks "is the full name a traversal token" would miss this. It's caught
        // here because crates.io names may not contain "." at all (see
        // RegistryMirrorPackageNameValidator#validateSimpleName).
        SyncOutcome outcome = service.syncPackages(List.of("...."));

        assertThat(outcome.synced()).isEqualTo(0);
        assertThat(outcome.unresolved()).isEqualTo(1);
        server.verify();
        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("crates.io"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).isEmpty();
    }

    @Test
    void rejectsANameWhoseTwoCharacterPrefixIsADotDotSegmentEvenThoughTheWholeNameIsNot() {
        // Closed-mode backlog item 184 REVISE: sparseIndexPath("..ab") == "../ab/..ab" -- the first
        // path segment ("..") comes from a two-character substring of the name, not the name as a
        // whole, so "is the full name '..'" would also miss this one. Same fix as the "...." case
        // above: "." is simply not an allowed character in a crates.io name.
        SyncOutcome outcome = service.syncPackages(List.of("..ab"));

        assertThat(outcome.synced()).isEqualTo(0);
        assertThat(outcome.unresolved()).isEqualTo(1);
        server.verify();
        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("crates.io"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).isEmpty();
    }

    @Test
    void sparseIndexPathFollowsTheConfirmedLiveConvention() {
        assertThat(CratesIoMirrorSyncService.sparseIndexPath("x")).isEqualTo("1/x");
        assertThat(CratesIoMirrorSyncService.sparseIndexPath("io")).isEqualTo("2/io");
        assertThat(CratesIoMirrorSyncService.sparseIndexPath("abc")).isEqualTo("3/a/abc");
        assertThat(CratesIoMirrorSyncService.sparseIndexPath("rand")).isEqualTo("ra/nd/rand");
        assertThat(CratesIoMirrorSyncService.sparseIndexPath("serde_json")).isEqualTo("se/rd/serde_json");
    }
}
