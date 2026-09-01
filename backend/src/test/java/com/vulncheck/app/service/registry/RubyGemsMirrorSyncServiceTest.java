package com.vulncheck.app.service.registry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.vulncheck.app.repository.RegistryPackageMirrorRepository;
import com.vulncheck.app.service.ratelimit.ExternalRegistryRateLimiter;
import com.vulncheck.app.service.registry.RubyGemsMirrorSyncService.SyncOutcome;
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

class RubyGemsMirrorSyncServiceTest {

    private MockRestServiceServer server;
    private RubyGemsMirrorSyncService service;
    private RegistryPackageMirrorRepository registryPackageMirrorRepository;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        registryPackageMirrorRepository = Mockito.mock(RegistryPackageMirrorRepository.class);
        service = new RubyGemsMirrorSyncService(
                builder.build(), ExternalRegistryRateLimiter.disabledForTesting(), registryPackageMirrorRepository);
    }

    @Test
    void syncsAPackageAndUpsertsItsFullVersionListNormalized() {
        server.expect(requestTo("https://index.rubygems.org/info/rails"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(
                        "---\n"
                                + "7.0.0 railties:= 7.0.0|checksum:abc,created_at:2022-01-01T00:00:00Z\n"
                                + "7.0.1 railties:= 7.0.1|checksum:def,created_at:2022-02-01T00:00:00Z\n",
                        MediaType.TEXT_PLAIN));

        SyncOutcome outcome = service.syncPackages(List.of("rails"));

        assertThat(outcome.synced()).isEqualTo(1);
        assertThat(outcome.unresolved()).isEqualTo(0);
        server.verify();

        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("rubygems"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).containsEntry("rails", List.of("7.0.0", "7.0.1"));
    }

    @Test
    void parsesAVersionLineWithNoDependenciesWhoseDepsSegmentIsJustASpaceBeforeThePipe() {
        server.expect(requestTo("https://index.rubygems.org/info/rake"))
                .andRespond(withSuccess(
                        "---\n13.0.0 |checksum:abc,ruby:>= 2.2,created_at:2019-09-27T08:22:14Z\n",
                        MediaType.TEXT_PLAIN));

        service.syncPackages(List.of("rake"));

        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("rubygems"), batchCaptor.capture());
        assertThat(batchCaptor.getValue().get("rake")).containsExactly("13.0.0");
    }

    @Test
    void normalizesTheStorageKeyLikeOsvPackageNameNormalizerDoes() {
        server.expect(requestTo("https://index.rubygems.org/info/Rails"))
                .andRespond(withSuccess("---\n7.0.1 |checksum:abc,created_at:2022-02-01T00:00:00Z\n",
                        MediaType.TEXT_PLAIN));

        service.syncPackages(List.of("Rails"));

        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("rubygems"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).containsOnlyKeys("rails");
    }

    @Test
    void countsA404AsUnresolvedAndDoesNotWriteThatPackageIntoTheBatch() {
        server.expect(requestTo("https://index.rubygems.org/info/totally-unknown-gem"))
                .andRespond(withStatus(HttpStatus.NOT_FOUND));

        SyncOutcome outcome = service.syncPackages(List.of("totally-unknown-gem"));

        assertThat(outcome.synced()).isEqualTo(0);
        assertThat(outcome.unresolved()).isEqualTo(1);
        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("rubygems"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).isEmpty();
    }

    @Test
    void parseVersionsSkipsTheLeadingSeparatorLineAndBlankLines() {
        String body = "---\n7.0.0 railties:= 7.0.0|checksum:abc,created_at:2022-01-01T00:00:00Z\n\n"
                + "7.0.1 |checksum:def,created_at:2022-02-01T00:00:00Z\n";

        assertThat(RubyGemsMirrorSyncService.parseVersions(body)).containsExactly("7.0.0", "7.0.1");
    }

    @Test
    void parseVersionsReturnsEmptyListForABlankOrSeparatorOnlyBody() {
        assertThat(RubyGemsMirrorSyncService.parseVersions("")).isEmpty();
        assertThat(RubyGemsMirrorSyncService.parseVersions("---\n")).isEmpty();
    }
}
