package com.vulncheck.app.service.registry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.vulncheck.app.repository.RegistryPackageMirrorRepository;
import com.vulncheck.app.service.ratelimit.ExternalRegistryRateLimiter;
import com.vulncheck.app.service.registry.PyPiMirrorSyncService.SyncOutcome;
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

class PyPiMirrorSyncServiceTest {

    private MockRestServiceServer server;
    private PyPiMirrorSyncService service;
    private RegistryPackageMirrorRepository registryPackageMirrorRepository;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        registryPackageMirrorRepository = Mockito.mock(RegistryPackageMirrorRepository.class);
        service = new PyPiMirrorSyncService(builder.build(), ExternalRegistryRateLimiter.disabledForTesting(),
                registryPackageMirrorRepository);
    }

    @Test
    void syncsAPackageAndUpsertsItsFullVersionList() {
        server.expect(requestTo("https://pypi.org/simple/requests/"))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("Accept", "application/vnd.pypi.simple.v1+json"))
                .andRespond(withSuccess(
                        "{\"name\":\"requests\",\"versions\":[\"2.31.0\",\"2.30.0\"]}",
                        MediaType.valueOf("application/vnd.pypi.simple.v1+json")));

        SyncOutcome outcome = service.syncPackages(List.of("requests"));

        assertThat(outcome.synced()).isEqualTo(1);
        assertThat(outcome.unresolved()).isEqualTo(0);
        server.verify();

        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("pypi"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).containsEntry("requests", List.of("2.31.0", "2.30.0"));
    }

    @Test
    void normalizesTheStorageKeyAndUrlPathPerPep503() {
        // PEP 503: mixed case and "_"/"." collapse into a single "-", lowercased. "Django-Extensions"
        // (an unnormalized name) would 301-redirect on the real API — pre-normalizing avoids that.
        server.expect(requestTo("https://pypi.org/simple/django-extensions/"))
                .andRespond(withSuccess(
                        "{\"name\":\"django-extensions\",\"versions\":[\"3.2.3\"]}",
                        MediaType.valueOf("application/vnd.pypi.simple.v1+json")));

        service.syncPackages(List.of("Django-Extensions"));

        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("pypi"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).containsOnlyKeys("django-extensions");
    }

    @Test
    void countsA404AsUnresolvedAndDoesNotWriteThatPackageIntoTheBatch() {
        server.expect(requestTo("https://pypi.org/simple/totally-unknown-pypi-pkg/"))
                .andRespond(withStatus(HttpStatus.NOT_FOUND));

        SyncOutcome outcome = service.syncPackages(List.of("totally-unknown-pypi-pkg"));

        assertThat(outcome.synced()).isEqualTo(0);
        assertThat(outcome.unresolved()).isEqualTo(1);
        ArgumentCaptor<Map<String, List<String>>> batchCaptor = ArgumentCaptor.forClass(Map.class);
        Mockito.verify(registryPackageMirrorRepository).upsertBatch(Mockito.eq("pypi"), batchCaptor.capture());
        assertThat(batchCaptor.getValue()).isEmpty();
    }

    @Test
    void treatsAnEmptyVersionsArrayAsUnresolved() {
        server.expect(requestTo("https://pypi.org/simple/empty-pkg/"))
                .andRespond(withSuccess(
                        "{\"name\":\"empty-pkg\",\"versions\":[]}",
                        MediaType.valueOf("application/vnd.pypi.simple.v1+json")));

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
