package com.vulncheck.app.service.registry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
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

class CratesIoRegistryClientTest {

    private MockRestServiceServer server;
    private CratesIoRegistryClient client;
    private RegistryPackageMirrorRepository registryPackageMirrorRepository;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        registryPackageMirrorRepository = Mockito.mock(RegistryPackageMirrorRepository.class);
        client = new CratesIoRegistryClient(
                builder.build(), ExternalRegistryRateLimiter.disabledForTesting(), registryPackageMirrorRepository);
        // mirrorEnabled defaults to false (plain field default, @Value only applies via a real
        // Spring context) for every test below except the dedicated mirror-path tests, which flip
        // it on themselves -- so every existing live-path test continues to exercise exactly the
        // pre-mirror behavior, unaffected by this new dependency.
    }

    @Test
    void confirmsWhenTheExactVersionIsPublished() {
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(
                        "{\"versions\":[{\"num\":\"1.0.229\"},{\"num\":\"1.0.228\"}]}", MediaType.APPLICATION_JSON));

        Optional<RegistryMatch> result = client.lookup("serde", "1.0.229");

        assertThat(result).isPresent();
        assertThat(result.get().packageName()).isEqualTo("serde");
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.95");
        assertThat(result.get().versions()).containsExactlyInAnyOrder("1.0.229", "1.0.228");
        server.verify();
    }

    @Test
    void packageExistsButRequestedVersionDoesNot() {
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess("{\"versions\":[{\"num\":\"0.1.0\"}]}", MediaType.APPLICATION_JSON));

        Optional<RegistryMatch> result = client.lookup("serde", "1.0.229");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isFalse();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.5");
        server.verify();
    }

    @Test
    void returnsEmptyWhenThePackageDoesNotExist() {
        server.expect(method(HttpMethod.GET)).andRespond(withStatus(HttpStatus.NOT_FOUND));

        Optional<RegistryMatch> result = client.lookup("totally-unknown-crate", "1.0.0");

        assertThat(result).isEmpty();
        server.verify();
    }

    @Test
    void mirrorDisabledByDefaultNeverConsultsTheMirrorRepository() {
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess("{\"versions\":[{\"num\":\"1.0.229\"}]}", MediaType.APPLICATION_JSON));

        client.lookup("serde", "1.0.229");

        server.verify();
        Mockito.verifyNoInteractions(registryPackageMirrorRepository);
    }

    @Test
    void mirrorEnabledButNeverSyncedFallsBackToLiveLookup() {
        ReflectionTestUtils.setField(client, "mirrorEnabled", true);
        Mockito.when(registryPackageMirrorRepository.hasAnyEntries("crates.io")).thenReturn(false);
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess("{\"versions\":[{\"num\":\"1.0.229\"}]}", MediaType.APPLICATION_JSON));

        Optional<RegistryMatch> result = client.lookup("serde", "1.0.229");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        server.verify();
        Mockito.verify(registryPackageMirrorRepository, Mockito.never()).findVersions(Mockito.any(), Mockito.any());
    }

    @Test
    void mirrorEnabledAndPopulatedConfirmsAnExactVersionWithoutAnyLiveCall() {
        ReflectionTestUtils.setField(client, "mirrorEnabled", true);
        Mockito.when(registryPackageMirrorRepository.hasAnyEntries("crates.io")).thenReturn(true);
        Mockito.when(registryPackageMirrorRepository.findVersions("crates.io", "serde"))
                .thenReturn(List.of("1.0.229", "1.0.228"));

        Optional<RegistryMatch> result = client.lookup("serde", "1.0.229");

        assertThat(result).isPresent();
        assertThat(result.get().packageName()).isEqualTo("serde");
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.95");
        assertThat(result.get().versions()).containsExactlyInAnyOrder("1.0.229", "1.0.228");
        server.verify(); // no requests were ever expected/sent on this mock server
    }

    @Test
    void mirrorEnabledAndPopulatedButPackageAbsentReturnsEmptyWithNoLiveFallback() {
        ReflectionTestUtils.setField(client, "mirrorEnabled", true);
        Mockito.when(registryPackageMirrorRepository.hasAnyEntries("crates.io")).thenReturn(true);
        Mockito.when(registryPackageMirrorRepository.findVersions("crates.io", "totally-unknown-crate"))
                .thenReturn(List.of());

        Optional<RegistryMatch> result = client.lookup("totally-unknown-crate", "1.0.0");

        assertThat(result).isEmpty();
        server.verify(); // no requests were ever expected/sent on this mock server
    }

    @Test
    void mirrorEnabledAndPopulatedNormalizesTheQueryNameLikeOsvPackageNameNormalizerDoes() {
        ReflectionTestUtils.setField(client, "mirrorEnabled", true);
        Mockito.when(registryPackageMirrorRepository.hasAnyEntries("crates.io")).thenReturn(true);
        // Sync-time storage keys are normalized (see OsvPackageNameNormalizer#normalize's crates.io
        // "-"/"_" folding), so a query for the "_" spelling must still look up the "-" mirror key.
        Mockito.when(registryPackageMirrorRepository.findVersions("crates.io", "serde-json"))
                .thenReturn(List.of("1.0.0"));

        Optional<RegistryMatch> result = client.lookup("serde_json", "1.0.0");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isTrue();
    }
}
