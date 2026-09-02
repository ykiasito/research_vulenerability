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

class PubRegistryClientTest {

    private MockRestServiceServer server;
    private PubRegistryClient client;
    private RegistryPackageMirrorRepository mirrorRepository;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        // mirrorEnabled defaults to false (this @Value field is never injected outside a Spring
        // context), so every test below (unless it explicitly flips the field, see the mirror-path
        // tests) exercises the pre-existing live path, same as before the mirror wiring was added --
        // no need to stub the mock's hasAnyEntries/findVersions.
        mirrorRepository = Mockito.mock(RegistryPackageMirrorRepository.class);
        client = new PubRegistryClient(builder.build(), ExternalRegistryRateLimiter.disabledForTesting(), mirrorRepository);
    }

    @Test
    void confirmsWhenTheExactVersionIsPublished() {
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(
                        "{\"versions\":[{\"version\":\"1.2.0\"},{\"version\":\"1.1.0\"}]}", MediaType.APPLICATION_JSON));

        Optional<RegistryMatch> result = client.lookup("http", "1.2.0");

        assertThat(result).isPresent();
        assertThat(result.get().packageName()).isEqualTo("http");
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.95");
        assertThat(result.get().versions()).containsExactlyInAnyOrder("1.2.0", "1.1.0");
        server.verify();
    }

    @Test
    void packageExistsButRequestedVersionDoesNot() {
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess("{\"versions\":[{\"version\":\"0.1.0\"}]}", MediaType.APPLICATION_JSON));

        Optional<RegistryMatch> result = client.lookup("http", "1.2.0");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isFalse();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.5");
        server.verify();
    }

    @Test
    void returnsEmptyWhenThePackageDoesNotExist() {
        server.expect(method(HttpMethod.GET)).andRespond(withStatus(HttpStatus.NOT_FOUND));

        Optional<RegistryMatch> result = client.lookup("totally-unknown-pub-pkg", "1.0.0");

        assertThat(result).isEmpty();
        server.verify();
    }

    @Test
    void mirrorEnabledButNotYetSyncedFallsBackToLiveLookup() {
        ReflectionTestUtils.setField(client, "mirrorEnabled", true);
        Mockito.when(mirrorRepository.hasAnyEntries("pub")).thenReturn(false);
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess("{\"versions\":[{\"version\":\"1.2.0\"}]}", MediaType.APPLICATION_JSON));

        Optional<RegistryMatch> result = client.lookup("http", "1.2.0");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        server.verify();
    }

    @Test
    void mirrorEnabledAndSyncedAnswersFromTheMirrorWithoutAnyHttpCall() {
        ReflectionTestUtils.setField(client, "mirrorEnabled", true);
        Mockito.when(mirrorRepository.hasAnyEntries("pub")).thenReturn(true);
        Mockito.when(mirrorRepository.findVersions("pub", "http"))
                .thenReturn(List.of("1.2.0", "1.1.0"));

        Optional<RegistryMatch> result = client.lookup("http", "1.2.0");

        assertThat(result).isPresent();
        assertThat(result.get().packageName()).isEqualTo("http");
        assertThat(result.get().purl()).isEqualTo("pkg:pub/http@1.2.0");
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.95");
        server.verify();
    }

    @Test
    void mirrorEnabledAndSyncedButPackageNotInMirrorReturnsEmptyWithoutAnyHttpCall() {
        ReflectionTestUtils.setField(client, "mirrorEnabled", true);
        Mockito.when(mirrorRepository.hasAnyEntries("pub")).thenReturn(true);
        Mockito.when(mirrorRepository.findVersions("pub", "totally-unknown-pub-pkg"))
                .thenReturn(List.of());

        Optional<RegistryMatch> result = client.lookup("totally-unknown-pub-pkg", "1.0.0");

        assertThat(result).isEmpty();
        server.verify();
    }
}
