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

class NuGetRegistryClientTest {

    private MockRestServiceServer server;
    private NuGetRegistryClient client;
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
        client = new NuGetRegistryClient(builder.build(), ExternalRegistryRateLimiter.disabledForTesting(), mirrorRepository);
    }

    @Test
    void confirmsWhenTheExactVersionIsPublishedCaseInsensitively() {
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(
                        "{\"versions\":[\"13.0.2\",\"13.0.3\"]}", MediaType.APPLICATION_JSON));

        Optional<RegistryMatch> result = client.lookup("Newtonsoft.Json", "13.0.3");

        assertThat(result).isPresent();
        // Keeps the caller's original casing, not the lowercased id used for the flat-container
        // URL — OSV.dev and GitHub Advisories are both case-sensitive on the NuGet package name
        // (confirmed live: querying "newtonsoft.json" finds nothing, "Newtonsoft.Json" does), and
        // the flat-container response never echoes back the canonical case to recover it from.
        assertThat(result.get().packageName()).isEqualTo("Newtonsoft.Json");
        assertThat(result.get().purl()).isEqualTo("pkg:nuget/newtonsoft.json@13.0.3");
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.95");
        assertThat(result.get().versions()).containsExactlyInAnyOrder("13.0.2", "13.0.3");
        server.verify();
    }

    @Test
    void packageExistsButRequestedVersionDoesNot() {
        // Same shape as the real "cURL"/"OpenSSL"/"7-Zip" collisions found live: a NuGet package
        // exists under the literal name but isn't the real desktop tool the CSV row meant.
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess("{\"versions\":[\"1.0.0\"]}", MediaType.APPLICATION_JSON));

        Optional<RegistryMatch> result = client.lookup("curl", "8.4.0");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isFalse();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.5");
        server.verify();
    }

    @Test
    void returnsEmptyWhenThePackageDoesNotExist() {
        server.expect(method(HttpMethod.GET)).andRespond(withStatus(HttpStatus.NOT_FOUND));

        Optional<RegistryMatch> result = client.lookup("totally-unknown-package", "1.0.0");

        assertThat(result).isEmpty();
        server.verify();
    }

    @Test
    void mirrorEnabledButNotYetSyncedFallsBackToLiveLookup() {
        ReflectionTestUtils.setField(client, "mirrorEnabled", true);
        Mockito.when(mirrorRepository.hasAnyEntries("nuget")).thenReturn(false);
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess("{\"versions\":[\"13.0.3\"]}", MediaType.APPLICATION_JSON));

        Optional<RegistryMatch> result = client.lookup("Newtonsoft.Json", "13.0.3");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        server.verify();
    }

    @Test
    void mirrorEnabledAndSyncedAnswersFromTheMirrorWithoutAnyHttpCall() {
        ReflectionTestUtils.setField(client, "mirrorEnabled", true);
        Mockito.when(mirrorRepository.hasAnyEntries("nuget")).thenReturn(true);
        Mockito.when(mirrorRepository.findVersions("nuget", "newtonsoft.json"))
                .thenReturn(List.of("13.0.2", "13.0.3"));

        Optional<RegistryMatch> result = client.lookup("Newtonsoft.Json", "13.0.3");

        assertThat(result).isPresent();
        // Same as the live path: the mirror never has a canonically-cased id to recover, so the
        // purl is built off the lowercase-folded storage key, not the caller's original casing.
        assertThat(result.get().purl()).isEqualTo("pkg:nuget/newtonsoft.json@13.0.3");
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.95");
        server.verify();
    }

    @Test
    void mirrorLookupIsCaseInsensitiveOnTheRequestedVersionSameAsTheLivePath() {
        ReflectionTestUtils.setField(client, "mirrorEnabled", true);
        Mockito.when(mirrorRepository.hasAnyEntries("nuget")).thenReturn(true);
        Mockito.when(mirrorRepository.findVersions("nuget", "somepackage"))
                .thenReturn(List.of("1.0.0-Beta1"));

        Optional<RegistryMatch> result = client.lookup("SomePackage", "1.0.0-beta1");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        server.verify();
    }

    @Test
    void mirrorEnabledAndSyncedButPackageNotInMirrorReturnsEmptyWithoutAnyHttpCall() {
        ReflectionTestUtils.setField(client, "mirrorEnabled", true);
        Mockito.when(mirrorRepository.hasAnyEntries("nuget")).thenReturn(true);
        Mockito.when(mirrorRepository.findVersions("nuget", "totally-unknown-package"))
                .thenReturn(List.of());

        Optional<RegistryMatch> result = client.lookup("totally-unknown-package", "1.0.0");

        assertThat(result).isEmpty();
        server.verify();
    }
}
