package com.vulncheck.app.service.registry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

class NpmRegistryClientTest {

    private MockRestServiceServer server;
    private NpmRegistryClient client;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        client = new NpmRegistryClient(builder.build(), ExternalRegistryRateLimiter.disabledForTesting());
    }

    @Test
    void confirmsWhenTheExactVersionIsPublished() {
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(
                        "{\"name\":\"lodash\",\"versions\":{\"4.17.21\":{},\"4.17.20\":{}}}",
                        MediaType.APPLICATION_JSON));

        Optional<RegistryMatch> result = client.lookup("lodash", "4.17.21");

        assertThat(result).isPresent();
        assertThat(result.get().packageName()).isEqualTo("lodash");
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.95");
        // Captured for RegistryLookupCache to re-derive a different version's answer without a
        // second request — see RegistryMatch#versions().
        assertThat(result.get().versions()).containsExactlyInAnyOrder("4.17.21", "4.17.20");
        server.verify();
    }

    @Test
    void packageExistsButRequestedVersionDoesNot() {
        // Same shape as the real "gson"/"junit"/"cobra" collisions found live: an unrelated
        // package happens to share the literal name, so it exists but never at this version.
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(
                        "{\"name\":\"gson\",\"versions\":{\"0.1.5\":{}}}",
                        MediaType.APPLICATION_JSON));

        Optional<RegistryMatch> result = client.lookup("gson", "2.10.1");

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
}
