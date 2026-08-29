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

class PyPiRegistryClientTest {

    private MockRestServiceServer server;
    private PyPiRegistryClient client;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        client = new PyPiRegistryClient(builder.build(), ExternalRegistryRateLimiter.disabledForTesting());
    }

    @Test
    void confirmsWhenTheExactVersionIsPublished() {
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(
                        "{\"info\":{\"name\":\"requests\"},\"releases\":{\"2.31.0\":[],\"2.30.0\":[]}}",
                        MediaType.APPLICATION_JSON));

        Optional<RegistryMatch> result = client.lookup("requests", "2.31.0");

        assertThat(result).isPresent();
        assertThat(result.get().packageName()).isEqualTo("requests");
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.95");
        assertThat(result.get().versions()).containsExactlyInAnyOrder("2.31.0", "2.30.0");
        server.verify();
    }

    @Test
    void packageExistsButRequestedVersionDoesNot() {
        // Same shape as the real "PuTTY" collision found live: PyPI has an unrelated package
        // literally named "Putty" that is not the real Windows terminal client.
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(
                        "{\"info\":{\"name\":\"Putty\"},\"releases\":{\"0.1.0\":[]}}",
                        MediaType.APPLICATION_JSON));

        Optional<RegistryMatch> result = client.lookup("PuTTY", "0.79");

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
