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

class CratesIoRegistryClientTest {

    private MockRestServiceServer server;
    private CratesIoRegistryClient client;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        client = new CratesIoRegistryClient(builder.build(), ExternalRegistryRateLimiter.disabledForTesting());
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
}
