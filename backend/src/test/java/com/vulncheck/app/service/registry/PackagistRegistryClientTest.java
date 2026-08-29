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

class PackagistRegistryClientTest {

    private MockRestServiceServer server;
    private PackagistRegistryClient client;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        client = new PackagistRegistryClient(builder.build(), ExternalRegistryRateLimiter.disabledForTesting());
    }

    @Test
    void confirmsWhenTheExactVersionIsPublished() {
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(
                        "{\"package\":{\"versions\":{\"3.5.0\":{},\"3.4.0\":{}}}}", MediaType.APPLICATION_JSON));

        Optional<RegistryMatch> result = client.lookup("monolog/monolog", "3.5.0");

        assertThat(result).isPresent();
        assertThat(result.get().packageName()).isEqualTo("monolog/monolog");
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.95");
        assertThat(result.get().versions()).containsExactlyInAnyOrder("3.5.0", "3.4.0");
        server.verify();
    }

    @Test
    void packageExistsButRequestedVersionDoesNot() {
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess("{\"package\":{\"versions\":{\"0.1.0\":{}}}}", MediaType.APPLICATION_JSON));

        Optional<RegistryMatch> result = client.lookup("monolog/monolog", "3.5.0");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isFalse();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.5");
        server.verify();
    }

    @Test
    void returnsEmptyWhenThePackageDoesNotExist() {
        server.expect(method(HttpMethod.GET)).andRespond(withStatus(HttpStatus.NOT_FOUND));

        Optional<RegistryMatch> result = client.lookup("totally/unknown-package", "1.0.0");

        assertThat(result).isEmpty();
        server.verify();
    }

    @Test
    void returnsEmptyWithoutAnyHttpCallWhenProductNameHasNoVendorSlash() {
        // Packagist has no lookup-by-bare-name endpoint — "monolog" alone (not "monolog/monolog")
        // has nothing to query. A real, structural limitation of this ecosystem, not a bug.
        Optional<RegistryMatch> result = client.lookup("monolog", "3.5.0");

        assertThat(result).isEmpty();
        server.verify();
    }
}
