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

class GoProxyRegistryClientTest {

    private MockRestServiceServer server;
    private GoProxyRegistryClient client;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        client = new GoProxyRegistryClient(builder.build(), ExternalRegistryRateLimiter.disabledForTesting());
    }

    @Test
    void confirmsWhenTheExactVersionInfoEndpointSucceeds() {
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess("{\"Version\":\"v1.9.1\"}", MediaType.APPLICATION_JSON));

        Optional<RegistryMatch> result = client.lookup("github.com/gin-gonic/gin", "v1.9.1");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.95");
        server.verify();
    }

    @Test
    void moduleExistsButRequestedVersionDoesNotFallsBackToLatestCheck() {
        server.expect(method(HttpMethod.GET)).andRespond(withStatus(HttpStatus.NOT_FOUND));
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess("{\"Version\":\"v1.9.1\"}", MediaType.APPLICATION_JSON));

        Optional<RegistryMatch> result = client.lookup("github.com/gin-gonic/gin", "v99.0.0");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isFalse();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.4");
        server.verify();
    }

    @Test
    void returnsEmptyWhenTheModuleDoesNotExistAtAll() {
        server.expect(method(HttpMethod.GET)).andRespond(withStatus(HttpStatus.NOT_FOUND));
        server.expect(method(HttpMethod.GET)).andRespond(withStatus(HttpStatus.NOT_FOUND));

        Optional<RegistryMatch> result = client.lookup("github.com/nobody/nothing", "v1.0.0");

        assertThat(result).isEmpty();
        server.verify();
    }

    @Test
    void returnsEmptyWithoutAnyHttpCallWhenProductNameIsNotAModulePath() {
        Optional<RegistryMatch> result = client.lookup("gson", "2.10.1");

        assertThat(result).isEmpty();
        server.verify();
    }
}
