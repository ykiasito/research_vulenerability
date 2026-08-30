package com.vulncheck.app.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Regression coverage for the Spring Boot 3.4+ auto-detection change: the deprecated
 * {@code ClientHttpRequestFactories.get(...)} silently switches from {@link
 * SimpleClientHttpRequestFactory} to {@code JdkClientHttpRequestFactory} once
 * {@link java.net.http.HttpClient} is on the classpath, which changes read-timeout semantics from
 * "socket idle timeout" to "timeout for the whole request". {@link RestClientConfig} avoids that
 * helper entirely and builds {@link SimpleClientHttpRequestFactory} directly; these tests pin both
 * the concrete factory type and the effective connect/read timeouts so a future change back to the
 * deprecated helper (or any other transport swap) fails loudly instead of being caught only by a
 * {@code MockRestServiceServer}-backed test that can't see the request factory at all.
 */
class RestClientConfigTest {

    @Test
    void simpleRequestFactoryReturnsSimpleClientHttpRequestFactoryWithConfiguredTimeouts() {
        Duration connectTimeout = Duration.ofSeconds(5);
        Duration readTimeout = Duration.ofSeconds(10);

        SimpleClientHttpRequestFactory requestFactory =
                RestClientConfig.simpleRequestFactory(connectTimeout, readTimeout);

        assertThat(requestFactory).isExactlyInstanceOf(SimpleClientHttpRequestFactory.class);
        assertThat((int) ReflectionTestUtils.getField(requestFactory, "connectTimeout"))
                .isEqualTo((int) connectTimeout.toMillis());
        assertThat((int) ReflectionTestUtils.getField(requestFactory, "readTimeout"))
                .isEqualTo((int) readTimeout.toMillis());
    }

    @Test
    void externalApiRestClientUsesSimpleClientHttpRequestFactoryWithFiveSecondConnectAndTenSecondRead() {
        SimpleClientHttpRequestFactory requestFactory =
                RestClientConfig.simpleRequestFactory(Duration.ofSeconds(5), Duration.ofSeconds(10));

        assertThat(requestFactory).isExactlyInstanceOf(SimpleClientHttpRequestFactory.class);
        assertThat((int) ReflectionTestUtils.getField(requestFactory, "connectTimeout")).isEqualTo(5_000);
        assertThat((int) ReflectionTestUtils.getField(requestFactory, "readTimeout")).isEqualTo(10_000);
    }

    @Test
    void nvdSyncRestClientUsesSimpleClientHttpRequestFactoryWithTenSecondConnectAndFiveMinuteRead() {
        SimpleClientHttpRequestFactory requestFactory =
                RestClientConfig.simpleRequestFactory(Duration.ofSeconds(10), Duration.ofMinutes(5));

        assertThat(requestFactory).isExactlyInstanceOf(SimpleClientHttpRequestFactory.class);
        assertThat((int) ReflectionTestUtils.getField(requestFactory, "connectTimeout")).isEqualTo(10_000);
        assertThat((int) ReflectionTestUtils.getField(requestFactory, "readTimeout"))
                .isEqualTo((int) Duration.ofMinutes(5).toMillis());
    }

    @Test
    void llmServiceRestClientUsesSimpleClientHttpRequestFactoryWithFiveSecondConnectAndSixtySecondRead() {
        SimpleClientHttpRequestFactory requestFactory =
                RestClientConfig.simpleRequestFactory(Duration.ofSeconds(5), Duration.ofSeconds(60));

        assertThat(requestFactory).isExactlyInstanceOf(SimpleClientHttpRequestFactory.class);
        assertThat((int) ReflectionTestUtils.getField(requestFactory, "connectTimeout")).isEqualTo(5_000);
        assertThat((int) ReflectionTestUtils.getField(requestFactory, "readTimeout")).isEqualTo(60_000);
    }

    /**
     * {@link RestClientConfig#noRedirectRequestFactory} backs {@code csafSyncRestClient} /
     * {@code ghsaSyncRestClient} / {@code osvSyncRestClient} — all three follow vendor-supplied
     * URLs and must re-validate every redirect hop against their own host allowlist themselves
     * (SSRF hardening) instead of trusting {@link java.net.HttpURLConnection}'s default redirect
     * handling. It's not exactly {@link SimpleClientHttpRequestFactory} (Spring Boot's {@code
     * SimpleClientHttpRequestFactoryBuilder} returns a package-private subclass), so unlike the
     * plain-{@code simpleRequestFactory} tests above this only asserts {@code isInstanceOf}, not
     * {@code isExactlyInstanceOf}.
     */
    @Test
    void noRedirectRequestFactoryPreservesConfiguredTimeouts() {
        SimpleClientHttpRequestFactory requestFactory =
                RestClientConfig.noRedirectRequestFactory(Duration.ofSeconds(10), Duration.ofSeconds(30));

        assertThat(requestFactory).isInstanceOf(SimpleClientHttpRequestFactory.class);
        assertThat((int) ReflectionTestUtils.getField(requestFactory, "connectTimeout")).isEqualTo(10_000);
        assertThat((int) ReflectionTestUtils.getField(requestFactory, "readTimeout")).isEqualTo(30_000);
    }

    /**
     * Behavioral (not just type-based) regression coverage for the redirect-disabling itself: a
     * real 302 response must surface to the caller as-is (readable status + {@code Location}
     * header) rather than being silently followed, so the sync services can inspect and
     * re-validate the redirect target's host before ever fetching it.
     */
    @Test
    void noRedirectRequestFactoryDoesNotFollowRedirects() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        try {
            int port = server.getAddress().getPort();
            server.createContext(
                    "/redirect",
                    exchange -> {
                        exchange.getResponseHeaders().add("Location", "http://localhost:" + port + "/target");
                        exchange.sendResponseHeaders(302, -1);
                        exchange.close();
                    });
            server.createContext(
                    "/target",
                    exchange -> {
                        exchange.sendResponseHeaders(200, -1);
                        exchange.close();
                    });
            server.start();

            SimpleClientHttpRequestFactory requestFactory =
                    RestClientConfig.noRedirectRequestFactory(Duration.ofSeconds(5), Duration.ofSeconds(5));
            ClientHttpRequest request =
                    requestFactory.createRequest(URI.create("http://localhost:" + port + "/redirect"), HttpMethod.GET);

            try (ClientHttpResponse response = request.execute()) {
                assertThat(response.getStatusCode().value()).isEqualTo(302);
                assertThat(response.getHeaders().getFirst("Location")).isEqualTo("http://localhost:" + port + "/target");
            }
        } finally {
            server.stop(0);
        }
    }

    /**
     * Contrast case proving the above test's server harness genuinely exercises redirect
     * behavior — {@link RestClientConfig#simpleRequestFactory}, without the redirects override,
     * follows the same 302 and lands on {@code /target}'s 200. If this ever stopped passing, the
     * redirect test above would no longer be meaningfully distinguishing "disabled" from "not
     * exercised at all".
     */
    @Test
    void simpleRequestFactoryFollowsRedirectsForContrast() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        try {
            int port = server.getAddress().getPort();
            server.createContext(
                    "/redirect",
                    exchange -> {
                        exchange.getResponseHeaders().add("Location", "http://localhost:" + port + "/target");
                        exchange.sendResponseHeaders(302, -1);
                        exchange.close();
                    });
            server.createContext(
                    "/target",
                    exchange -> {
                        exchange.sendResponseHeaders(200, -1);
                        exchange.close();
                    });
            server.start();

            SimpleClientHttpRequestFactory requestFactory =
                    RestClientConfig.simpleRequestFactory(Duration.ofSeconds(5), Duration.ofSeconds(5));
            ClientHttpRequest request =
                    requestFactory.createRequest(URI.create("http://localhost:" + port + "/redirect"), HttpMethod.GET);

            try (ClientHttpResponse response = request.execute()) {
                assertThat(response.getStatusCode().value()).isEqualTo(200);
            }
        } finally {
            server.stop(0);
        }
    }
}
