package com.vulncheck.app.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import org.junit.jupiter.api.Test;
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
}
