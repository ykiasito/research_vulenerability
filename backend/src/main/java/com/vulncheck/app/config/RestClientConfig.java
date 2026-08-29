package com.vulncheck.app.config;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.ClientHttpRequestFactories;
import org.springframework.boot.web.client.ClientHttpRequestFactorySettings;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

@Configuration
public class RestClientConfig {

    @Bean
    public RestClient externalApiRestClient() {
        ClientHttpRequestFactorySettings settings = ClientHttpRequestFactorySettings.DEFAULTS
                .withConnectTimeout(Duration.ofSeconds(5))
                .withReadTimeout(Duration.ofSeconds(10));
        ClientHttpRequestFactory requestFactory = ClientHttpRequestFactories.get(settings);

        return RestClient.builder()
                .requestFactory(requestFactory)
                .defaultHeader("User-Agent", "vulncheck-server/0.1 (product identification)")
                .build();
    }

    /**
     * For the paginating NVD CPE dictionary sync only — NOT for per-item lookups. A full-dictionary
     * page (10,000 CPEs, ~3MB) measured 29.5s to return from NVD, which the 10s read timeout on
     * {@link #externalApiRestClient} would kill outright, so a full sync could never complete on
     * that client. Deliberately a separate bean rather than relaxing the shared one: the short
     * timeout is exactly what we want for a per-item live lookup, where a hung NVD should fail fast
     * and let the item fall through instead of stalling the whole job for minutes.
     */
    @Bean
    public RestClient nvdSyncRestClient() {
        ClientHttpRequestFactorySettings settings = ClientHttpRequestFactorySettings.DEFAULTS
                .withConnectTimeout(Duration.ofSeconds(10))
                .withReadTimeout(Duration.ofMinutes(5));
        ClientHttpRequestFactory requestFactory = ClientHttpRequestFactories.get(settings);

        return RestClient.builder()
                .requestFactory(requestFactory)
                .defaultHeader("User-Agent", "vulncheck-server/0.1 (cpe dictionary sync)")
                .build();
    }

    /**
     * For CSAF vendor advisory sync ({@code SiemensCsafSyncService}, and later a Red Hat
     * equivalent). Deliberately NOT the shared {@link #externalApiRestClient} — the CSAF sync
     * flow follows vendor-supplied URLs (provider-metadata -> ROLIE feed -> per-document links)
     * that are themselves an SSRF-shaped risk (see the plan's §6), so this client disables
     * automatic HTTP redirect following ({@link NoRedirectClientHttpRequestFactory}) so the sync
     * service can inspect and re-validate each hop's host against its own allowlist itself rather
     * than silently trusting wherever {@link HttpURLConnection}'s default redirect handling would
     * otherwise follow. The descriptive User-Agent (with a contact address) follows §5-7's
     * requirement — a background sync loop is a more continuous, higher-frequency access pattern
     * than this app's existing per-item lookups, so a vendor who notices unusual traffic has a way
     * to reach the operator.
     */
    @Bean
    public RestClient csafSyncRestClient() {
        ClientHttpRequestFactorySettings settings = ClientHttpRequestFactorySettings.DEFAULTS
                .withConnectTimeout(Duration.ofSeconds(10))
                .withReadTimeout(Duration.ofSeconds(30));
        SimpleClientHttpRequestFactory requestFactory = new NoRedirectClientHttpRequestFactory();
        requestFactory.setConnectTimeout((int) settings.connectTimeout().toMillis());
        requestFactory.setReadTimeout((int) settings.readTimeout().toMillis());

        return RestClient.builder()
                .requestFactory(requestFactory)
                .defaultHeader("User-Agent", "vulncheck-server/0.1 (csaf vendor advisory sync; +mailto:security-tooling@vulncheck-server.invalid)")
                .build();
    }

    /**
     * For GHSA advisory mirror sync ({@code GhsaSyncService}) — same no-auto-redirect rationale as
     * {@link #csafSyncRestClient}: {@code GET /repos/github/advisory-database/tarball/main} (the
     * baseline archive endpoint) returns an HTTP 302 to {@code codeload.github.com} (confirmed live
     * 2026-08-27 — see {@code docs/spec/ghsa-mirror-plan.md} §2-4/§5-2), which the sync service must
     * inspect and re-validate against its own host allowlist ({@code api.github.com}/{@code
     * raw.githubusercontent.com}/{@code codeload.github.com}) rather than following blindly. Only
     * for the REST API calls and per-document {@code raw.githubusercontent.com} fetches, which are
     * all small (a JSON document or a paginated list response) — the tarball body itself is streamed
     * through a plain {@link java.net.URLConnection} with an unbounded read timeout, mirroring
     * {@code CveOrgSyncService#download}, once the redirect target is resolved and validated.
     */
    @Bean
    public RestClient ghsaSyncRestClient() {
        ClientHttpRequestFactorySettings settings = ClientHttpRequestFactorySettings.DEFAULTS
                .withConnectTimeout(Duration.ofSeconds(10))
                .withReadTimeout(Duration.ofSeconds(30));
        SimpleClientHttpRequestFactory requestFactory = new NoRedirectClientHttpRequestFactory();
        requestFactory.setConnectTimeout((int) settings.connectTimeout().toMillis());
        requestFactory.setReadTimeout((int) settings.readTimeout().toMillis());

        return RestClient.builder()
                .requestFactory(requestFactory)
                .defaultHeader("User-Agent", "vulncheck-server/0.1 (ghsa sync)")
                .build();
    }

    /**
     * For OSV.dev mirror sync ({@code OsvSyncService}) — used only for the bounded, small requests
     * (delta's per-document {@code {directory}/{id}.json} fetches, ≤5MB each). The 10 per-ecosystem
     * baseline {@code {ecosystem}/all.zip} downloads and the {@code modified_id.csv} fetch (up to
     * hundreds of MB combined) instead stream through a plain {@link java.net.URLConnection} with an
     * unbounded read timeout, mirroring {@code CveOrgSyncService#download}/{@code
     * GhsaSyncService#openStream} — the same reason {@link #ghsaSyncRestClient} isn't used for the
     * GHSA tarball body either. No-auto-redirect, same SSRF-hardening rationale as {@link
     * #ghsaSyncRestClient}.
     */
    @Bean
    public RestClient osvSyncRestClient() {
        ClientHttpRequestFactorySettings settings = ClientHttpRequestFactorySettings.DEFAULTS
                .withConnectTimeout(Duration.ofSeconds(10))
                .withReadTimeout(Duration.ofSeconds(30));
        SimpleClientHttpRequestFactory requestFactory = new NoRedirectClientHttpRequestFactory();
        requestFactory.setConnectTimeout((int) settings.connectTimeout().toMillis());
        requestFactory.setReadTimeout((int) settings.readTimeout().toMillis());

        return RestClient.builder()
                .requestFactory(requestFactory)
                .defaultHeader("User-Agent", "vulncheck-server/0.1 (osv sync)")
                .build();
    }

    /** See {@link #csafSyncRestClient}'s javadoc — the only change from the plain {@link
     *  SimpleClientHttpRequestFactory} is disabling {@link HttpURLConnection}'s automatic redirect
     *  following, so a 3xx response surfaces to the caller as a normal response (readable status +
     *  {@code Location} header) instead of being silently followed by the JDK. */
    private static final class NoRedirectClientHttpRequestFactory extends SimpleClientHttpRequestFactory {
        @Override
        protected void prepareConnection(HttpURLConnection connection, String httpMethod) throws IOException {
            super.prepareConnection(connection, httpMethod);
            connection.setInstanceFollowRedirects(false);
        }
    }

    /**
     * Points at the Python LLM microservice (Stage1 Tier2/Tier3, Stage4). Longer read timeout
     * than the external-API client — a web_search-enabled Claude call can take well over 10s.
     */
    @Bean
    public RestClient llmServiceRestClient(@Value("${app.llm-service-url}") String llmServiceUrl) {
        ClientHttpRequestFactorySettings settings = ClientHttpRequestFactorySettings.DEFAULTS
                .withConnectTimeout(Duration.ofSeconds(5))
                .withReadTimeout(Duration.ofSeconds(60));
        ClientHttpRequestFactory requestFactory = ClientHttpRequestFactories.get(settings);

        return RestClient.builder()
                .baseUrl(llmServiceUrl)
                .requestFactory(requestFactory)
                .build();
    }
}
