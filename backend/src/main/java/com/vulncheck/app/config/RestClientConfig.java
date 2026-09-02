package com.vulncheck.app.config;

import java.net.HttpURLConnection;
import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.ClientHttpRequestFactorySettings;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

@Configuration
public class RestClientConfig {

    /**
     * Builds a plain {@link SimpleClientHttpRequestFactory} (backed by {@link
     * HttpURLConnection}) with the given timeouts. Deliberately not the deprecated {@code
     * ClientHttpRequestFactories.get(...)} helper: as of Spring Boot 3.4 its auto-detection picks
     * {@code JdkClientHttpRequestFactory} ({@link java.net.http.HttpClient}) whenever it's on the
     * classpath, which changes read-timeout semantics from "socket idle timeout" to "timeout for
     * the whole request" — a silent behavior change that a BOM bump alone would otherwise
     * introduce. Explicitly constructing {@link SimpleClientHttpRequestFactory} keeps the
     * pre-3.4 transport and timeout semantics regardless of what's on the classpath.
     *
     * <p>Package-private (rather than {@code private}) so the unit test can call it directly and
     * assert on the concrete factory type and its effective timeouts.
     */
    static SimpleClientHttpRequestFactory simpleRequestFactory(Duration connectTimeout, Duration readTimeout) {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout((int) connectTimeout.toMillis());
        requestFactory.setReadTimeout((int) readTimeout.toMillis());
        return requestFactory;
    }

    /**
     * Same as {@link #simpleRequestFactory}, but with automatic HTTP redirect following disabled —
     * for clients that must inspect and re-validate each redirect hop against their own host
     * allowlist rather than following blindly (SSRF hardening; see each caller's javadoc).
     *
     * <p>Uses Spring Boot's native {@code ClientHttpRequestFactorySettings.Redirects.DONT_FOLLOW}
     * (available since Boot 3.4, {@code org.springframework.boot.http.client} package — not the
     * older {@code org.springframework.boot.web.client.ClientHttpRequestFactorySettings}, which has
     * no redirects control at all) instead of a hand-written {@link SimpleClientHttpRequestFactory}
     * subclass. Confirmed by decompiling {@code
     * SimpleClientHttpRequestFactoryBuilder$SimpleClientHttpsRequestFactory} in spring-boot
     * 3.5.16.jar: it calls {@link HttpURLConnection#setInstanceFollowRedirects}{@code (false)} when
     * {@code settings.redirects() == DONT_FOLLOW} — the exact same mechanism a hand-written subclass
     * would use, so this is not a behavior change.
     */
    static SimpleClientHttpRequestFactory noRedirectRequestFactory(Duration connectTimeout, Duration readTimeout) {
        ClientHttpRequestFactorySettings settings = ClientHttpRequestFactorySettings.defaults()
                .withConnectTimeout(connectTimeout)
                .withReadTimeout(readTimeout)
                .withRedirects(ClientHttpRequestFactorySettings.Redirects.DONT_FOLLOW);
        return ClientHttpRequestFactoryBuilder.simple().build(settings);
    }

    @Bean
    public RestClient externalApiRestClient() {
        SimpleClientHttpRequestFactory requestFactory =
                simpleRequestFactory(Duration.ofSeconds(5), Duration.ofSeconds(10));

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
        SimpleClientHttpRequestFactory requestFactory =
                simpleRequestFactory(Duration.ofSeconds(10), Duration.ofMinutes(5));

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
     * automatic HTTP redirect following (see {@link #noRedirectRequestFactory}) so the sync
     * service can inspect and re-validate each hop's host against its own allowlist itself rather
     * than silently trusting wherever {@link HttpURLConnection}'s default redirect handling would
     * otherwise follow. The descriptive User-Agent (with a contact address) follows §5-7's
     * requirement — a background sync loop is a more continuous, higher-frequency access pattern
     * than this app's existing per-item lookups, so a vendor who notices unusual traffic has a way
     * to reach the operator.
     */
    @Bean
    public RestClient csafSyncRestClient() {
        SimpleClientHttpRequestFactory requestFactory =
                noRedirectRequestFactory(Duration.ofSeconds(10), Duration.ofSeconds(30));

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
        SimpleClientHttpRequestFactory requestFactory =
                noRedirectRequestFactory(Duration.ofSeconds(10), Duration.ofSeconds(30));

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
        SimpleClientHttpRequestFactory requestFactory =
                noRedirectRequestFactory(Duration.ofSeconds(10), Duration.ofSeconds(30));

        return RestClient.builder()
                .requestFactory(requestFactory)
                .defaultHeader("User-Agent", "vulncheck-server/0.1 (osv sync)")
                .build();
    }

    /**
     * For CVE.org mirror sync ({@code CveOrgSyncService}) — used only for the one small GitHub
     * Releases API call ({@code GET .../releases/latest}) that resolves the current baseline/delta
     * asset URLs. Deliberately NOT the shared {@link #externalApiRestClient} (item 165, 2026-09-01):
     * that bean is meant to stay a request-path-only egress (10 registries, live NVD, live OSV), and
     * mixing this sync-time call into it would make it one of the things a future closed-mode branch
     * would have to carefully carve back out. Same shape as {@link #ghsaSyncRestClient}/{@link
     * #osvSyncRestClient} (no-auto-redirect, same SSRF-hardening rationale) even though this
     * particular call has no known redirect in practice, for consistency across the sync clients.
     * The baseline/delta zip bodies themselves are NOT fetched through this client — {@code
     * CveOrgSyncService#download} streams them through a plain {@link java.net.URLConnection} with
     * an unbounded read timeout, same as {@link #ghsaSyncRestClient}/{@link #osvSyncRestClient}'s
     * large-download callers.
     */
    @Bean
    public RestClient cveOrgSyncRestClient() {
        SimpleClientHttpRequestFactory requestFactory =
                noRedirectRequestFactory(Duration.ofSeconds(10), Duration.ofSeconds(30));

        return RestClient.builder()
                .requestFactory(requestFactory)
                .defaultHeader("User-Agent", "vulncheck-server/0.1 (cve.org sync)")
                .build();
    }

    /**
     * For the crates.io sparse-index mirror sync (closed-mode backlog item 176 pilot, {@code
     * CratesIoMirrorSyncService}) — deliberately NOT the shared {@link #externalApiRestClient}, same
     * item-165 rationale as the other {@code *SyncRestClient} beans above: that bean is meant to stay
     * a request-path-only egress (the 10 live registries, live NVD, live OSV) so a future full
     * closed-mode branch can delete it outright without having to first carve sync-time traffic back
     * out of it. {@code index.crates.io} is a static-file CDN (one small NDJSON response per
     * package), not an API with SSRF-shaped redirect chains like the CSAF/GHSA/OSV/CVE.org sync
     * targets above, so a plain {@link #simpleRequestFactory} (auto-follow redirects) is enough here.
     */
    @Bean
    public RestClient cratesIoSyncRestClient() {
        SimpleClientHttpRequestFactory requestFactory =
                simpleRequestFactory(Duration.ofSeconds(5), Duration.ofSeconds(15));

        return RestClient.builder()
                .requestFactory(requestFactory)
                .defaultHeader("User-Agent", "vulncheck-server/0.1 (crates.io mirror sync)")
                .build();
    }

    /**
     * For the RubyGems compact-index mirror sync (closed-mode backlog item 176 rollout, {@code
     * RubyGemsMirrorSyncService}) — deliberately NOT the shared {@link #externalApiRestClient}, same
     * item-165 rationale as {@link #cratesIoSyncRestClient} and the other {@code *SyncRestClient}
     * beans above. {@code index.rubygems.org} is served through Fastly with no redirect chain
     * observed against real gem lookups (confirmed live 2026-09-02), so a plain {@link
     * #simpleRequestFactory} (auto-follow redirects) is enough here, matching {@link
     * #cratesIoSyncRestClient}'s reasoning for its own equivalent static-index target.
     */
    @Bean
    public RestClient rubyGemsSyncRestClient() {
        SimpleClientHttpRequestFactory requestFactory =
                simpleRequestFactory(Duration.ofSeconds(5), Duration.ofSeconds(15));

        return RestClient.builder()
                .requestFactory(requestFactory)
                .defaultHeader("User-Agent", "vulncheck-server/0.1 (rubygems mirror sync)")
                .build();
    }

    /**
     * For the Packagist {@code p2/} provider-metadata mirror sync (closed-mode backlog item 176
     * rollout, {@code PackagistMirrorSyncService}) — deliberately NOT the shared {@link
     * #externalApiRestClient}, same item-165 rationale as {@link #cratesIoSyncRestClient}/{@link
     * #rubyGemsSyncRestClient} and the other {@code *SyncRestClient} beans above. {@code
     * repo.packagist.org} is served through a static-file CDN (one small JSON response per package,
     * confirmed live 2026-09-02 with no redirect chain observed), same shape as the crates.io/RubyGems
     * index targets, so a plain {@link #simpleRequestFactory} (auto-follow redirects) is enough here.
     */
    @Bean
    public RestClient packagistSyncRestClient() {
        SimpleClientHttpRequestFactory requestFactory =
                simpleRequestFactory(Duration.ofSeconds(5), Duration.ofSeconds(15));

        return RestClient.builder()
                .requestFactory(requestFactory)
                .defaultHeader("User-Agent", "vulncheck-server/0.1 (packagist mirror sync)")
                .build();
    }

    /**
     * For the Hex.pm mirror sync (closed-mode backlog item 176, Hex rollout, {@code
     * HexMirrorSyncService}) — deliberately NOT the shared {@link #externalApiRestClient}, same
     * item-165 rationale as {@link #cratesIoSyncRestClient}/{@link #rubyGemsSyncRestClient} and the
     * other {@code *SyncRestClient} beans above. {@code hex.pm} is served through Fastly with no
     * redirect chain observed against real package lookups (confirmed live 2026-09-02 against
     * jason/phoenix), so a plain {@link #simpleRequestFactory} (auto-follow redirects) is enough
     * here, matching {@link #cratesIoSyncRestClient}'s/{@link #rubyGemsSyncRestClient}'s reasoning
     * for their own equivalent static-index targets.
     */
    @Bean
    public RestClient hexSyncRestClient() {
        SimpleClientHttpRequestFactory requestFactory =
                simpleRequestFactory(Duration.ofSeconds(5), Duration.ofSeconds(15));

        return RestClient.builder()
                .requestFactory(requestFactory)
                .defaultHeader("User-Agent", "vulncheck-server/0.1 (hex mirror sync)")
                .build();
    }

    /**
     * For the npm registry mirror sync (closed-mode backlog item 176 rollout, npm, {@code
     * NpmMirrorSyncService}) — deliberately NOT the shared {@link #externalApiRestClient}, same
     * item-165 rationale as {@link #cratesIoSyncRestClient}/{@link #rubyGemsSyncRestClient}/{@link
     * #packagistSyncRestClient}/{@link #hexSyncRestClient} and the other {@code *SyncRestClient} beans
     * above. {@code registry.npmjs.org}'s per-package document endpoint ({@code GET /{package}}) is
     * served with no redirect chain observed against real package lookups (confirmed live 2026-09-02
     * against {@code lodash} and the fully-percent-encoded scoped package path {@code
     * %40types%2Fnode}), same shape as the crates.io/RubyGems/Packagist/Hex index targets, so a plain
     * {@link #simpleRequestFactory} (auto-follow redirects) is enough here.
     */
    @Bean
    public RestClient npmSyncRestClient() {
        SimpleClientHttpRequestFactory requestFactory =
                simpleRequestFactory(Duration.ofSeconds(5), Duration.ofSeconds(15));

        return RestClient.builder()
                .requestFactory(requestFactory)
                .defaultHeader("User-Agent", "vulncheck-server/0.1 (npm mirror sync)")
                .build();
    }

    /**
     * For the PyPI Simple API (PEP 691 JSON) mirror sync (closed-mode backlog item 176 rollout,
     * PyPI, {@code PyPiMirrorSyncService}) — deliberately NOT the shared {@link
     * #externalApiRestClient}, same item-165 rationale as {@link #cratesIoSyncRestClient}/{@link
     * #rubyGemsSyncRestClient}/{@link #packagistSyncRestClient}/{@link #hexSyncRestClient} and the
     * other {@code *SyncRestClient} beans above. {@code pypi.org/simple/} is served through Fastly
     * with no redirect chain observed against a package's already-PEP-503-normalized name
     * (confirmed live 2026-09-02 against requests/django-extensions — a non-normalized name like
     * {@code Django-Extensions} does 301-redirect to the normalized path, which is exactly why
     * {@link PyPiMirrorSyncService} always normalizes the name into the URL itself rather than
     * relying on this client to follow a redirect), so a plain {@link #simpleRequestFactory}
     * (auto-follow redirects, matching the other static-index sync clients) is enough here.
     */
    @Bean
    public RestClient pypiSyncRestClient() {
        SimpleClientHttpRequestFactory requestFactory =
                simpleRequestFactory(Duration.ofSeconds(5), Duration.ofSeconds(15));

        return RestClient.builder()
                .requestFactory(requestFactory)
                .defaultHeader("User-Agent", "vulncheck-server/0.1 (pypi mirror sync)")
                .build();
    }

    /**
     * For the NuGet flat-container package-base-address mirror sync (closed-mode backlog item 176
     * rollout, NuGet, {@code NuGetMirrorSyncService}) — deliberately NOT the shared {@link
     * #externalApiRestClient}, same item-165 rationale as {@link #cratesIoSyncRestClient}/{@link
     * #rubyGemsSyncRestClient}/{@link #packagistSyncRestClient}/{@link #hexSyncRestClient}/{@link
     * #npmSyncRestClient}/{@link #pypiSyncRestClient} and the other {@code *SyncRestClient} beans
     * above. {@code api.nuget.org}'s flat-container endpoint is served directly off Azure Blob
     * Storage with no redirect chain observed against real package lookups (confirmed live
     * 2026-09-02 against {@code newtonsoft.json} and a nonexistent id — the response's own {@code
     * x-ms-blob-type}/{@code X-CDN-Rewrite} headers confirm the blob-storage origin), same shape as
     * the crates.io/RubyGems/Packagist/Hex/npm/PyPI index targets, so a plain {@link
     * #simpleRequestFactory} (auto-follow redirects) is enough here.
     */
    @Bean
    public RestClient nugetSyncRestClient() {
        SimpleClientHttpRequestFactory requestFactory =
                simpleRequestFactory(Duration.ofSeconds(5), Duration.ofSeconds(15));

        return RestClient.builder()
                .requestFactory(requestFactory)
                .defaultHeader("User-Agent", "vulncheck-server/0.1 (nuget mirror sync)")
                .build();
    }

    /**
     * For the Go module proxy per-module version-list mirror sync (closed-mode backlog item 176
     * rollout, Go, {@code GoMirrorSyncService}) — deliberately NOT the shared {@link
     * #externalApiRestClient}, same item-165 rationale as {@link #cratesIoSyncRestClient}/{@link
     * #rubyGemsSyncRestClient}/{@link #packagistSyncRestClient}/{@link #hexSyncRestClient}/{@link
     * #npmSyncRestClient}/{@link #pypiSyncRestClient}/{@link #nugetSyncRestClient} and the other
     * {@code *SyncRestClient} beans above. {@code proxy.golang.org}'s {@code @v/list} endpoint
     * returns its plain-text version list with no redirect chain observed against real module
     * lookups (confirmed live 2026-09-02 against {@code github.com/gin-gonic/gin} and a nonexistent
     * module — plain 404, no body), same shape as the crates.io/RubyGems/Packagist/Hex/npm/PyPI/
     * NuGet index targets, so a plain {@link #simpleRequestFactory} (auto-follow redirects) is
     * enough here.
     */
    @Bean
    public RestClient goSyncRestClient() {
        SimpleClientHttpRequestFactory requestFactory =
                simpleRequestFactory(Duration.ofSeconds(5), Duration.ofSeconds(15));

        return RestClient.builder()
                .requestFactory(requestFactory)
                .defaultHeader("User-Agent", "vulncheck-server/0.1 (go mirror sync)")
                .build();
    }

    /**
     * Points at the Python LLM microservice (Stage1 Tier2/Tier3, Stage4). Longer read timeout
     * than the external-API client — a web_search-enabled Claude call can take well over 10s.
     */
    @Bean
    public RestClient llmServiceRestClient(@Value("${app.llm-service-url}") String llmServiceUrl) {
        SimpleClientHttpRequestFactory requestFactory =
                simpleRequestFactory(Duration.ofSeconds(5), Duration.ofSeconds(60));

        return RestClient.builder()
                .baseUrl(llmServiceUrl)
                .requestFactory(requestFactory)
                .build();
    }
}
