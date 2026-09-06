package com.vulncheck.app.service.cveorg;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.sun.net.httpserver.HttpServer;
import com.vulncheck.app.repository.CveOrgAffectedProductRepository;
import com.vulncheck.app.repository.CveOrgRecordRepository;
import com.vulncheck.app.repository.CveOrgSyncStateRepository;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLConnection;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

/**
 * Regression coverage for backlog items 359/361/362: {@link CveOrgSyncService#download} takes a
 * URL parsed from GitHub's {@code browser_download_url} (not a hardcoded constant), so it must
 * validate the scheme/host and re-validate any redirect target the same way the sibling sync
 * services ({@code OsvSyncService}, {@code GhsaSyncService}, both CSAF sync services) already do,
 * must not leave the read timeout unbounded, must fail closed on any redirect it wasn't already
 * told to expect, and must never leak the redirect target's {@code sig=}/{@code jwt=} query-string
 * credentials into a log or exception message. These tests exercise {@link
 * CveOrgSyncService#validatedUri}, {@link CveOrgSyncService#resolveRedirectTarget}, {@link
 * CveOrgSyncService#openConnection}, and {@link CveOrgSyncService#download} directly — all four
 * are package-private specifically so this test can call them without needing a live network
 * call, matching {@code RestClientConfig#simpleRequestFactory}'s established convention for this
 * kind of seam.
 */
@ExtendWith(MockitoExtension.class)
class CveOrgSyncServiceTest {

    @Mock
    private CveOrgRecordRepository cveOrgRecordRepository;
    @Mock
    private CveOrgAffectedProductRepository cveOrgAffectedProductRepository;
    @Mock
    private CveOrgSyncStateRepository cveOrgSyncStateRepository;

    private CveOrgSyncService service(RestClient restClient) {
        return new CveOrgSyncService(
                restClient, cveOrgRecordRepository, cveOrgAffectedProductRepository, cveOrgSyncStateRepository);
    }

    private RestClient.Builder builder() {
        return RestClient.builder();
    }

    // ----------------------------------------------------------------- validatedUri ------------

    @Test
    void validatedUriRejectsNonHttpsScheme() {
        CveOrgSyncService service = service(builder().build());

        URI result = service.validatedUri("http://github.com/CVEProject/cvelistV5/releases/download/x/y.zip");

        assertThat(result).isNull();
    }

    @Test
    void validatedUriRejectsDisallowedHost() {
        CveOrgSyncService service = service(builder().build());

        URI result = service.validatedUri("https://evil.example.com/CVEProject/cvelistV5/releases/download/x/y.zip");

        assertThat(result).isNull();
    }

    @Test
    void validatedUriAcceptsAllowlistedGitHubHost() {
        CveOrgSyncService service = service(builder().build());

        URI result = service.validatedUri("https://github.com/CVEProject/cvelistV5/releases/download/x/y.zip");

        assertThat(result).isNotNull();
        assertThat(result.getHost()).isEqualTo("github.com");
    }

    /** The confirmed-live (2026-09-06) redirect target — see {@code
     *  CveOrgSyncService.ALLOWED_HOSTS}'s javadoc. */
    @Test
    void validatedUriAcceptsAllowlistedPrimaryAssetCdnHost() {
        CveOrgSyncService service = service(builder().build());

        URI result = service.validatedUri(
                "https://release-assets.githubusercontent.com/github-production-release-asset/x?sig=abc&jwt=def");

        assertThat(result).isNotNull();
        assertThat(result.getHost()).isEqualTo("release-assets.githubusercontent.com");
    }

    /** Kept accepted as a historical/failover asset host even though it's not the currently
     *  observed redirect target — see {@code CveOrgSyncService.ALLOWED_HOSTS}'s javadoc. */
    @Test
    void validatedUriAcceptsAllowlistedSecondaryAssetCdnHost() {
        CveOrgSyncService service = service(builder().build());

        URI result = service.validatedUri("https://objects.githubusercontent.com/github-production-release-asset/x");

        assertThat(result).isNotNull();
        assertThat(result.getHost()).isEqualTo("objects.githubusercontent.com");
    }

    @Test
    void validatedUriRejectsUnparseableUrl() {
        CveOrgSyncService service = service(builder().build());

        URI result = service.validatedUri("not a url at all");

        assertThat(result).isNull();
    }

    // ------------------------------------------------------------ resolveRedirectTarget --------

    @Test
    void resolveRedirectTargetReturnsOriginalUriWhenNoRedirect() throws IOException {
        RestClient.Builder builder = builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        CveOrgSyncService service = service(builder.build());
        URI uri = URI.create("https://github.com/CVEProject/cvelistV5/releases/download/x/y.zip");

        server.expect(requestTo(uri.toString())).andRespond(withSuccess());

        URI resolved = service.resolveRedirectTarget(uri);

        assertThat(resolved).isEqualTo(uri);
        server.verify();
    }

    @Test
    void resolveRedirectTargetFollowsAndRevalidatesAnAllowlistedRedirect() throws IOException {
        RestClient.Builder builder = builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        CveOrgSyncService service = service(builder.build());
        URI uri = URI.create("https://github.com/CVEProject/cvelistV5/releases/download/x/y.zip");
        String redirectTarget =
                "https://release-assets.githubusercontent.com/github-production-release-asset/x?sig=abc&jwt=def";

        server.expect(requestTo(uri.toString()))
                .andRespond(withStatus(HttpStatus.FOUND).header("Location", redirectTarget));

        URI resolved = service.resolveRedirectTarget(uri);

        assertThat(resolved.toString()).isEqualTo(redirectTarget);
        server.verify();
    }

    /** Confirms the secondary/historical asset host ({@code objects.githubusercontent.com}) is
     *  still accepted as a redirect target, not just as a direct {@link
     *  CveOrgSyncService#validatedUri} input. */
    @Test
    void resolveRedirectTargetFollowsARedirectToTheSecondaryAssetCdnHost() throws IOException {
        RestClient.Builder builder = builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        CveOrgSyncService service = service(builder.build());
        URI uri = URI.create("https://github.com/CVEProject/cvelistV5/releases/download/x/y.zip");
        String redirectTarget = "https://objects.githubusercontent.com/github-production-release-asset/x";

        server.expect(requestTo(uri.toString()))
                .andRespond(withStatus(HttpStatus.FOUND).header("Location", redirectTarget));

        URI resolved = service.resolveRedirectTarget(uri);

        assertThat(resolved.toString()).isEqualTo(redirectTarget);
        server.verify();
    }

    @Test
    void resolveRedirectTargetRejectsARedirectToADisallowedHost() {
        RestClient.Builder builder = builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        CveOrgSyncService service = service(builder.build());
        URI uri = URI.create("https://github.com/CVEProject/cvelistV5/releases/download/x/y.zip");

        server.expect(requestTo(uri.toString()))
                .andRespond(withStatus(HttpStatus.FOUND).header("Location", "https://evil.example.com/steal-me"));

        assertThatThrownBy(() -> service.resolveRedirectTarget(uri))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("rejected non-allowlisted redirect target");
    }

    /** Backlog item 362 follow-up (senior review, 2026-09-06): the redirect target carries
     *  request-signing credentials in its query string ({@code sig=}/{@code jwt=}) — a rejected
     *  target must never leak that value into the exception message, even when the target is also
     *  disallowed on host grounds. */
    @Test
    void resolveRedirectTargetRejectionMessageDoesNotLeakTheSignedQueryString() {
        RestClient.Builder builder = builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        CveOrgSyncService service = service(builder.build());
        URI uri = URI.create("https://github.com/CVEProject/cvelistV5/releases/download/x/y.zip");
        String secret = "SECRETVALUE123";

        server.expect(requestTo(uri.toString()))
                .andRespond(withStatus(HttpStatus.FOUND)
                        .header("Location", "https://evil.example.com/steal-me?sig=" + secret));

        assertThatThrownBy(() -> service.resolveRedirectTarget(uri))
                .isInstanceOf(IOException.class)
                .hasMessageNotContaining(secret);
    }

    @Test
    void resolveRedirectTargetRejectsARedirectMissingTheLocationHeader() {
        RestClient.Builder builder = builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        CveOrgSyncService service = service(builder.build());
        URI uri = URI.create("https://github.com/CVEProject/cvelistV5/releases/download/x/y.zip");

        server.expect(requestTo(uri.toString())).andRespond(withStatus(HttpStatus.FOUND));

        assertThatThrownBy(() -> service.resolveRedirectTarget(uri))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("no Location header");
    }

    // ------------------------------------------------------------------------- download --------

    /** Backlog item 361 follow-up (senior review, 2026-09-06): {@link CveOrgSyncService#download}
     *  loops through {@link CveOrgSyncService#resolveRedirectTarget} (bounded by {@code
     *  MAX_REDIRECTS = 3}) rather than following a single hop — a chain that keeps redirecting past
     *  the bound must fail closed with an {@link IOException} instead of looping forever or
     *  silently giving up and connecting to an unvalidated final hop. */
    @Test
    void downloadFailsWhenTheRedirectChainExceedsTheMaxRedirectsBound() {
        RestClient.Builder builder = builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        CveOrgSyncService service = service(builder.build());
        URI hop0 = URI.create("https://github.com/CVEProject/cvelistV5/releases/download/x/y.zip");
        URI hop1 = URI.create("https://release-assets.githubusercontent.com/hop1");
        URI hop2 = URI.create("https://objects.githubusercontent.com/hop2");
        URI hop3 = URI.create("https://release-assets.githubusercontent.com/hop3");

        server.expect(requestTo(hop0.toString())).andRespond(withStatus(HttpStatus.FOUND).header("Location", hop1.toString()));
        server.expect(requestTo(hop1.toString())).andRespond(withStatus(HttpStatus.FOUND).header("Location", hop2.toString()));
        server.expect(requestTo(hop2.toString())).andRespond(withStatus(HttpStatus.FOUND).header("Location", hop3.toString()));

        assertThatThrownBy(() -> service.download(hop0.toString()))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("too many redirects");
        server.verify();
    }

    @Test
    void downloadRejectsANonAllowlistedUrlWithoutEverConnecting() {
        CveOrgSyncService service = service(builder().build());

        assertThatThrownBy(() -> service.download("https://evil.example.com/steal-me"))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Rejected non-allowlisted download URL");
    }

    // -------------------------------------------------------------------- openConnection -------

    private interface HttpServerHandler {
        void handle(com.sun.net.httpserver.HttpExchange exchange) throws IOException;
    }

    private static String withLocalServer(HttpServerHandler handler, LocalServerCallback callback) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        try {
            int port = server.getAddress().getPort();
            server.createContext("/", handler::handle);
            server.start();
            return callback.run("http://localhost:" + port + "/");
        } finally {
            server.stop(0);
        }
    }

    private interface LocalServerCallback {
        String run(String baseUrl) throws Exception;
    }

    @Test
    void openConnectionSetsAFiniteReadTimeoutInsteadOfUnbounded() throws Exception {
        CveOrgSyncService service = service(builder().build());

        withLocalServer(
                exchange -> {
                    exchange.sendResponseHeaders(200, -1);
                    exchange.close();
                },
                baseUrl -> {
                    URLConnection connection = service.openConnection(URI.create(baseUrl));
                    assertThat(connection.getReadTimeout())
                            .isGreaterThan(0)
                            .isEqualTo((int) Duration.ofSeconds(30).toMillis());
                    return null;
                });
    }

    @Test
    void openConnectionSetsATenSecondConnectTimeout() throws Exception {
        CveOrgSyncService service = service(builder().build());

        withLocalServer(
                exchange -> {
                    exchange.sendResponseHeaders(200, -1);
                    exchange.close();
                },
                baseUrl -> {
                    URLConnection connection = service.openConnection(URI.create(baseUrl));
                    assertThat(connection.getConnectTimeout()).isEqualTo((int) Duration.ofSeconds(10).toMillis());
                    return null;
                });
    }

    @Test
    void openConnectionSetsTheDescriptiveUserAgent() throws Exception {
        CveOrgSyncService service = service(builder().build());

        withLocalServer(
                exchange -> {
                    exchange.sendResponseHeaders(200, -1);
                    exchange.close();
                },
                baseUrl -> {
                    URLConnection connection = service.openConnection(URI.create(baseUrl));
                    assertThat(connection.getRequestProperty("User-Agent")).isEqualTo("vulncheck-server/0.1 (cve.org sync)");
                    return null;
                });
    }

    /** Backlog item 362 follow-up (senior review, 2026-09-06): {@link HttpURLConnection}'s own
     *  auto-redirect-following must be disabled — every hop is meant to go through {@link
     *  CveOrgSyncService#resolveRedirectTarget}'s allowlist check instead. */
    @Test
    void openConnectionDisablesAutomaticRedirectFollowing() throws Exception {
        CveOrgSyncService service = service(builder().build());

        withLocalServer(
                exchange -> {
                    exchange.sendResponseHeaders(200, -1);
                    exchange.close();
                },
                baseUrl -> {
                    URLConnection connection = service.openConnection(URI.create(baseUrl));
                    assertThat(connection).isInstanceOf(HttpURLConnection.class);
                    assertThat(((HttpURLConnection) connection).getInstanceFollowRedirects()).isFalse();
                    return null;
                });
    }

    /** Backlog item 362 follow-up (senior review, 2026-09-06): a 3xx surfacing at connection time
     *  (rather than at {@link CveOrgSyncService#resolveRedirectTarget}'s explicit resolution step)
     *  must fail closed instead of being silently followed. */
    @Test
    void openConnectionFailsClosedOnAnUnexpectedRedirectResponse() throws Exception {
        CveOrgSyncService service = service(builder().build());

        withLocalServer(
                exchange -> {
                    exchange.getResponseHeaders().add("Location", "http://localhost/elsewhere");
                    exchange.sendResponseHeaders(302, -1);
                    exchange.close();
                },
                baseUrl -> {
                    assertThatThrownBy(() -> service.openConnection(URI.create(baseUrl)))
                            .isInstanceOf(IOException.class)
                            .hasMessageContaining("unexpected redirect");
                    return null;
                });
    }
}
