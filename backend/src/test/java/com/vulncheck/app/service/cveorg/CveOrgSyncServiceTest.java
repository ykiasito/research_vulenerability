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

    /** Backlog item 362 follow-up (senior review, 2026-09-06, second round): the previous test
     *  above only covers a clean rejection (an {@link IllegalStateException} this class itself
     *  throws with an already-sanitized message) — it does NOT cover a genuine transport-level
     *  failure, where {@code cveOrgSyncRestClient} throws Spring's {@code ResourceAccessException}
     *  (connect timeout/reset/TLS failure), whose OWN message embeds the full, un-sanitized request
     *  URI ("I/O error on GET request for \"&lt;uri&gt;\": ..."). {@code uri} passed into {@link
     *  CveOrgSyncService#resolveRedirectTarget} here already carries a signed query string — as it
     *  would on any redirect hop past the first — so if that exception were chained as this
     *  method's cause, the secret would resurface via {@code getCause().getMessage()}, which
     *  {@code syncBaseline}/{@code syncDelta}'s {@code log.error("...", e)} would print in full.
     *  Asserts on the FULL stack-trace text (not just the top-level message), since SLF4J's
     *  cause-chain rendering is what the fix must defend against, and only checking {@code
     *  getMessage()} wouldn't catch a leak reintroduced via {@code getCause()}. */
    @Test
    void resolveRedirectTargetTransportFailureDoesNotLeakTheSignedQueryStringAnywhereInTheThrowable() {
        RestClient.Builder builder = builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        CveOrgSyncService service = service(builder.build());
        String secret = "SECRETVALUE789";
        URI uri = URI.create("https://release-assets.githubusercontent.com/hop2?sig=" + secret + "&jwt=whatever");

        server.expect(requestTo(uri.toString())).andRespond(request -> {
            throw new IOException("connection reset by peer");
        });

        Throwable thrown = org.assertj.core.api.Assertions.catchThrowable(() -> service.resolveRedirectTarget(uri));

        assertThat(thrown).isInstanceOf(IOException.class);
        assertThat(fullStackTraceText(thrown)).doesNotContain(secret);
    }

    private static String fullStackTraceText(Throwable t) {
        java.io.StringWriter writer = new java.io.StringWriter();
        t.printStackTrace(new java.io.PrintWriter(writer));
        return writer.toString();
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
     *  loops through {@link CveOrgSyncService#resolveRedirectTarget}, tolerating up to {@code
     *  MAX_REDIRECTS = 3} actual redirect hops (matching {@code GhsaSyncService.fetchBounded}'s own
     *  {@code redirectsRemaining} semantics: 3 -> 2 -> 1 -> 0) — a chain needs a genuine 4th
     *  redirect (past the tolerated 3) to fail closed with an {@link IOException}, rather than
     *  looping forever or silently giving up and connecting to an unvalidated final hop. (An
     *  earlier version of this test used only 3 redirects and still expected failure — that was
     *  itself evidence of the off-by-one bug a second peer review caught: the loop used to require
     *  its own final iteration to observe a non-redirect, tolerating only 2 hops, not 3.) */
    @Test
    void downloadFailsWhenTheRedirectChainExceedsTheMaxRedirectsBound() {
        RestClient.Builder builder = builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        CveOrgSyncService service = service(builder.build());
        URI hop0 = URI.create("https://github.com/CVEProject/cvelistV5/releases/download/x/y.zip");
        URI hop1 = URI.create("https://release-assets.githubusercontent.com/hop1");
        URI hop2 = URI.create("https://objects.githubusercontent.com/hop2");
        URI hop3 = URI.create("https://release-assets.githubusercontent.com/hop3");
        URI hop4 = URI.create("https://objects.githubusercontent.com/hop4");

        server.expect(requestTo(hop0.toString())).andRespond(withStatus(HttpStatus.FOUND).header("Location", hop1.toString()));
        server.expect(requestTo(hop1.toString())).andRespond(withStatus(HttpStatus.FOUND).header("Location", hop2.toString()));
        server.expect(requestTo(hop2.toString())).andRespond(withStatus(HttpStatus.FOUND).header("Location", hop3.toString()));
        server.expect(requestTo(hop3.toString())).andRespond(withStatus(HttpStatus.FOUND).header("Location", hop4.toString()));

        assertThatThrownBy(() -> service.download(hop0.toString()))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("too many redirects");
        server.verify();
    }

    /** Confirms the corrected loop genuinely tolerates exactly {@code MAX_REDIRECTS = 3} redirect
     *  hops before it must observe a non-redirect — i.e. the boundary the fix in {@link
     *  #downloadFailsWhenTheRedirectChainExceedsTheMaxRedirectsBound} exercises from the failing
     *  side is exercised here from the succeeding side, one hop short of failure. Stops short of
     *  the actual byte fetch ({@link CveOrgSyncService#openConnection} opens a real connection,
     *  which would require a live network call to an allowlisted host — outside this unit test's
     *  scope) — asserts on {@link CveOrgSyncService#resolveRedirectTarget} chained three times
     *  instead, which is exactly the loop body {@link CveOrgSyncService#download} repeats. */
    @Test
    void resolvingThreeChainedRedirectsSucceedsWithoutExhaustingTheBound() throws IOException {
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
        server.expect(requestTo(hop3.toString())).andRespond(withSuccess());

        URI afterHop1 = service.resolveRedirectTarget(hop0);
        URI afterHop2 = service.resolveRedirectTarget(afterHop1);
        URI afterHop3 = service.resolveRedirectTarget(afterHop2);
        URI terminal = service.resolveRedirectTarget(afterHop3);

        assertThat(afterHop1).isEqualTo(hop1);
        assertThat(afterHop2).isEqualTo(hop2);
        assertThat(afterHop3).isEqualTo(hop3);
        assertThat(terminal).isEqualTo(hop3);
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

    /** Backlog item 362 follow-up (senior review, 2026-09-06, third round): a non-2xx/non-3xx
     *  terminal response (e.g. an expired signature returning 403) must also fail closed here,
     *  with an already-sanitized message — {@code uri} is the final, signed download URL, and
     *  letting the caller's own {@link URLConnection#getInputStream()} run on a 4xx/5xx throws the
     *  JDK's own plain {@code IOException("Server returned HTTP response code: <code> for URL:
     *  <uri>")}, which embeds the FULL, un-sanitized URL (including the signed query string) —
     *  exactly the same leak class the redirect and transport-error cases were already fixed
     *  against. Asserts on the FULL stack-trace text (not just {@code getMessage()}), matching
     *  {@link #resolveRedirectTargetTransportFailureDoesNotLeakTheSignedQueryStringAnywhereInTheThrowable}'s
     *  rigor. */
    @Test
    void openConnectionFailsClosedOnANonTwoXxResponseWithoutLeakingTheSignedQueryString() throws Exception {
        CveOrgSyncService service = service(builder().build());
        String secret = "SECRETSIGNATURE999";

        withLocalServer(
                exchange -> {
                    exchange.sendResponseHeaders(403, -1);
                    exchange.close();
                },
                baseUrl -> {
                    URI signedUri = URI.create(baseUrl + "?sig=" + secret + "&jwt=alsoSecretButUnused");

                    Throwable thrown = org.assertj.core.api.Assertions.catchThrowable(() -> service.openConnection(signedUri));

                    assertThat(thrown).isInstanceOf(IOException.class);
                    assertThat(fullStackTraceText(thrown)).doesNotContain(secret);
                    return null;
                });
    }
}
