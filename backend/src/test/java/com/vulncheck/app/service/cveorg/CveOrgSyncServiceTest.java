package com.vulncheck.app.service.cveorg;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.sun.net.httpserver.HttpServer;
import com.vulncheck.app.repository.CveOrgAffectedProductRepository;
import com.vulncheck.app.repository.CveOrgRecordRepository;
import com.vulncheck.app.repository.CveOrgSyncStateRepository;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestClient;

/**
 * Regression coverage for backlog items 359/361/362: {@link CveOrgSyncService#download} takes a
 * URL parsed from GitHub's {@code browser_download_url} (not a hardcoded constant), so it must
 * validate the scheme/host and re-validate any redirect target the same way the sibling sync
 * services ({@code OsvSyncService}, {@code GhsaSyncService}, both CSAF sync services) already do,
 * must not leave the read timeout unbounded, must fail closed on any redirect/response it wasn't
 * already told to expect, must open exactly one HTTP connection per hop, and must never leak the
 * redirect target's {@code sig=}/{@code jwt=} query-string credentials into a log or exception
 * message.
 *
 * <p>{@link CveOrgSyncService#download} drives its entire redirect-following loop through raw
 * {@link HttpURLConnection}s (see {@link CveOrgSyncService#openConnection}) — there is no {@code
 * RestClient}/{@code MockRestServiceServer} anywhere in that path (an earlier version used a
 * separate {@code resolveRedirectTarget} {@code RestClient} call per hop before opening a second,
 * brand-new connection to actually fetch the bytes — which meant the terminal hop's response body
 * was downloaded once and silently discarded, then downloaded again for real, a genuine
 * double-download regression this class had between the second and third senior-review rounds;
 * see {@link CveOrgSyncService#download}'s own javadoc). So these tests exercise it end-to-end
 * against a real local {@code com.sun.net.httpserver.HttpServer}, reachable only at {@code
 * http://localhost:<port>}. Since production's host allowlist only accepts real GitHub hostnames
 * over {@code https}, these tests relax {@link CveOrgSyncService}'s package-private {@code
 * urlAllowed} field via {@link ReflectionTestUtils#setField} (see that field's own javadoc for why
 * this seam exists and why it can never affect production) to accept {@code localhost} instead —
 * this still exercises the real allowlist-rejection code path (a redirect target host that isn't
 * {@code localhost} is still rejected), just against a test-controlled host set rather than the
 * real GitHub one, which {@link #validatedUriRejectsDisallowedHost}/{@link
 * #validatedUriAcceptsAllowlistedGitHubHost} already cover directly against the real production
 * predicate.
 */
@ExtendWith(MockitoExtension.class)
class CveOrgSyncServiceTest {

    @Mock
    private CveOrgRecordRepository cveOrgRecordRepository;
    @Mock
    private CveOrgAffectedProductRepository cveOrgAffectedProductRepository;
    @Mock
    private CveOrgSyncStateRepository cveOrgSyncStateRepository;

    private CveOrgSyncService service() {
        return new CveOrgSyncService(
                RestClient.builder().build(),
                cveOrgRecordRepository,
                cveOrgAffectedProductRepository,
                cveOrgSyncStateRepository);
    }

    /** Relaxes {@code urlAllowed} (see the class javadoc) to accept any scheme, host {@code
     *  localhost} only — matching production's shape (a fixed allowlist) but pointed at the
     *  {@code HttpServer} test harness instead of real GitHub hosts. */
    private CveOrgSyncService serviceWithLocalhostAllowed() {
        CveOrgSyncService service = service();
        Predicate<URI> localhostOnly = uri -> "localhost".equals(uri.getHost());
        ReflectionTestUtils.setField(service, "urlAllowed", localhostOnly);
        return service;
    }

    private static String fullStackTraceText(Throwable t) {
        StringWriter writer = new StringWriter();
        t.printStackTrace(new PrintWriter(writer));
        return writer.toString();
    }

    // ----------------------------------------------------------------- validatedUri ------------

    @Test
    void validatedUriRejectsNonHttpsScheme() {
        CveOrgSyncService service = service();

        URI result = service.validatedUri("http://github.com/CVEProject/cvelistV5/releases/download/x/y.zip");

        assertThat(result).isNull();
    }

    @Test
    void validatedUriRejectsDisallowedHost() {
        CveOrgSyncService service = service();

        URI result = service.validatedUri("https://evil.example.com/CVEProject/cvelistV5/releases/download/x/y.zip");

        assertThat(result).isNull();
    }

    @Test
    void validatedUriAcceptsAllowlistedGitHubHost() {
        CveOrgSyncService service = service();

        URI result = service.validatedUri("https://github.com/CVEProject/cvelistV5/releases/download/x/y.zip");

        assertThat(result).isNotNull();
        assertThat(result.getHost()).isEqualTo("github.com");
    }

    /** The confirmed-live (2026-09-06) redirect target — see {@code
     *  CveOrgSyncService.DEFAULT_ALLOWED_HOSTS}'s javadoc. */
    @Test
    void validatedUriAcceptsAllowlistedPrimaryAssetCdnHost() {
        CveOrgSyncService service = service();

        URI result = service.validatedUri(
                "https://release-assets.githubusercontent.com/github-production-release-asset/x?sig=abc&jwt=def");

        assertThat(result).isNotNull();
        assertThat(result.getHost()).isEqualTo("release-assets.githubusercontent.com");
    }

    /** Kept accepted as a historical/failover asset host even though it's not the currently
     *  observed redirect target — see {@code CveOrgSyncService.DEFAULT_ALLOWED_HOSTS}'s javadoc. */
    @Test
    void validatedUriAcceptsAllowlistedSecondaryAssetCdnHost() {
        CveOrgSyncService service = service();

        URI result = service.validatedUri("https://objects.githubusercontent.com/github-production-release-asset/x");

        assertThat(result).isNotNull();
        assertThat(result.getHost()).isEqualTo("objects.githubusercontent.com");
    }

    @Test
    void validatedUriRejectsUnparseableUrl() {
        CveOrgSyncService service = service();

        URI result = service.validatedUri("not a url at all");

        assertThat(result).isNull();
    }

    // -------------------------------------------------------------- local HttpServer harness ---

    private interface HttpServerHandler {
        void handle(com.sun.net.httpserver.HttpExchange exchange) throws IOException;
    }

    private interface LocalServerCallback {
        void run(int port) throws Exception;
    }

    /** A single local server with per-path handlers registered up front, so a whole redirect
     *  chain (hop0 -> hop1 -> hop2 -> ...) can be served from one {@code HttpServer} instance —
     *  each hop is just a different path on the same {@code localhost:<port>}. Handlers use
     *  relative {@code Location} values ({@code current.resolve(location)} in {@link
     *  CveOrgSyncService#download} resolves those against the request's own scheme/host/port), so
     *  the handler map itself never needs to know the port up front. */
    private static void withLocalServer(Map<String, HttpServerHandler> handlersByPath, LocalServerCallback callback)
            throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        try {
            for (Map.Entry<String, HttpServerHandler> entry : handlersByPath.entrySet()) {
                server.createContext(entry.getKey(), entry.getValue()::handle);
            }
            server.start();
            callback.run(server.getAddress().getPort());
        } finally {
            server.stop(0);
        }
    }

    private static HttpServerHandler respondWithStatus(int statusCode) {
        return exchange -> {
            exchange.sendResponseHeaders(statusCode, -1);
            exchange.close();
        };
    }

    private static HttpServerHandler redirectTo(String location) {
        return exchange -> {
            exchange.getResponseHeaders().add("Location", location);
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        };
    }

    private static HttpServerHandler respondWithBody(byte[] body) {
        return exchange -> {
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        };
    }

    /** Wraps a handler to count how many times it's actually invoked — the assertion that would
     *  have caught the double-download regression (see the class javadoc). */
    private static HttpServerHandler countingWrapperOf(AtomicInteger counter, HttpServerHandler delegate) {
        return exchange -> {
            counter.incrementAndGet();
            delegate.handle(exchange);
        };
    }

    // ------------------------------------------------------------------------- download --------

    @Test
    void downloadRejectsANonAllowlistedUrlWithoutEverConnecting() {
        CveOrgSyncService service = service();

        assertThatThrownBy(() -> service.download("https://evil.example.com/steal-me"))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Rejected non-allowlisted download URL");
    }

    @Test
    void downloadReturnsTheBodyWhenTheInitialUrlIsNotARedirect() throws Exception {
        CveOrgSyncService service = serviceWithLocalhostAllowed();
        byte[] body = "the actual asset bytes".getBytes(StandardCharsets.UTF_8);

        withLocalServer(Map.of("/asset", respondWithBody(body)), port -> {
            try (InputStream stream = service.download("http://localhost:" + port + "/asset")) {
                assertThat(stream.readAllBytes()).isEqualTo(body);
            }
        });
    }

    @Test
    void downloadFollowsAndRevalidatesAnAllowlistedRedirect() throws Exception {
        CveOrgSyncService service = serviceWithLocalhostAllowed();
        byte[] body = "redirected asset bytes".getBytes(StandardCharsets.UTF_8);

        withLocalServer(
                Map.of(
                        "/hop0", redirectTo("/asset"),
                        "/asset", respondWithBody(body)),
                port -> {
                    try (InputStream stream = service.download("http://localhost:" + port + "/hop0")) {
                        assertThat(stream.readAllBytes()).isEqualTo(body);
                    }
                });
    }

    /** Backlog items 359/361 follow-up (senior review, 2026-09-06, fourth round): a redirect
     *  {@code Location} pointing at a host {@link CveOrgSyncService#urlAllowed} rejects must fail
     *  closed without leaking that target's signed query string into the exception message or full
     *  stack trace — the target is deliberately a fully-qualified, non-localhost URL (not resolved
     *  relative to the test server), so it exercises the real "disallowed host" branch rather than
     *  "disallowed because it's not even localhost" being conflated with something else. */
    @Test
    void downloadRejectsARedirectToADisallowedHostWithoutLeakingASignedQueryString() throws Exception {
        CveOrgSyncService service = serviceWithLocalhostAllowed();
        String secret = "SECRETVALUE123";

        withLocalServer(
                Map.of("/hop0", redirectTo("https://evil.example.com/steal-me?sig=" + secret)),
                port -> {
                    Throwable thrown = catchThrowable(() -> service.download("http://localhost:" + port + "/hop0"));

                    assertThat(thrown).isInstanceOf(IOException.class);
                    assertThat(thrown.getMessage()).contains("rejected non-allowlisted redirect target");
                    assertThat(fullStackTraceText(thrown)).doesNotContain(secret);
                });
    }

    @Test
    void downloadRejectsARedirectMissingTheLocationHeader() throws Exception {
        CveOrgSyncService service = serviceWithLocalhostAllowed();

        withLocalServer(Map.of("/hop0", respondWithStatus(302)), port -> {
            assertThatThrownBy(() -> service.download("http://localhost:" + port + "/hop0"))
                    .isInstanceOf(IOException.class)
                    .hasMessageContaining("no Location header");
        });
    }

    /** Backlog item 362 follow-up (senior review, 2026-09-06, third + fourth rounds): a
     *  non-2xx/non-3xx terminal response (e.g. an expired signature returning 403) must fail closed
     *  without leaking the URL's signed query string — letting the caller's own {@link
     *  URLConnection#getInputStream()} run on a 4xx/5xx would otherwise throw the JDK's own plain
     *  {@code IOException("Server returned HTTP response code: <code> for URL: <uri>")}, which
     *  embeds the FULL, un-sanitized URL. */
    @Test
    void downloadFailsClosedOnANonTwoXxTerminalResponseWithoutLeakingTheSignedQueryString() throws Exception {
        CveOrgSyncService service = serviceWithLocalhostAllowed();
        String secret = "SECRETSIGNATURE999";

        withLocalServer(Map.of("/asset", respondWithStatus(403)), port -> {
            Throwable thrown = catchThrowable(
                    () -> service.download("http://localhost:" + port + "/asset?sig=" + secret + "&jwt=alsoSecretButUnused"));

            assertThat(thrown).isInstanceOf(IOException.class);
            assertThat(fullStackTraceText(thrown)).doesNotContain(secret);
        });
    }

    /** Backlog item 361 follow-up (senior review, 2026-09-06, second round): {@link
     *  CveOrgSyncService#download} tolerates up to {@code MAX_REDIRECTS = 3} actual redirect hops
     *  (matching {@code GhsaSyncService.fetchBounded}'s own {@code redirectsRemaining} semantics: 3
     *  -> 2 -> 1 -> 0) — a chain needs a genuine 4th redirect (past the tolerated 3) to fail closed
     *  with an {@link IOException}. The would-be 5th hop ({@code /hop4}) must never actually be
     *  requested — the bound is enforced right after the 4th redirect response is read, not by
     *  attempting and then rejecting a 5th connection. */
    @Test
    void downloadFailsWhenTheRedirectChainExceedsTheMaxRedirectsBound() throws Exception {
        CveOrgSyncService service = serviceWithLocalhostAllowed();
        AtomicInteger hop4Requests = new AtomicInteger();

        withLocalServer(
                Map.of(
                        "/hop0", redirectTo("/hop1"),
                        "/hop1", redirectTo("/hop2"),
                        "/hop2", redirectTo("/hop3"),
                        "/hop3", redirectTo("/hop4"),
                        "/hop4", countingWrapperOf(hop4Requests, respondWithBody("unreachable".getBytes(StandardCharsets.UTF_8)))),
                port -> {
                    assertThatThrownBy(() -> service.download("http://localhost:" + port + "/hop0"))
                            .isInstanceOf(IOException.class)
                            .hasMessageContaining("too many redirects");
                    assertThat(hop4Requests.get()).isZero();
                });
    }

    /** Confirms the loop genuinely tolerates exactly {@code MAX_REDIRECTS = 3} redirect hops
     *  before it must observe a non-redirect — the boundary {@link
     *  #downloadFailsWhenTheRedirectChainExceedsTheMaxRedirectsBound} exercises from the failing
     *  side is exercised here from the succeeding side, one hop short of failure. */
    @Test
    void downloadSucceedsAfterExactlyMaxRedirectsHops() throws Exception {
        CveOrgSyncService service = serviceWithLocalhostAllowed();
        byte[] body = "asset after three redirects".getBytes(StandardCharsets.UTF_8);

        withLocalServer(
                Map.of(
                        "/hop0", redirectTo("/hop1"),
                        "/hop1", redirectTo("/hop2"),
                        "/hop2", redirectTo("/hop3"),
                        "/hop3", respondWithBody(body)),
                port -> {
                    try (InputStream stream = service.download("http://localhost:" + port + "/hop0")) {
                        assertThat(stream.readAllBytes()).isEqualTo(body);
                    }
                });
    }

    /** THE regression test for the double-download bug (senior review, 2026-09-06, fourth round):
     *  an earlier version of {@link CveOrgSyncService#download} resolved the redirect through a
     *  separate {@code RestClient} call (which drained the terminal hop's ENTIRE response body to
     *  EOF, discarding it) and only then opened a second, brand-new connection to actually fetch
     *  the bytes — so the terminal path was requested twice per {@code download()} call. Asserts
     *  the terminal path's request count is exactly 1 across a full {@code download()} call
     *  spanning a redirect. */
    @Test
    void downloadRequestsTheTerminalPathExactlyOnceAcrossARedirectChain() throws Exception {
        CveOrgSyncService service = serviceWithLocalhostAllowed();
        byte[] body = "must be fetched exactly once".getBytes(StandardCharsets.UTF_8);
        AtomicInteger terminalRequests = new AtomicInteger();

        withLocalServer(
                Map.of(
                        "/hop0", redirectTo("/terminal"),
                        "/terminal", countingWrapperOf(terminalRequests, respondWithBody(body))),
                port -> {
                    try (InputStream stream = service.download("http://localhost:" + port + "/hop0")) {
                        assertThat(stream.readAllBytes()).isEqualTo(body);
                    }
                    assertThat(terminalRequests.get()).isEqualTo(1);
                });
    }

    // ---------------------------------------------------------------------- responseCodeOf -----

    /** Backlog item 362 follow-up (senior review, 2026-09-06, second + fourth rounds): {@link
     *  CveOrgSyncService#responseCodeOf} must not chain a transport-level failure's own exception
     *  as cause, nor embed its message — Spring's {@code ResourceAccessException} (the shape this
     *  guards against, from the now-deleted {@code RestClient}-based redirect resolution) embeds
     *  the full, un-sanitized request URI in its own message, and {@code uri} here may already
     *  carry a previously-resolved {@code sig=}/{@code jwt=} credential. Forces a deterministic
     *  transport failure via a fake {@link HttpURLConnection} (a real {@code HttpServer}-level
     *  socket failure isn't practical to force reliably) whose {@code getResponseCode()} throws an
     *  {@link IOException} that itself embeds a secret-bearing URL — asserting the FULL stack-trace
     *  text (not just {@code getMessage()}) never contains that secret, since SLF4J's cause-chain
     *  rendering is exactly what the fix must defend against. */
    @Test
    void responseCodeOfDoesNotLeakTheSignedQueryStringFromATransportFailure() throws Exception {
        CveOrgSyncService service = service();
        String secret = "SECRETVALUE789";
        URI uri = URI.create("https://release-assets.githubusercontent.com/hop2?sig=" + secret + "&jwt=whatever");
        HttpURLConnection fakeConnection = new HttpURLConnection(uri.toURL()) {
            @Override
            public void connect() {
            }

            @Override
            public void disconnect() {
            }

            @Override
            public boolean usingProxy() {
                return false;
            }

            @Override
            public int getResponseCode() throws IOException {
                throw new IOException("I/O error on GET request for \"" + getURL() + "\": connection reset by peer");
            }
        };

        Throwable thrown = catchThrowable(() -> service.responseCodeOf(fakeConnection, uri));

        assertThat(thrown).isInstanceOf(IOException.class);
        assertThat(fullStackTraceText(thrown)).doesNotContain(secret);
    }

    // -------------------------------------------------------------------- openConnection -------

    private static void withPlainLocalServer(HttpServerHandler handler, LocalServerCallback callback) throws Exception {
        withLocalServer(Map.of("/", handler), callback);
    }

    @Test
    void openConnectionSetsAFiniteReadTimeoutInsteadOfUnbounded() throws Exception {
        CveOrgSyncService service = service();

        withPlainLocalServer(respondWithStatus(200), port -> {
            URLConnection connection = service.openConnection(URI.create("http://localhost:" + port + "/"));
            assertThat(connection.getReadTimeout())
                    .isGreaterThan(0)
                    .isEqualTo((int) Duration.ofSeconds(30).toMillis());
        });
    }

    @Test
    void openConnectionSetsATenSecondConnectTimeout() throws Exception {
        CveOrgSyncService service = service();

        withPlainLocalServer(respondWithStatus(200), port -> {
            URLConnection connection = service.openConnection(URI.create("http://localhost:" + port + "/"));
            assertThat(connection.getConnectTimeout()).isEqualTo((int) Duration.ofSeconds(10).toMillis());
        });
    }

    @Test
    void openConnectionSetsTheDescriptiveUserAgent() throws Exception {
        CveOrgSyncService service = service();

        withPlainLocalServer(respondWithStatus(200), port -> {
            URLConnection connection = service.openConnection(URI.create("http://localhost:" + port + "/"));
            assertThat(connection.getRequestProperty("User-Agent")).isEqualTo("vulncheck-server/0.1 (cve.org sync)");
        });
    }

    /** {@link HttpURLConnection}'s own auto-redirect-following must be disabled — {@link
     *  CveOrgSyncService#download}'s loop is what decides whether to follow a redirect (after
     *  re-validating its target), not the connection itself. */
    @Test
    void openConnectionDisablesAutomaticRedirectFollowing() throws Exception {
        CveOrgSyncService service = service();

        withPlainLocalServer(respondWithStatus(200), port -> {
            HttpURLConnection connection = service.openConnection(URI.create("http://localhost:" + port + "/"));
            assertThat(connection.getInstanceFollowRedirects()).isFalse();
        });
    }
}
