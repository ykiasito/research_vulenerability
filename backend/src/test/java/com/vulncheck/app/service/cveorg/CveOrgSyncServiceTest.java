package com.vulncheck.app.service.cveorg;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.sun.net.httpserver.HttpServer;
import com.vulncheck.app.entity.CveOrgSyncState;
import com.vulncheck.app.repository.CveOrgAffectedProductRepository;
import com.vulncheck.app.repository.CveOrgRecordRepository;
import com.vulncheck.app.repository.CveOrgSyncStateRepository;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

/**
 * Backlog item 416 (SSRF hardening): {@link CveOrgSyncService#download} used to hand a
 * GitHub-supplied URL straight to {@link URLConnection#openConnection()} with no host allowlist and
 * automatic redirect-following left on. These tests exercise the resulting host allowlist ({@link
 * CveOrgSyncService#validatedUri}), the manual bounded redirect loop ({@link
 * CveOrgSyncService#download}), the connection setup ({@link CveOrgSyncService#openConnection}),
 * and the pre-existing {@code cve_org_sync_state} bookkeeping (backlog item 379) end-to-end.
 *
 * <p>Since production's allowlist only accepts real GitHub hostnames over {@code https}, and {@link
 * CveOrgSyncService#download} drives its redirect loop through raw {@link HttpURLConnection}s (no
 * {@code RestClient}/{@code MockRestServiceServer} involved), the redirect-loop tests below run
 * against a real local {@code com.sun.net.httpserver.HttpServer} (reachable only at {@code
 * http://localhost:<port>}) and relax {@link CveOrgSyncService}'s package-private {@code urlAllowed}
 * field via {@link ReflectionTestUtils#setField} to accept {@code localhost} — this never affects
 * production, where that field is a {@code final} instance initializer never touched by the
 * constructor. The allowlist itself is exercised directly (against the real, unrelaxed predicate) by
 * {@link #validatedUriRejectsDisallowedHost}/{@link #validatedUriAcceptsAllowlistedGitHubHost}/etc.
 */
@ExtendWith(MockitoExtension.class)
class CveOrgSyncServiceTest {

    private static final String LATEST_RELEASE_API = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest";

    @Mock
    private CveOrgRecordRepository cveOrgRecordRepository;
    @Mock
    private CveOrgAffectedProductRepository cveOrgAffectedProductRepository;
    @Mock
    private CveOrgSyncStateRepository cveOrgSyncStateRepository;

    private CveOrgSyncService service(RestClient restClient) {
        return new CveOrgSyncService(restClient, cveOrgRecordRepository, cveOrgAffectedProductRepository,
                cveOrgSyncStateRepository);
    }

    private CveOrgSyncService service() {
        return service(RestClient.builder().build());
    }

    /** Relaxes {@code urlAllowed} (see the class javadoc) to accept any scheme, host {@code
     *  localhost} only — same shape as production (a fixed host check), just pointed at the test
     *  harness instead of real GitHub hosts. */
    private CveOrgSyncService serviceWithLocalhostAllowed(RestClient restClient) {
        CveOrgSyncService service = service(restClient);
        Predicate<URI> localhostOnly = uri -> "localhost".equals(uri.getHost());
        ReflectionTestUtils.setField(service, "urlAllowed", localhostOnly);
        return service;
    }

    private CveOrgSyncService serviceWithLocalhostAllowed() {
        return serviceWithLocalhostAllowed(RestClient.builder().build());
    }

    private static String fullStackTraceText(Throwable t) {
        StringWriter writer = new StringWriter();
        t.printStackTrace(new PrintWriter(writer));
        return writer.toString();
    }

    // ------------------------------------------------------------------ validatedUri -------------

    @Test
    void validatedUriRejectsNonHttpsScheme() {
        URI result = service().validatedUri("http://github.com/CVEProject/cvelistV5/releases/download/x/y.zip");

        assertThat(result).isNull();
    }

    @Test
    void validatedUriRejectsDisallowedHost() {
        URI result = service().validatedUri("https://evil.example.com/CVEProject/cvelistV5/releases/download/x/y.zip");

        assertThat(result).isNull();
    }

    @Test
    void validatedUriAcceptsAllowlistedGitHubHost() {
        URI result = service().validatedUri("https://github.com/CVEProject/cvelistV5/releases/download/x/y.zip");

        assertThat(result).isNotNull();
        assertThat(result.getHost()).isEqualTo("github.com");
    }

    @Test
    void validatedUriAcceptsAllowlistedReleaseAssetCdnHost() {
        URI result = service().validatedUri(
                "https://release-assets.githubusercontent.com/github-production-release-asset/x?sig=abc&jwt=def");

        assertThat(result).isNotNull();
        assertThat(result.getHost()).isEqualTo("release-assets.githubusercontent.com");
    }

    @Test
    void validatedUriAcceptsAllowlistedObjectsCdnHost() {
        URI result = service().validatedUri("https://objects.githubusercontent.com/github-production-release-asset/x");

        assertThat(result).isNotNull();
        assertThat(result.getHost()).isEqualTo("objects.githubusercontent.com");
    }

    @Test
    void validatedUriRejectsUnparseableUrl() {
        URI result = service().validatedUri("not a url at all");

        assertThat(result).isNull();
    }

    // ------------------------------------------------------------- local HttpServer harness -------

    private interface HttpServerHandler {
        void handle(com.sun.net.httpserver.HttpExchange exchange) throws IOException;
    }

    private interface LocalServerCallback {
        void run(int port) throws Exception;
    }

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

    private static HttpServerHandler countingWrapperOf(AtomicInteger counter, HttpServerHandler delegate) {
        return exchange -> {
            counter.incrementAndGet();
            delegate.handle(exchange);
        };
    }

    // ----------------------------------------------------------------------- download --------------

    @Test
    void downloadRejectsANonAllowlistedUrlWithoutEverConnecting() {
        assertThatThrownBy(() -> service().download("https://evil.example.com/steal-me"))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("rejected non-allowlisted download URL");
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
                Map.of("/hop0", redirectTo("/asset"), "/asset", respondWithBody(body)),
                port -> {
                    try (InputStream stream = service.download("http://localhost:" + port + "/hop0")) {
                        assertThat(stream.readAllBytes()).isEqualTo(body);
                    }
                });
    }

    /** A redirect target on a disallowed host must fail closed and must never leak its signed query
     *  string into the exception message or stack trace. */
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

    /** Senior review REVISE (item 416, 2026-09-07): {@code URI#resolve(String)} calls {@code
     *  URI.create} internally, so a redirect {@code Location} header that isn't a parseable URI
     *  reference (here, a raw unescaped space) used to throw an uncaught, unchecked {@link
     *  IllegalArgumentException} straight out of {@link CveOrgSyncService#download} — bypassing
     *  {@code syncBaseline}/{@code syncDelta}'s {@code catch (IOException e)} entirely (so item 379's
     *  {@code recordSyncFailure} never ran) and embedding the raw, unsanitized {@code Location}
     *  string (including any signed query string it carries) in the exception's own message. Must
     *  now surface as an {@code IOException} without leaking the malformed Location's secret. */
    @Test
    void downloadRejectsAMalformedRedirectLocationWithoutLeakingASignedQueryString() throws Exception {
        CveOrgSyncService service = serviceWithLocalhostAllowed();
        String secret = "SECRETVALUE456";

        withLocalServer(
                Map.of("/hop0", redirectTo("/bad path?sig=" + secret)),
                port -> {
                    Throwable thrown = catchThrowable(() -> service.download("http://localhost:" + port + "/hop0"));

                    assertThat(thrown).isInstanceOf(IOException.class);
                    assertThat(fullStackTraceText(thrown)).doesNotContain(secret);
                });
    }

    @Test
    void downloadRejectsARedirectMissingTheLocationHeader() throws Exception {
        CveOrgSyncService service = serviceWithLocalhostAllowed();

        withLocalServer(Map.of("/hop0", respondWithStatus(302)), port ->
                assertThatThrownBy(() -> service.download("http://localhost:" + port + "/hop0"))
                        .isInstanceOf(IOException.class)
                        .hasMessageContaining("no Location header"));
    }

    /** A non-2xx/non-3xx terminal response (e.g. an expired signature returning 403) must fail closed
     *  without leaking the URL's signed query string — the JDK's own {@link
     *  HttpURLConnection#getInputStream()} would otherwise throw a plain {@code IOException} that
     *  embeds the full, un-sanitized request URL, which {@link CveOrgSyncService#download}
     *  deliberately never calls on a non-2xx response. */
    @Test
    void downloadFailsClosedOnANonTwoXxTerminalResponseWithoutLeakingTheSignedQueryString() throws Exception {
        CveOrgSyncService service = serviceWithLocalhostAllowed();
        String secret = "SECRETSIGNATURE999";

        withLocalServer(Map.of("/asset", respondWithStatus(403)), port -> {
            Throwable thrown = catchThrowable(
                    () -> service.download("http://localhost:" + port + "/asset?sig=" + secret + "&jwt=unused"));

            assertThat(thrown).isInstanceOf(IOException.class);
            assertThat(fullStackTraceText(thrown)).doesNotContain(secret);
        });
    }

    /** {@link CveOrgSyncService#download} tolerates up to {@code MAX_REDIRECTS = 3} actual redirect
     *  hops; a genuine 4th redirect must fail closed, and the would-be 5th hop must never be
     *  requested at all. */
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

    /** The terminal path must be requested exactly once across a redirect chain — a regression here
     *  (e.g. resolving the redirect through one connection and then opening a second, brand-new one
     *  to fetch the actual bytes) would silently double the egress/time cost of every multi-GB
     *  baseline download. */
    @Test
    void downloadRequestsTheTerminalPathExactlyOnceAcrossARedirectChain() throws Exception {
        CveOrgSyncService service = serviceWithLocalhostAllowed();
        byte[] body = "must be fetched exactly once".getBytes(StandardCharsets.UTF_8);
        AtomicInteger terminalRequests = new AtomicInteger();

        withLocalServer(
                Map.of("/hop0", redirectTo("/terminal"), "/terminal", countingWrapperOf(terminalRequests, respondWithBody(body))),
                port -> {
                    try (InputStream stream = service.download("http://localhost:" + port + "/hop0")) {
                        assertThat(stream.readAllBytes()).isEqualTo(body);
                    }
                    assertThat(terminalRequests.get()).isEqualTo(1);
                });
    }

    // ------------------------------------------------------------------- responseCodeOf ------------

    /** {@link CveOrgSyncService#responseCodeOf} must not leak a signed query string carried by {@code
     *  uri} through a transport-level failure's own message. Forces a deterministic transport failure
     *  via a fake {@link HttpURLConnection} whose {@code getResponseCode()} throws an {@link
     *  IOException} that itself embeds a secret-bearing URL, and asserts the full stack-trace text
     *  (not just {@code getMessage()}) never contains that secret. */
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

    // ---------------------------------------------------------------------- openConnection ----------

    private static void withPlainLocalServer(HttpServerHandler handler, LocalServerCallback callback) throws Exception {
        withLocalServer(Map.of("/", handler), callback);
    }

    @Test
    void openConnectionSetsAFiniteReadTimeoutInsteadOfUnbounded() throws Exception {
        CveOrgSyncService service = service();

        withPlainLocalServer(respondWithStatus(200), port -> {
            URLConnection connection = service.openConnection(URI.create("http://localhost:" + port + "/"));
            assertThat(connection.getReadTimeout()).isEqualTo(30_000);
        });
    }

    @Test
    void openConnectionSetsATenSecondConnectTimeout() throws Exception {
        CveOrgSyncService service = service();

        withPlainLocalServer(respondWithStatus(200), port -> {
            URLConnection connection = service.openConnection(URI.create("http://localhost:" + port + "/"));
            assertThat(connection.getConnectTimeout()).isEqualTo(10_000);
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

    /** {@link HttpURLConnection}'s own automatic redirect-following must be disabled — {@link
     *  CveOrgSyncService#download}'s loop is what decides whether to follow a redirect, not the
     *  connection itself. */
    @Test
    void openConnectionDisablesAutomaticRedirectFollowing() throws Exception {
        CveOrgSyncService service = service();

        withPlainLocalServer(respondWithStatus(200), port -> {
            HttpURLConnection connection = service.openConnection(URI.create("http://localhost:" + port + "/"));
            assertThat(connection.getInstanceFollowRedirects()).isFalse();
        });
    }

    // ---------------------------------------------------------------- sync failure bookkeeping ------

    /** Before backlog item 379's fix, a release response with no matching delta asset just logged a
     *  warning and returned — {@code cve_org_sync_state} stayed completely untouched, forever, on a
     *  run shaped like this. */
    @Test
    void syncDeltaRecordsAFailureWhenTheLatestReleaseHasNoDeltaAsset() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(method(HttpMethod.GET))
                .andExpect(requestTo(LATEST_RELEASE_API))
                .andRespond(withSuccess("{\"tag_name\":\"cve_2026-09-07_0000Z\",\"assets\":[]}", MediaType.APPLICATION_JSON));
        CveOrgSyncService service = service(builder.build());

        int upserted = service.syncDelta();

        assertThat(upserted).isZero();
        ArgumentCaptor<CveOrgSyncState> captor = ArgumentCaptor.forClass(CveOrgSyncState.class);
        verify(cveOrgSyncStateRepository).save(captor.capture());
        assertThat(captor.getValue().getLastSyncError()).contains("delta asset");
        assertThat(captor.getValue().getLastSyncedAt()).isNotNull();
    }

    /** A genuine download failure (here, a 403 on the resolved baseline asset URL) must also reach
     *  {@code cve_org_sync_state}, not just the log — the recorded message must not be the raw
     *  exception message (which could echo request details). */
    @Test
    void syncBaselineRecordsAFailureWhenTheDownloadFails() throws Exception {
        withLocalServer(Map.of("/asset", respondWithStatus(403)), port -> {
            RestClient.Builder builder = RestClient.builder();
            MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
            String releaseJson = "{\"tag_name\":\"cve_2026-09-07_0000Z\",\"assets\":[{"
                    + "\"name\":\"2026-09-07T00_00_00Z_all_CVEs_at_midnight.zip.zip\","
                    + "\"browser_download_url\":\"http://localhost:" + port + "/asset\"}]}";
            server.expect(method(HttpMethod.GET))
                    .andExpect(requestTo(LATEST_RELEASE_API))
                    .andRespond(withSuccess(releaseJson, MediaType.APPLICATION_JSON));

            CveOrgSyncService service = serviceWithLocalhostAllowed(builder.build());

            int upserted = service.syncBaseline();

            assertThat(upserted).isZero();
            ArgumentCaptor<CveOrgSyncState> captor = ArgumentCaptor.forClass(CveOrgSyncState.class);
            verify(cveOrgSyncStateRepository).save(captor.capture());
            assertThat(captor.getValue().getLastSyncError()).contains("baseline sync failed");
            assertThat(captor.getValue().getLastSyncedAt()).isNotNull();
        });
    }

    /** A successful sync must clear a previously-recorded error, not just leave it stale. Uses a
     *  valid but empty outer zip (no {@code CVE-*.json} entries) as the baseline asset — this test
     *  only cares about {@code cve_org_sync_state}'s bookkeeping on the success path, not record
     *  upserts. */
    @Test
    void syncBaselineClearsAPreviouslyRecordedErrorOnSuccess() throws Exception {
        CveOrgSyncState existing = new CveOrgSyncState();
        existing.setLastSyncError("previous run failed");
        when(cveOrgSyncStateRepository.findById((short) 1)).thenReturn(Optional.of(existing));

        ByteArrayOutputStream zipBytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(zipBytes)) {
            // Deliberately empty -- an outer zip with zero entries is still a valid zip, and the
            // success path (markSynced) doesn't require any CVE record to have been upserted.
        }
        byte[] emptyZip = zipBytes.toByteArray();

        withLocalServer(Map.of("/asset", respondWithBody(emptyZip)), port -> {
            RestClient.Builder builder = RestClient.builder();
            MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
            String releaseJson = "{\"tag_name\":\"cve_2026-09-07_0000Z\",\"assets\":[{"
                    + "\"name\":\"2026-09-07T00_00_00Z_all_CVEs_at_midnight.zip.zip\","
                    + "\"browser_download_url\":\"http://localhost:" + port + "/asset\"}]}";
            server.expect(method(HttpMethod.GET))
                    .andExpect(requestTo(LATEST_RELEASE_API))
                    .andRespond(withSuccess(releaseJson, MediaType.APPLICATION_JSON));

            CveOrgSyncService service = serviceWithLocalhostAllowed(builder.build());

            int upserted = service.syncBaseline();

            assertThat(upserted).isZero();
            ArgumentCaptor<CveOrgSyncState> captor = ArgumentCaptor.forClass(CveOrgSyncState.class);
            verify(cveOrgSyncStateRepository).save(captor.capture());
            assertThat(captor.getValue().getLastSyncError()).isNull();
            assertThat(captor.getValue().isBaselineLoaded()).isTrue();
            assertThat(captor.getValue().getLastReleaseTag()).isEqualTo("cve_2026-09-07_0000Z");
        });
    }

    /** Senior review REVISE (item 416, 2026-09-07, second round): the "sync starting" log lines
     *  (109/160) were sanitized in the first REVISE round, but the matching "sync complete" log
     *  lines (147/182) were missed — same {@code release.tag()} value, same threat model (this
     *  class's own javadoc already treats a compromised/spoofed release response as untrusted), just
     *  the exit side of the same method left unsanitized while the entry side was fixed. Captures the
     *  actual formatted log line {@link CveOrgSyncService} emits (not just the sanitizer's output in
     *  isolation) to prove the CR/LF a malicious {@code tag_name} carries never reaches it, while
     *  {@code cve_org_sync_state.last_release_tag} (a DB column, not a log line) still stores the
     *  value verbatim — sanitization here is a log-injection defense, not a data-integrity one. */
    @Test
    void syncBaselineCompleteLogSanitizesAReleaseTagContainingCrlf() throws Exception {
        String maliciousTag = "cve_2026-09-07_0000Z\r\nFAKE LOG LINE";

        ByteArrayOutputStream zipBytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(zipBytes)) {
            // Deliberately empty, same as syncBaselineClearsAPreviouslyRecordedErrorOnSuccess -- this
            // test only cares about the completion log line, not record upserts.
        }
        byte[] emptyZip = zipBytes.toByteArray();

        withLocalServer(Map.of("/asset", respondWithBody(emptyZip)), port -> {
            RestClient.Builder builder = RestClient.builder();
            MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
            // \\r\\n (a literal backslash-r-backslash-n in the JSON text) is the valid-JSON escape
            // sequence for an actual CR/LF -- Jackson parses this into a tag_name String genuinely
            // containing \r\n, exactly like a compromised/spoofed release response could send.
            String releaseJson = "{\"tag_name\":\"cve_2026-09-07_0000Z\\r\\nFAKE LOG LINE\",\"assets\":[{"
                    + "\"name\":\"2026-09-07T00_00_00Z_all_CVEs_at_midnight.zip.zip\","
                    + "\"browser_download_url\":\"http://localhost:" + port + "/asset\"}]}";
            server.expect(method(HttpMethod.GET))
                    .andExpect(requestTo(LATEST_RELEASE_API))
                    .andRespond(withSuccess(releaseJson, MediaType.APPLICATION_JSON));

            CveOrgSyncService service = serviceWithLocalhostAllowed(builder.build());

            List<ILoggingEvent> events = captureLogEvents(service::syncBaseline);

            List<ILoggingEvent> completionEvents = events.stream()
                    .filter(event -> event.getFormattedMessage().contains("sync complete"))
                    .toList();
            assertThat(completionEvents).hasSize(1);
            assertThat(completionEvents.get(0).getFormattedMessage()).doesNotContain("\r").doesNotContain("\n");

            // The DB column stores the tag verbatim -- only the log line is sanitized.
            ArgumentCaptor<CveOrgSyncState> captor = ArgumentCaptor.forClass(CveOrgSyncState.class);
            verify(cveOrgSyncStateRepository, atLeastOnce()).save(captor.capture());
            assertThat(captor.getValue().getLastReleaseTag()).isEqualTo(maliciousTag);
        });
    }

    /** Captures every log event {@link CveOrgSyncService}'s own logger emits while {@code action}
     *  runs, temporarily lowering the logger to DEBUG (same convention as {@code
     *  UserApiKeyServiceTest#captureLogEvents}) and restoring both the original level and appender
     *  list afterward regardless of outcome. */
    private List<ILoggingEvent> captureLogEvents(Runnable action) {
        Logger logger = (Logger) LoggerFactory.getLogger(CveOrgSyncService.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        Level originalLevel = logger.getLevel();
        logger.setLevel(Level.DEBUG);
        try {
            action.run();
        } finally {
            logger.detachAppender(appender);
            logger.setLevel(originalLevel);
        }
        return appender.list;
    }
}
