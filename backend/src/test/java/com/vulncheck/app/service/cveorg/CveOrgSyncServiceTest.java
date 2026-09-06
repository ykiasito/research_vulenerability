package com.vulncheck.app.service.cveorg;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.sun.net.httpserver.HttpServer;
import com.vulncheck.app.entity.CveOrgSyncState;
import com.vulncheck.app.repository.CveOrgAffectedProductRepository;
import com.vulncheck.app.repository.CveOrgRecordRepository;
import com.vulncheck.app.repository.CveOrgSyncStateRepository;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Optional;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

/**
 * Closed-mode backlog item 379: {@link CveOrgSyncService#syncBaseline}/{@link
 * CveOrgSyncService#syncDelta} previously logged a metadata-resolution or download failure and
 * returned without ever touching {@code cve_org_sync_state} — a mirror failing every scheduled run
 * left no signal anywhere in the DB. These tests exercise the {@code recordSyncFailure}/{@code
 * markSynced} bookkeeping directly (via a real {@link MockRestServiceServer} for the releases-API
 * metadata call and a plain local {@link HttpServer} for the asset download itself — this class's
 * current {@link CveOrgSyncService#download} is a plain, unauthenticated {@link
 * java.net.URLConnection#openConnection()} with no host allowlist to relax for a test).
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

    private interface LocalServerCallback {
        void run(int port) throws Exception;
    }

    private static void withLocalServer(com.sun.net.httpserver.HttpHandler handler, LocalServerCallback callback)
            throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        try {
            server.createContext("/asset", handler);
            server.start();
            callback.run(server.getAddress().getPort());
        } finally {
            server.stop(0);
        }
    }

    private static com.sun.net.httpserver.HttpHandler respondWithStatus(int statusCode) {
        return exchange -> {
            exchange.sendResponseHeaders(statusCode, -1);
            exchange.close();
        };
    }

    private static com.sun.net.httpserver.HttpHandler respondWithBody(byte[] body) {
        return exchange -> {
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        };
    }

    /** Before this fix, a release response with no matching delta asset just logged a warning and
     *  returned — {@code cve_org_sync_state} stayed completely untouched, forever, on a run shaped
     *  like this. */
    @Test
    void syncDeltaRecordsAFailureWhenTheLatestReleaseHasNoDeltaAsset() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(method(HttpMethod.GET))
                .andExpect(requestTo(LATEST_RELEASE_API))
                .andRespond(withSuccess("{\"tag_name\":\"cve_2026-09-06_0000Z\",\"assets\":[]}", MediaType.APPLICATION_JSON));
        CveOrgSyncService service = new CveOrgSyncService(builder.build(), cveOrgRecordRepository,
                cveOrgAffectedProductRepository, cveOrgSyncStateRepository);

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
        withLocalServer(respondWithStatus(403), port -> {
            RestClient.Builder builder = RestClient.builder();
            MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
            String releaseJson = "{\"tag_name\":\"cve_2026-09-06_0000Z\",\"assets\":[{"
                    + "\"name\":\"2026-09-06T00_00_00Z_all_CVEs_at_midnight.zip.zip\","
                    + "\"browser_download_url\":\"http://localhost:" + port + "/asset\"}]}";
            server.expect(method(HttpMethod.GET))
                    .andExpect(requestTo(LATEST_RELEASE_API))
                    .andRespond(withSuccess(releaseJson, MediaType.APPLICATION_JSON));

            CveOrgSyncService service = new CveOrgSyncService(builder.build(), cveOrgRecordRepository,
                    cveOrgAffectedProductRepository, cveOrgSyncStateRepository);

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

        withLocalServer(respondWithBody(emptyZip), port -> {
            RestClient.Builder builder = RestClient.builder();
            MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
            String releaseJson = "{\"tag_name\":\"cve_2026-09-06_0000Z\",\"assets\":[{"
                    + "\"name\":\"2026-09-06T00_00_00Z_all_CVEs_at_midnight.zip.zip\","
                    + "\"browser_download_url\":\"http://localhost:" + port + "/asset\"}]}";
            server.expect(method(HttpMethod.GET))
                    .andExpect(requestTo(LATEST_RELEASE_API))
                    .andRespond(withSuccess(releaseJson, MediaType.APPLICATION_JSON));

            CveOrgSyncService service = new CveOrgSyncService(builder.build(), cveOrgRecordRepository,
                    cveOrgAffectedProductRepository, cveOrgSyncStateRepository);

            int upserted = service.syncBaseline();

            assertThat(upserted).isZero();
            ArgumentCaptor<CveOrgSyncState> captor = ArgumentCaptor.forClass(CveOrgSyncState.class);
            verify(cveOrgSyncStateRepository).save(captor.capture());
            assertThat(captor.getValue().getLastSyncError()).isNull();
            assertThat(captor.getValue().isBaselineLoaded()).isTrue();
            assertThat(captor.getValue().getLastReleaseTag()).isEqualTo("cve_2026-09-06_0000Z");
        });
    }
}
