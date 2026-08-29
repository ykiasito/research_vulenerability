package com.vulncheck.app.service.osv;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.fasterxml.jackson.databind.JsonNode;
import com.vulncheck.app.entity.OsvSyncFailure;
import com.vulncheck.app.entity.OsvSyncState;
import com.vulncheck.app.repository.OsvAdvisoryRepository;
import com.vulncheck.app.repository.OsvSyncFailureRepository;
import com.vulncheck.app.repository.OsvSyncStateRepository;
import com.vulncheck.app.service.osv.OsvSyncService.StreamWithHeaders;
import com.vulncheck.app.service.vuln.OsvEcosystems;
import com.vulncheck.app.service.vuln.OsvSyncRateLimiter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

/** Mockito-based unit test (this project's convention: mock the repository/external-client
 *  dependencies rather than hitting a real DB) — {@link OsvDocumentUpsertService} is mocked to a
 *  simple "return the document's own id" stand-in, so these tests exercise {@link OsvSyncService}'s
 *  own baseline/delta orchestration logic (ecosystem-zip fan-out, GHSA-/MAL- exclusion, the
 *  self-calibrating completeness gate, delta's directory allowlist, and group-atomic cursor
 *  advancement) rather than the JSON-parsing details {@code OsvDocumentUpsertServiceTest} already
 *  covers. */
class OsvSyncServiceTest {

    private OsvDocumentUpsertService documentUpsertService;
    private OsvAdvisoryRepository osvAdvisoryRepository;
    private Map<Short, OsvSyncState> stateStore;
    private OsvSyncStateRepository osvSyncStateRepository;
    private Map<String, OsvSyncFailure> failureStore;
    private OsvSyncFailureRepository osvSyncFailureRepository;

    private void setUpCommonMocks() {
        documentUpsertService = mock(OsvDocumentUpsertService.class);
        when(documentUpsertService.upsertOsvJson(any(JsonNode.class)))
                .thenAnswer(inv -> inv.getArgument(0, JsonNode.class).path("id").asText(null));

        osvAdvisoryRepository = mock(OsvAdvisoryRepository.class);
        when(osvAdvisoryRepository.currentDatabaseTime()).thenReturn(Instant.parse("2026-01-10T00:00:00Z"));

        stateStore = new HashMap<>();
        osvSyncStateRepository = mock(OsvSyncStateRepository.class);
        when(osvSyncStateRepository.findById((short) 1)).thenAnswer(inv -> Optional.ofNullable(stateStore.get((short) 1)));
        when(osvSyncStateRepository.save(any())).thenAnswer(inv -> {
            OsvSyncState s = inv.getArgument(0);
            stateStore.put((short) 1, s);
            return s;
        });

        failureStore = new LinkedHashMap<>();
        osvSyncFailureRepository = mock(OsvSyncFailureRepository.class);
        when(osvSyncFailureRepository.findById(anyString())).thenAnswer(inv -> Optional.ofNullable(failureStore.get((String) inv.getArgument(0))));
        when(osvSyncFailureRepository.save(any())).thenAnswer(inv -> {
            OsvSyncFailure f = inv.getArgument(0);
            failureStore.put(f.getOsvId(), f);
            return f;
        });
    }

    private byte[] buildZip(Map<String, String> filenameToJson) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
                for (Map.Entry<String, String> entry : filenameToJson.entrySet()) {
                    zip.putNextEntry(new ZipEntry(entry.getKey()));
                    zip.write(entry.getValue().getBytes(StandardCharsets.UTF_8));
                    zip.closeEntry();
                }
            }
            return bytes.toByteArray();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // ------------------------------------------------------------------ baseline ----------------

    @Test
    void baselineFetchesAllTenEcosystemZipsExcludesGhsaAndMalAndComputesInitialCursor() {
        setUpCommonMocks();

        Map<String, byte[]> zipsByEcosystem = new HashMap<>();
        Map<String, String> pypiEntries = new LinkedHashMap<>();
        pypiEntries.put("PYSEC-2023-1.json", "{\"id\":\"PYSEC-2023-1\",\"modified\":\"2026-01-01T00:00:00Z\"}");
        pypiEntries.put("GHSA-aaaa-bbbb-cccc.json", "{\"id\":\"GHSA-aaaa-bbbb-cccc\",\"modified\":\"2026-01-01T00:00:00Z\"}");
        pypiEntries.put("MAL-2023-1.json", "{\"id\":\"MAL-2023-1\",\"modified\":\"2026-01-01T00:00:00Z\"}");
        zipsByEcosystem.put("PyPI", buildZip(pypiEntries));

        Map<String, String> goEntries = new LinkedHashMap<>();
        goEntries.put("GO-2023-1.json", "{\"id\":\"GO-2023-1\",\"modified\":\"2026-01-01T00:00:00Z\"}");
        zipsByEcosystem.put("Go", buildZip(goEntries));

        Map<String, String> lastModifiedByEcosystem = Map.of(
                "PyPI", "Thu, 01 Jan 2026 00:00:00 GMT",
                "Go", "Sat, 03 Jan 2026 00:00:00 GMT");

        Function<String, StreamWithHeaders> zipStreamOpener = url -> {
            for (String ecosystem : OsvEcosystems.INTERNAL_TO_OSV.values()) {
                if (url.equals("https://osv-vulnerabilities.storage.googleapis.com/" + ecosystem + "/all.zip")) {
                    byte[] bytes = zipsByEcosystem.getOrDefault(ecosystem, buildZip(Map.of()));
                    String lastModified = lastModifiedByEcosystem.get(ecosystem);
                    return new StreamWithHeaders(new ByteArrayInputStream(bytes), lastModified, "gen-" + ecosystem);
                }
            }
            throw new IllegalArgumentException("Unexpected URL: " + url);
        };
        Function<String, InputStream> csvStreamOpener = url -> new ByteArrayInputStream(new byte[0]);

        OsvSyncService service = new OsvSyncService(RestClient.builder().build(), documentUpsertService, osvAdvisoryRepository,
                osvSyncStateRepository, osvSyncFailureRepository, OsvSyncRateLimiter.disabledForTesting(),
                OsvSyncService.DEFAULT_MAX_DOCUMENTS_PER_DELTA_RUN, zipStreamOpener, csvStreamOpener);

        OsvSyncService.SyncResult result = service.syncBaseline();

        assertThat(result.upserted()).isEqualTo(2); // PYSEC-2023-1, GO-2023-1 — GHSA-*/MAL-* excluded
        assertThat(result.failed()).isZero();

        OsvSyncState state = stateStore.get((short) 1);
        assertThat(state.isBaselineLoaded()).isTrue();
        assertThat(state.isSyncInProgress()).isFalse();
        // min(last-modified) across the 10 zips is PyPI's 2026-01-01T00:00:00Z, minus 7 days.
        assertThat(state.getLastCursor()).isEqualTo(OffsetDateTime.parse("2025-12-25T00:00:00Z"));
        assertThat(state.getBaselineSourceGeneration()).contains("PyPI=gen-PyPI").contains("Go=gen-Go");
    }

    @Test
    void baselineBelowTheCompletenessThresholdIsNotMarkedLoaded() {
        setUpCommonMocks();
        // documentUpsertService returns null (failure) for a specific id, to simulate a partial run.
        when(documentUpsertService.upsertOsvJson(any(JsonNode.class))).thenAnswer(inv -> {
            String id = inv.getArgument(0, JsonNode.class).path("id").asText(null);
            return "PYSEC-2023-BAD".equals(id) ? null : id;
        });

        Map<String, String> pypiEntries = new LinkedHashMap<>();
        // Only 1 of 10 candidate entries succeeds — well under the 90% completeness threshold.
        for (int i = 0; i < 9; i++) {
            pypiEntries.put("PYSEC-2023-BAD" + i + ".json", "{\"id\":\"PYSEC-2023-BAD\",\"modified\":\"2026-01-01T00:00:00Z\"}");
        }
        pypiEntries.put("PYSEC-2023-OK.json", "{\"id\":\"PYSEC-2023-OK\",\"modified\":\"2026-01-01T00:00:00Z\"}");

        Function<String, StreamWithHeaders> zipStreamOpener = url -> {
            if (url.equals("https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip")) {
                return new StreamWithHeaders(new ByteArrayInputStream(buildZip(pypiEntries)), null, null);
            }
            return new StreamWithHeaders(new ByteArrayInputStream(buildZip(Map.of())), null, null);
        };
        Function<String, InputStream> csvStreamOpener = url -> new ByteArrayInputStream(new byte[0]);

        OsvSyncService service = new OsvSyncService(RestClient.builder().build(), documentUpsertService, osvAdvisoryRepository,
                osvSyncStateRepository, osvSyncFailureRepository, OsvSyncRateLimiter.disabledForTesting(),
                OsvSyncService.DEFAULT_MAX_DOCUMENTS_PER_DELTA_RUN, zipStreamOpener, csvStreamOpener);

        OsvSyncService.SyncResult result = service.syncBaseline();

        assertThat(result.upserted()).isEqualTo(1);
        assertThat(result.failed()).isEqualTo(9);
        OsvSyncState state = stateStore.get((short) 1);
        assertThat(state.isBaselineLoaded()).isFalse();
        assertThat(state.getLastSyncError()).contains("incomplete");
    }

    @Test
    void baselineWithNoCandidatesAtAllIsNotMarkedLoaded() {
        setUpCommonMocks();
        Function<String, StreamWithHeaders> zipStreamOpener =
                url -> new StreamWithHeaders(new ByteArrayInputStream(buildZip(Map.of())), null, null);
        Function<String, InputStream> csvStreamOpener = url -> new ByteArrayInputStream(new byte[0]);

        OsvSyncService service = new OsvSyncService(RestClient.builder().build(), documentUpsertService, osvAdvisoryRepository,
                osvSyncStateRepository, osvSyncFailureRepository, OsvSyncRateLimiter.disabledForTesting(),
                OsvSyncService.DEFAULT_MAX_DOCUMENTS_PER_DELTA_RUN, zipStreamOpener, csvStreamOpener);

        OsvSyncService.SyncResult result = service.syncBaseline();

        assertThat(result.upserted()).isZero();
        OsvSyncState state = stateStore.get((short) 1);
        assertThat(state.isBaselineLoaded()).isFalse();
    }

    // -------------------------------------------------------------------- delta -----------------

    private void seedBaselineLoadedState(OffsetDateTime cursor) {
        OsvSyncState state = new OsvSyncState();
        state.setId((short) 1);
        state.setBaselineLoaded(true);
        state.setLastCursor(cursor);
        stateStore.put((short) 1, state);
    }

    private OsvSyncService deltaService(RestClient.Builder builder, int maxDocumentsPerDeltaRun, String csvContent) {
        Function<String, InputStream> csvStreamOpener = url -> new ByteArrayInputStream(csvContent.getBytes(StandardCharsets.UTF_8));
        Function<String, OsvSyncService.StreamWithHeaders> zipStreamOpener =
                url -> new StreamWithHeaders(new ByteArrayInputStream(buildZip(Map.of())), null, null);
        return new OsvSyncService(builder.build(), documentUpsertService, osvAdvisoryRepository,
                osvSyncStateRepository, osvSyncFailureRepository, OsvSyncRateLimiter.disabledForTesting(),
                maxDocumentsPerDeltaRun, zipStreamOpener, csvStreamOpener);
    }

    @Test
    void deltaFiltersByDirectoryAllowlistExcludesGhsaAndMalAndOnlyProcessesRowsAfterTheCursor() {
        setUpCommonMocks();
        seedBaselineLoadedState(OffsetDateTime.parse("2026-01-01T00:00:00Z"));

        String csv = String.join("\n",
                "2026-01-05T00:00:00Z,PyPI/PYSEC-2023-5",
                "2026-01-05T00:00:00Z,PyPI/GHSA-xxxx-xxxx-xxxx",
                "2026-01-05T00:00:00Z,npm/MAL-2023-1",
                "2026-01-05T00:00:00Z,GIT/EEF-CVE-2026-1", // GIT is not an allowlisted directory
                "2020-01-01T00:00:00Z,PyPI/PYSEC-OLD"); // before the cursor

        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(method(org.springframework.http.HttpMethod.GET))
                .andExpect(requestTo("https://osv-vulnerabilities.storage.googleapis.com/PyPI/PYSEC-2023-5.json"))
                .andRespond(withSuccess("{\"id\":\"PYSEC-2023-5\",\"modified\":\"2026-01-05T00:00:00Z\"}", MediaType.APPLICATION_JSON));

        OsvSyncService service = deltaService(builder, OsvSyncService.DEFAULT_MAX_DOCUMENTS_PER_DELTA_RUN, csv);

        OsvSyncService.SyncResult result = service.syncDelta();

        server.verify(); // exactly one request made — the other 4 rows were filtered out before any fetch
        assertThat(result.upserted()).isEqualTo(1);
        assertThat(result.failed()).isZero();
        assertThat(stateStore.get((short) 1).getLastCursor()).isEqualTo(OffsetDateTime.parse("2026-01-05T00:00:00Z"));
    }

    @Test
    void aRealFailureInATimestampGroupStopsTheRunAndDoesNotAdvanceTheCursorPastIt() {
        setUpCommonMocks();
        seedBaselineLoadedState(OffsetDateTime.parse("2026-01-01T00:00:00Z"));

        String csv = String.join("\n",
                "2026-01-05T00:00:00Z,PyPI/PYSEC-A", // succeeds
                "2026-01-05T00:00:00Z,PyPI/PYSEC-B", // fails — same timestamp group as PYSEC-A
                "2026-01-06T00:00:00Z,PyPI/PYSEC-C"); // a later group — must never be attempted

        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(method(org.springframework.http.HttpMethod.GET))
                .andExpect(requestTo("https://osv-vulnerabilities.storage.googleapis.com/PyPI/PYSEC-A.json"))
                .andRespond(withSuccess("{\"id\":\"PYSEC-A\",\"modified\":\"2026-01-05T00:00:00Z\"}", MediaType.APPLICATION_JSON));
        server.expect(method(org.springframework.http.HttpMethod.GET))
                .andExpect(requestTo("https://osv-vulnerabilities.storage.googleapis.com/PyPI/PYSEC-B.json"))
                .andRespond(withServerError());

        OsvSyncService service = deltaService(builder, OsvSyncService.DEFAULT_MAX_DOCUMENTS_PER_DELTA_RUN, csv);

        OsvSyncService.SyncResult result = service.syncDelta();

        server.verify(); // PYSEC-C was never requested — confirms the run stopped, didn't just skip the failure
        assertThat(result.upserted()).isEqualTo(1);
        assertThat(result.failed()).isEqualTo(1);
        // Cursor stays at the ORIGINAL cursor — the failed group's timestamp is never committed.
        assertThat(stateStore.get((short) 1).getLastCursor()).isEqualTo(OffsetDateTime.parse("2026-01-01T00:00:00Z"));
        assertThat(stateStore.get((short) 1).getLastSyncError()).contains("failed");
    }

    @Test
    void maxDocumentsPerDeltaRunOnlyCutsOffAtAGroupBoundaryNeverMidGroup() {
        setUpCommonMocks();
        seedBaselineLoadedState(OffsetDateTime.parse("2026-01-01T00:00:00Z"));

        // First group has 2 rows sharing one timestamp; a limit of 1 must still let BOTH finish
        // (the boundary is only checked BETWEEN groups) — the second group must never be attempted.
        String csv = String.join("\n",
                "2026-01-05T00:00:00Z,PyPI/PYSEC-A",
                "2026-01-05T00:00:00Z,PyPI/PYSEC-B",
                "2026-01-06T00:00:00Z,PyPI/PYSEC-C",
                "2026-01-06T00:00:00Z,PyPI/PYSEC-D");

        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(method(org.springframework.http.HttpMethod.GET))
                .andExpect(requestTo("https://osv-vulnerabilities.storage.googleapis.com/PyPI/PYSEC-A.json"))
                .andRespond(withSuccess("{\"id\":\"PYSEC-A\",\"modified\":\"2026-01-05T00:00:00Z\"}", MediaType.APPLICATION_JSON));
        server.expect(method(org.springframework.http.HttpMethod.GET))
                .andExpect(requestTo("https://osv-vulnerabilities.storage.googleapis.com/PyPI/PYSEC-B.json"))
                .andRespond(withSuccess("{\"id\":\"PYSEC-B\",\"modified\":\"2026-01-05T00:00:00Z\"}", MediaType.APPLICATION_JSON));

        OsvSyncService service = deltaService(builder, 1, csv); // limit of 1 — but boundary is per-group, not per-row

        OsvSyncService.SyncResult result = service.syncDelta();

        server.verify(); // PYSEC-C/D never requested
        assertThat(result.upserted()).isEqualTo(2);
        assertThat(stateStore.get((short) 1).getLastCursor()).isEqualTo(OffsetDateTime.parse("2026-01-05T00:00:00Z"));
    }

    @Test
    void aThirdConsecutiveFailureDeadLettersAndTheCursorThenAdvancesPastIt() {
        setUpCommonMocks();
        seedBaselineLoadedState(OffsetDateTime.parse("2026-01-01T00:00:00Z"));
        String csv = "2026-01-05T00:00:00Z,PyPI/PYSEC-POISON";

        RestClient.Builder builder1 = RestClient.builder();
        MockRestServiceServer server1 = MockRestServiceServer.bindTo(builder1).build();
        server1.expect(method(org.springframework.http.HttpMethod.GET)).andRespond(withServerError());
        deltaService(builder1, OsvSyncService.DEFAULT_MAX_DOCUMENTS_PER_DELTA_RUN, csv).syncDelta();

        RestClient.Builder builder2 = RestClient.builder();
        MockRestServiceServer server2 = MockRestServiceServer.bindTo(builder2).build();
        server2.expect(method(org.springframework.http.HttpMethod.GET)).andRespond(withServerError());
        deltaService(builder2, OsvSyncService.DEFAULT_MAX_DOCUMENTS_PER_DELTA_RUN, csv).syncDelta();

        assertThat(stateStore.get((short) 1).getLastCursor()).isEqualTo(OffsetDateTime.parse("2026-01-01T00:00:00Z"));

        RestClient.Builder builder3 = RestClient.builder();
        MockRestServiceServer server3 = MockRestServiceServer.bindTo(builder3).build();
        server3.expect(method(org.springframework.http.HttpMethod.GET)).andRespond(withServerError());
        OsvSyncService.SyncResult third = deltaService(builder3, OsvSyncService.DEFAULT_MAX_DOCUMENTS_PER_DELTA_RUN, csv).syncDelta();

        assertThat(third.failed()).isEqualTo(1);
        assertThat(failureStore.get("PYSEC-POISON").getDeadLetteredAt()).isNotNull();
        // Dead-lettered failures don't block the group from being treated as complete — the cursor
        // advances past this poison-pill entry so it doesn't wedge delta sync forever.
        assertThat(stateStore.get((short) 1).getLastCursor()).isEqualTo(OffsetDateTime.parse("2026-01-05T00:00:00Z"));
    }

    @Test
    void deltaIsANoOpWhenBaselineHasNeverCompleted() {
        setUpCommonMocks();
        OsvSyncService service = deltaService(RestClient.builder(), OsvSyncService.DEFAULT_MAX_DOCUMENTS_PER_DELTA_RUN, "");

        OsvSyncService.SyncResult result = service.syncDelta();

        assertThat(result.upserted()).isZero();
        assertThat(result.alreadyRunning()).isFalse();
    }
}
