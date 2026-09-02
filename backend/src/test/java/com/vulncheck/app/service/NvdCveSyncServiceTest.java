package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.vulncheck.app.entity.NvdCveSyncChunk;
import com.vulncheck.app.entity.NvdCveSyncChunkStatus;
import com.vulncheck.app.entity.NvdCveSyncState;
import com.vulncheck.app.repository.NvdCveCpeMatchRepository;
import com.vulncheck.app.repository.NvdCveRecordRepository;
import com.vulncheck.app.repository.NvdCveSyncChunkRepository;
import com.vulncheck.app.repository.NvdCveSyncStateRepository;
import com.vulncheck.app.service.NvdCveSyncService.RunBudget;
import com.vulncheck.app.service.NvdCveSyncService.SyncOutcome;
import com.vulncheck.app.service.nvd.NvdRateLimiter;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

/**
 * Coverage for the chunked, resumable NVD CVE backfill/delta engine (closed-mode backlog item 202)
 * — the {@link NvdCveSyncService#tryBeginRun}/{@link NvdCveSyncService#releaseRunGuard} single-run
 * guard (same shape as {@code NvdCpeSyncServiceTest}), chunk-window seeding, per-page persistence,
 * the adaptive-split threshold, the sanitized error path, and the run-budget cutoff. Every fetch
 * failure/success is driven through {@link MockRestServiceServer} — no real NVD network call.
 */
class NvdCveSyncServiceTest {

    private MockRestServiceServer syncServer;
    private NvdCveSyncStateRepository stateRepository;
    private NvdCveSyncChunkRepository chunkRepository;
    private NvdCveRecordRepository recordRepository;
    private NvdCveCpeMatchRepository cpeMatchRepository;
    private NvdCveSyncService service;

    @BeforeEach
    void setUp() {
        RestClient.Builder syncClientBuilder = RestClient.builder();
        syncServer = MockRestServiceServer.bindTo(syncClientBuilder).build();
        stateRepository = mock(NvdCveSyncStateRepository.class);
        chunkRepository = mock(NvdCveSyncChunkRepository.class);
        recordRepository = mock(NvdCveRecordRepository.class);
        cpeMatchRepository = mock(NvdCveCpeMatchRepository.class);
        service = new NvdCveSyncService(syncClientBuilder.build(), new NvdRateLimiter(), stateRepository,
                chunkRepository, recordRepository, cpeMatchRepository);

        when(stateRepository.findById((short) 1)).thenReturn(Optional.of(freshState()));
    }

    private NvdCveSyncState freshState() {
        NvdCveSyncState state = new NvdCveSyncState();
        state.setBaselineCompleted(false);
        return state;
    }

    private NvdCveSyncChunk pendingChunk(OffsetDateTime start, OffsetDateTime end) {
        NvdCveSyncChunk chunk = new NvdCveSyncChunk();
        chunk.setId(1L);
        chunk.setWindowStart(start);
        chunk.setWindowEnd(end);
        chunk.setStatus(NvdCveSyncChunkStatus.PENDING);
        chunk.setNextStartIndex(0);
        return chunk;
    }

    private String pageJson(int totalResults, String vulnerabilitiesJson) {
        return "{\"totalResults\":" + totalResults + ",\"vulnerabilities\":" + vulnerabilitiesJson + "}";
    }

    private String oneVulnerabilityJson(String cveId) {
        return "[{\"cve\":{\"id\":\"" + cveId + "\",\"published\":\"2023-01-01T00:00:00.000\","
                + "\"lastModified\":\"2023-06-01T00:00:00.000\","
                + "\"descriptions\":[{\"lang\":\"en\",\"value\":\"An example vulnerability.\"}],"
                + "\"metrics\":{\"cvssMetricV31\":[{\"cvssData\":{\"baseScore\":9.8,\"baseSeverity\":\"CRITICAL\"}}]},"
                + "\"configurations\":[{\"nodes\":[{\"cpeMatch\":[{\"vulnerable\":true,"
                + "\"criteria\":\"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*\",\"versionEndExcluding\":\"2.0.0\"}]}]}]}}]";
    }

    // --- single-run guard -----------------------------------------------------------------

    @Test
    void tryBeginRunReturnsFalseWhileASlotIsAlreadyHeld() {
        assertThat(service.tryBeginRun()).isTrue();
        assertThat(service.tryBeginRun())
                .as("a second caller must not be able to acquire the slot while the first still holds it")
                .isFalse();
    }

    @Test
    void releaseRunGuardFreesTheSlotWithoutRunningATick() {
        assertThat(service.tryBeginRun()).isTrue();

        service.releaseRunGuard();

        assertThat(service.tryBeginRun()).isTrue();
    }

    @Test
    void runBackfillTickAndReleaseFreesTheSlotEvenWhenTheTickThrows() {
        when(stateRepository.findById((short) 1)).thenReturn(Optional.empty());
        assertThat(service.tryBeginRun()).isTrue();

        assertThatThrownBy(() -> service.runBackfillTickAndRelease(Optional.empty(), new RunBudget(1, Duration.ofMinutes(1))))
                .isInstanceOf(IllegalStateException.class);

        assertThat(service.tryBeginRun())
                .as("the slot must be free again even when the tick itself throws")
                .isTrue();
    }

    // --- chunk-window seeding ---------------------------------------------------------------

    @Test
    void backfillTickSeedsTheFullDateWindowQueueOnlyWhenNoChunksExistYet() {
        when(chunkRepository.count()).thenReturn(0L);
        when(chunkRepository.findByStatusNotOrderByWindowStartAsc(NvdCveSyncChunkStatus.COMPLETED))
                .thenReturn(List.of());
        when(chunkRepository.countByStatusNot(NvdCveSyncChunkStatus.COMPLETED)).thenReturn(0L);

        SyncOutcome outcome = service.runBackfillTickAndRelease(Optional.empty(), new RunBudget(5, Duration.ofMinutes(5)));

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<NvdCveSyncChunk>> captor = ArgumentCaptor.forClass(List.class);
        verify(chunkRepository).saveAll(captor.capture());
        List<NvdCveSyncChunk> seeded = captor.getValue();
        assertThat(seeded).isNotEmpty();
        assertThat(seeded.get(0).getWindowStart()).isEqualTo(OffsetDateTime.of(1999, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC));
        assertThat(seeded).allSatisfy(c -> assertThat(c.getStatus()).isEqualTo(NvdCveSyncChunkStatus.PENDING));
        // Every window must be <= 120 days (NVD's documented lastModStartDate/lastModEndDate cap).
        assertThat(seeded).allSatisfy(c ->
                assertThat(Duration.between(c.getWindowStart(), c.getWindowEnd()).toDays()).isLessThanOrEqualTo(120));
        // Windows must fully cover [1999-01-01, now) with no gaps: each window's end is the next
        // window's start.
        for (int i = 1; i < seeded.size(); i++) {
            assertThat(seeded.get(i).getWindowStart()).isEqualTo(seeded.get(i - 1).getWindowEnd());
        }
        assertThat(outcome.completed())
                .as("no chunks were left pending after this (artificial, empty-pending-list) tick")
                .isTrue();
    }

    @Test
    void backfillTickDoesNotReseedWhenChunksAlreadyExist() {
        when(chunkRepository.count()).thenReturn(1L);
        when(chunkRepository.findByStatusNotOrderByWindowStartAsc(NvdCveSyncChunkStatus.COMPLETED))
                .thenReturn(List.of());
        when(chunkRepository.countByStatusNot(NvdCveSyncChunkStatus.COMPLETED)).thenReturn(0L);

        service.runBackfillTickAndRelease(Optional.empty(), new RunBudget(5, Duration.ofMinutes(5)));

        verify(chunkRepository, never()).saveAll(anyList());
    }

    // --- per-page chunk processing -----------------------------------------------------------

    @Test
    void backfillTickFullyIngestsAndCompletesAChunkThatFitsInOnePage() {
        when(chunkRepository.count()).thenReturn(1L);
        OffsetDateTime start = OffsetDateTime.of(2020, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC);
        NvdCveSyncChunk chunk = pendingChunk(start, start.plusDays(120));
        when(chunkRepository.findByStatusNotOrderByWindowStartAsc(NvdCveSyncChunkStatus.COMPLETED))
                .thenReturn(List.of(chunk));
        when(chunkRepository.countByStatusNot(NvdCveSyncChunkStatus.COMPLETED)).thenReturn(0L);
        syncServer.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(pageJson(1, oneVulnerabilityJson("CVE-2023-0001")), MediaType.APPLICATION_JSON));

        SyncOutcome outcome = service.runBackfillTickAndRelease(Optional.empty(), new RunBudget(5, Duration.ofMinutes(5)));

        syncServer.verify();
        assertThat(outcome.upserted()).isEqualTo(1);
        assertThat(outcome.completed()).isTrue();
        assertThat(chunk.getStatus()).isEqualTo(NvdCveSyncChunkStatus.COMPLETED);
        assertThat(chunk.getNextStartIndex()).isEqualTo(1);

        ArgumentCaptor<List<NvdCveRecordRepository.Row>> recordsCaptor = ArgumentCaptor.forClass(List.class);
        verify(recordRepository).upsertBatch(recordsCaptor.capture());
        NvdCveRecordRepository.Row row = recordsCaptor.getValue().get(0);
        assertThat(row.cveId()).isEqualTo("CVE-2023-0001");
        assertThat(row.description()).isEqualTo("An example vulnerability.");
        assertThat(row.severity()).isEqualTo("CRITICAL");
        assertThat(row.cvssScore()).isEqualByComparingTo("9.8");

        ArgumentCaptor<List<NvdCveCpeMatchRepository.Row>> matchesCaptor = ArgumentCaptor.forClass(List.class);
        verify(cpeMatchRepository).replaceForCves(eq(List.of("CVE-2023-0001")), matchesCaptor.capture());
        NvdCveCpeMatchRepository.Row match = matchesCaptor.getValue().get(0);
        assertThat(match.vendor()).isEqualTo("acme");
        assertThat(match.product()).isEqualTo("widget");
        assertThat(match.versionEndExcluding()).isEqualTo("2.0.0");
    }

    @Test
    void backfillTickMarksAChunkFailedOnAFetchErrorWithoutLeakingTheUrlOrResponseBody() {
        when(chunkRepository.count()).thenReturn(1L);
        OffsetDateTime start = OffsetDateTime.of(2020, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC);
        NvdCveSyncChunk chunk = pendingChunk(start, start.plusDays(120));
        when(chunkRepository.findByStatusNotOrderByWindowStartAsc(NvdCveSyncChunkStatus.COMPLETED))
                .thenReturn(List.of(chunk));
        when(chunkRepository.countByStatusNot(NvdCveSyncChunkStatus.COMPLETED)).thenReturn(1L);
        syncServer.expect(method(HttpMethod.GET)).andRespond(withServerError());

        SyncOutcome outcome = service.runBackfillTickAndRelease(Optional.empty(), new RunBudget(5, Duration.ofMinutes(5)));

        syncServer.verify();
        assertThat(outcome.completed()).isFalse();
        assertThat(chunk.getStatus()).isEqualTo(NvdCveSyncChunkStatus.FAILED);
        assertThat(chunk.getLastError())
                .as("must record status + exception class only, never the request URL or response body")
                .contains("500")
                .doesNotContain("nvd.nist.gov")
                .doesNotContain("apiKey");
        verifyNoInteractions(recordRepository);
    }

    @Test
    void backfillTickAdaptivelySplitsAWindowWhoseFirstPageExceedsTheThreshold() {
        when(chunkRepository.count()).thenReturn(1L);
        OffsetDateTime start = OffsetDateTime.of(2020, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC);
        OffsetDateTime end = start.plusDays(120);
        NvdCveSyncChunk chunk = pendingChunk(start, end);
        when(chunkRepository.findByStatusNotOrderByWindowStartAsc(NvdCveSyncChunkStatus.COMPLETED))
                .thenReturn(List.of(chunk));
        when(chunkRepository.countByStatusNot(NvdCveSyncChunkStatus.COMPLETED)).thenReturn(2L);
        syncServer.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(pageJson(25_000, oneVulnerabilityJson("CVE-2023-0002")), MediaType.APPLICATION_JSON));

        service.runBackfillTickAndRelease(Optional.empty(), new RunBudget(5, Duration.ofMinutes(5)));

        syncServer.verify();
        assertThat(chunk.getStatus())
                .as("the original (too-dense) chunk is marked COMPLETED once its children exist")
                .isEqualTo(NvdCveSyncChunkStatus.COMPLETED);
        // Its first page's data is still ingested rather than discarded.
        verify(recordRepository).upsertBatch(anyList());

        ArgumentCaptor<NvdCveSyncChunk> childCaptor = ArgumentCaptor.forClass(NvdCveSyncChunk.class);
        verify(chunkRepository, times(3)).save(childCaptor.capture());
        List<NvdCveSyncChunk> saved = childCaptor.getAllValues();
        OffsetDateTime mid = start.plus(Duration.between(start, end).dividedBy(2));
        assertThat(saved).filteredOn(c -> c != chunk)
                .hasSize(2)
                .allSatisfy(c -> assertThat(c.getStatus()).isEqualTo(NvdCveSyncChunkStatus.PENDING))
                .anySatisfy(c -> {
                    assertThat(c.getWindowStart()).isEqualTo(start);
                    assertThat(c.getWindowEnd()).isEqualTo(mid);
                })
                .anySatisfy(c -> {
                    assertThat(c.getWindowStart()).isEqualTo(mid);
                    assertThat(c.getWindowEnd()).isEqualTo(end);
                });
    }

    @Test
    void backfillTickStopsAtTheRequestBudgetEvenWithMoreChunksPending() {
        when(chunkRepository.count()).thenReturn(1L);
        OffsetDateTime start = OffsetDateTime.of(2020, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC);
        NvdCveSyncChunk chunk = pendingChunk(start, start.plusDays(120));
        when(chunkRepository.findByStatusNotOrderByWindowStartAsc(NvdCveSyncChunkStatus.COMPLETED))
                .thenReturn(List.of(chunk));
        when(chunkRepository.countByStatusNot(NvdCveSyncChunkStatus.COMPLETED)).thenReturn(1L);
        // totalResults far exceeds one page's worth, so after ingesting this single page the chunk
        // still isn't finished -- but the budget (1 request) must stop the run right here anyway.
        syncServer.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(pageJson(5000, oneVulnerabilityJson("CVE-2023-0003")), MediaType.APPLICATION_JSON));

        SyncOutcome outcome = service.runBackfillTickAndRelease(Optional.empty(), new RunBudget(1, Duration.ofMinutes(5)));

        syncServer.verify();
        assertThat(outcome.completed()).isFalse();
        assertThat(chunk.getNextStartIndex()).isEqualTo(1);
        assertThat(chunk.getStatus()).isEqualTo(NvdCveSyncChunkStatus.IN_PROGRESS);
    }

    // --- delta sync (shares the same per-chunk executor) --------------------------------------

    @Test
    void deltaTickIsSkippedWhenTheBaselineHasNotCompletedYet() {
        SyncOutcome outcome = service.runDeltaTickAndRelease(Optional.empty(), new RunBudget(5, Duration.ofMinutes(5)));

        assertThat(outcome.upserted()).isZero();
        assertThat(outcome.completed()).isFalse();
        verifyNoInteractions(chunkRepository);
        syncServer.verify();
    }

    @Test
    void deltaTickEnqueuesAndCompletesAChunkAndAdvancesTheHighWaterMark() {
        NvdCveSyncState state = freshState();
        state.setBaselineCompleted(true);
        when(stateRepository.findById((short) 1)).thenReturn(Optional.of(state));
        syncServer.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(pageJson(0, "[]"), MediaType.APPLICATION_JSON));

        SyncOutcome outcome = service.runDeltaTickAndRelease(Optional.empty(), new RunBudget(5, Duration.ofMinutes(5)));

        syncServer.verify();
        assertThat(outcome.completed()).isTrue();
        assertThat(state.getLastDeltaSyncedAt()).isNotNull();
        // Once to persist the newly-enqueued chunk, once more when processChunkStep marks it
        // COMPLETED after the (single, empty) page it fetched.
        verify(chunkRepository, times(2)).save(any(NvdCveSyncChunk.class));
        verify(stateRepository, times(1)).save(state);
    }
}
