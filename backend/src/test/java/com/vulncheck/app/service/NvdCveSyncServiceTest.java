package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
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
        // The real split service, backed by the same mocked chunkRepository -- not a mock itself --
        // so tests can assert against chunkRepository's actual save/exists calls (including the
        // idempotent-split behavior it's responsible for) exactly as if it were wired by Spring.
        NvdCveSyncChunkSplitService chunkSplitService = new NvdCveSyncChunkSplitService(chunkRepository);
        service = new NvdCveSyncService(syncClientBuilder.build(), new NvdRateLimiter(), stateRepository,
                chunkRepository, recordRepository, cpeMatchRepository, chunkSplitService);

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

    /** Same shape as {@link #oneVulnerabilityJson}, but a bare (non-array) fragment and with the
     *  {@code lastModified} field optional -- lets a single page mix a normal CVE with one missing
     *  {@code lastModified} entirely. */
    private String vulnerabilityFragment(String cveId, boolean includeLastModified) {
        String lastModifiedField = includeLastModified ? "\"lastModified\":\"2023-06-01T00:00:00.000\"," : "";
        return "{\"cve\":{\"id\":\"" + cveId + "\",\"published\":\"2023-01-01T00:00:00.000\"," + lastModifiedField
                + "\"descriptions\":[{\"lang\":\"en\",\"value\":\"An example vulnerability.\"}],"
                + "\"metrics\":{\"cvssMetricV31\":[{\"cvssData\":{\"baseScore\":9.8,\"baseSeverity\":\"CRITICAL\"}}]}}}";
    }

    /** A bare-bones {@code vulnerabilities} array of {@code count} entries, each with only an id
     *  and a {@code lastModified} -- used for pagination tests where the exact contents of each
     *  entry don't matter, only that there are enough of them to force a second page. */
    private String manyVulnerabilitiesJson(int count, String cveIdPrefix) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < count; i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append("{\"cve\":{\"id\":\"").append(cveIdPrefix).append(i)
                    .append("\",\"lastModified\":\"2023-06-01T00:00:00.000\"}}");
        }
        return sb.append(']').toString();
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

    /** Closed-mode backlog item 202, REVISE round 1, point 1: a CVE missing {@code lastModified}
     *  (or with an unparseable one) must be skipped, not allowed to blow up the whole page's batch
     *  upsert via {@code nvd_cve_records.last_modified_at}'s {@code NOT NULL} constraint -- which
     *  would otherwise leave the chunk re-fetching (and re-failing on) this exact page forever. */
    @Test
    void ingestSkipsACveWithMissingLastModifiedButStillIngestsTheRestOfThePageAndAdvancesTheChunk() {
        when(chunkRepository.count()).thenReturn(1L);
        OffsetDateTime start = OffsetDateTime.of(2020, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC);
        NvdCveSyncChunk chunk = pendingChunk(start, start.plusDays(120));
        when(chunkRepository.findByStatusNotOrderByWindowStartAsc(NvdCveSyncChunkStatus.COMPLETED))
                .thenReturn(List.of(chunk));
        when(chunkRepository.countByStatusNot(NvdCveSyncChunkStatus.COMPLETED)).thenReturn(0L);
        String vulnerabilitiesJson = "[" + vulnerabilityFragment("CVE-2023-0001", true) + ","
                + vulnerabilityFragment("CVE-2023-9999", false) + "]";
        syncServer.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(pageJson(2, vulnerabilitiesJson), MediaType.APPLICATION_JSON));

        SyncOutcome outcome = service.runBackfillTickAndRelease(Optional.empty(), new RunBudget(5, Duration.ofMinutes(5)));

        syncServer.verify();
        assertThat(outcome.upserted())
                .as("the CVE missing lastModified must be skipped, not counted as upserted")
                .isEqualTo(1);
        assertThat(outcome.completed()).isTrue();
        assertThat(chunk.getStatus())
                .as("the chunk must still complete rather than getting stuck re-fetching this page")
                .isEqualTo(NvdCveSyncChunkStatus.COMPLETED);
        assertThat(chunk.getNextStartIndex())
                .as("next_start_index must move past both fetched records (including the skipped "
                        + "one) so the next tick doesn't refetch this exact same page")
                .isEqualTo(2);

        ArgumentCaptor<List<NvdCveRecordRepository.Row>> recordsCaptor = ArgumentCaptor.forClass(List.class);
        verify(recordRepository).upsertBatch(recordsCaptor.capture());
        assertThat(recordsCaptor.getValue())
                .extracting(NvdCveRecordRepository.Row::cveId)
                .containsExactly("CVE-2023-0001");
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

    /** Closed-mode backlog item 202, REVISE round 1, point 2: {@code splitChunk} must be idempotent
     *  -- a parent window re-selected and re-split a second time (e.g. a retried tick after an
     *  earlier attempt crashed between committing the children and completing the parent) must not
     *  throw ({@code UNIQUE (window_start, window_end)}) or create duplicate child chunks. */
    @Test
    void splittingTheSameWindowTwiceDoesNotDuplicateChildChunksOrThrow() {
        when(chunkRepository.count()).thenReturn(1L);
        OffsetDateTime start = OffsetDateTime.of(2020, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC);
        OffsetDateTime end = start.plusDays(120);
        OffsetDateTime mid = start.plus(Duration.between(start, end).dividedBy(2));
        NvdCveSyncChunk chunk = pendingChunk(start, end);
        when(chunkRepository.findByStatusNotOrderByWindowStartAsc(NvdCveSyncChunkStatus.COMPLETED))
                .thenReturn(List.of(chunk));
        when(chunkRepository.countByStatusNot(NvdCveSyncChunkStatus.COMPLETED)).thenReturn(2L);
        // false on the first check (child doesn't exist yet, gets inserted), true on the second
        // (the retried split finds it already committed and must skip re-inserting it).
        when(chunkRepository.existsByWindowStartAndWindowEnd(start, mid)).thenReturn(false, true);
        when(chunkRepository.existsByWindowStartAndWindowEnd(mid, end)).thenReturn(false, true);
        syncServer.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(pageJson(25_000, oneVulnerabilityJson("CVE-2023-0002")), MediaType.APPLICATION_JSON));
        syncServer.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(pageJson(25_000, oneVulnerabilityJson("CVE-2023-0002")), MediaType.APPLICATION_JSON));

        assertThatCode(() -> {
            service.runBackfillTickAndRelease(Optional.empty(), new RunBudget(5, Duration.ofMinutes(5)));
            service.runBackfillTickAndRelease(Optional.empty(), new RunBudget(5, Duration.ofMinutes(5)));
        }).doesNotThrowAnyException();

        syncServer.verify();
        // Exactly two child chunks total across both split attempts -- no duplicates from the retry.
        verify(chunkRepository, times(2)).save(argThat((NvdCveSyncChunk c) -> c != chunk));
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

    /** Closed-mode backlog item 202, REVISE round 1, point 6: {@code next_start_index} is the
     *  design's resumption mechanism (§4-2-4), but until now nothing exercised a window spanning
     *  more than one page. Confirms the second request's {@code startIndex} equals the first page's
     *  own record count, and that the chunk only completes once the second (final) page is in. */
    @Test
    void backfillTickResumesAcrossMultiplePagesOfTheSameChunkAndOnlyCompletesAfterTheSecondPage() {
        when(chunkRepository.count()).thenReturn(1L);
        OffsetDateTime start = OffsetDateTime.of(2020, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC);
        NvdCveSyncChunk chunk = pendingChunk(start, start.plusDays(120));
        when(chunkRepository.findByStatusNotOrderByWindowStartAsc(NvdCveSyncChunkStatus.COMPLETED))
                .thenReturn(List.of(chunk));
        when(chunkRepository.countByStatusNot(NvdCveSyncChunkStatus.COMPLETED)).thenReturn(1L, 0L);
        // totalResults=2500 across two pages: 2000 (a full page) + 500 (the remainder).
        syncServer.expect(method(HttpMethod.GET))
                .andExpect(requestTo(containsString("startIndex=0")))
                .andRespond(withSuccess(pageJson(2500, manyVulnerabilitiesJson(2000, "CVE-2023-P1-")),
                        MediaType.APPLICATION_JSON));
        syncServer.expect(method(HttpMethod.GET))
                .andExpect(requestTo(containsString("startIndex=2000")))
                .andRespond(withSuccess(pageJson(2500, manyVulnerabilitiesJson(500, "CVE-2023-P2-")),
                        MediaType.APPLICATION_JSON));

        // First tick's budget only allows one page -- the chunk must still be IN_PROGRESS
        // afterward, not COMPLETED, even though only one page has been fetched so far.
        SyncOutcome firstTick = service.runBackfillTickAndRelease(Optional.empty(), new RunBudget(1, Duration.ofMinutes(5)));
        assertThat(firstTick.completed()).isFalse();
        assertThat(chunk.getStatus()).isEqualTo(NvdCveSyncChunkStatus.IN_PROGRESS);
        assertThat(chunk.getNextStartIndex())
                .as("next tick must resume from where the first page left off, not refetch startIndex=0")
                .isEqualTo(2000);

        // Second tick fetches the second (final) page -- its startIndex (asserted above) must equal
        // the first page's own record count, and only now does the chunk complete.
        SyncOutcome secondTick = service.runBackfillTickAndRelease(Optional.empty(), new RunBudget(5, Duration.ofMinutes(5)));

        syncServer.verify();
        assertThat(secondTick.completed()).isTrue();
        assertThat(chunk.getStatus()).isEqualTo(NvdCveSyncChunkStatus.COMPLETED);
        assertThat(chunk.getNextStartIndex()).isEqualTo(2500);
    }

    /** Closed-mode backlog item 202, REVISE round 2, point A: an exception thrown by {@code ingest}
     *  (as opposed to a fetch failure) must fail *that* chunk only, exactly like a fetch failure
     *  does -- not propagate out of {@code processChunkStep} uncaught and abort the whole tick's
     *  remaining budget (which, since {@code next_start_index} is never persisted on that path,
     *  would leave the chunk permanently re-fetching and re-failing on this exact same page). */
    @Test
    void backfillTickFailsAChunkWhoseIngestThrowsButStillProcessesTheNextChunk() {
        when(chunkRepository.count()).thenReturn(1L);
        OffsetDateTime start1 = OffsetDateTime.of(2020, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC);
        NvdCveSyncChunk chunk1 = pendingChunk(start1, start1.plusDays(120));
        OffsetDateTime start2 = start1.plusDays(120);
        NvdCveSyncChunk chunk2 = pendingChunk(start2, start2.plusDays(120));
        chunk2.setId(2L);
        when(chunkRepository.findByStatusNotOrderByWindowStartAsc(NvdCveSyncChunkStatus.COMPLETED))
                .thenReturn(List.of(chunk1, chunk2));
        when(chunkRepository.countByStatusNot(NvdCveSyncChunkStatus.COMPLETED)).thenReturn(1L);
        syncServer.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(pageJson(1, oneVulnerabilityJson("CVE-2023-0010")), MediaType.APPLICATION_JSON));
        syncServer.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(pageJson(1, oneVulnerabilityJson("CVE-2023-0011")), MediaType.APPLICATION_JSON));
        // The first chunk's page fetches fine -- the downstream upsert is what throws -- and this
        // must fail only that chunk, not abort the tick before the second chunk is ever attempted.
        doThrow(new RuntimeException("simulated upsert failure"))
                .doNothing()
                .when(recordRepository).upsertBatch(anyList());

        SyncOutcome outcome = service.runBackfillTickAndRelease(Optional.empty(), new RunBudget(5, Duration.ofMinutes(5)));

        syncServer.verify();
        assertThat(outcome.upserted())
                .as("the failed chunk's page contributes nothing; the second chunk's page still counts")
                .isEqualTo(1);
        assertThat(chunk1.getStatus()).isEqualTo(NvdCveSyncChunkStatus.FAILED);
        assertThat(chunk1.getLastError())
                .as("must record the exception class only, never its message (which could embed a URL)")
                .contains("RuntimeException")
                .doesNotContain("simulated upsert failure");
        assertThat(chunk2.getStatus())
                .as("the second chunk must still be processed even though the first chunk's ingest threw")
                .isEqualTo(NvdCveSyncChunkStatus.COMPLETED);
        verify(recordRepository, times(2)).upsertBatch(anyList());
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

    /** Closed-mode backlog item 202, REVISE round 1, point 3: the very first delta tick after
     *  baseline completion (before {@code last_delta_synced_at} has ever been set) must fall back
     *  to {@code baseline_started_at}, not {@code now.minusDays(1)} -- the latter would leave a
     *  multi-day gap between whatever the backfill's chunk queue was seeded up to and the first
     *  delta tick's own window. */
    @Test
    void deltaTickFallsBackToBaselineStartedAtMinusTheSafetyMarginBeforeAnyDeltaHasEverSynced() {
        NvdCveSyncState state = freshState();
        state.setBaselineCompleted(true);
        OffsetDateTime baselineStartedAt = OffsetDateTime.of(2026, 8, 1, 0, 0, 0, 0, ZoneOffset.UTC);
        state.setBaselineStartedAt(baselineStartedAt);
        // lastDeltaSyncedAt is intentionally left null -- this is the first delta tick ever.
        when(stateRepository.findById((short) 1)).thenReturn(Optional.of(state));
        syncServer.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(pageJson(0, "[]"), MediaType.APPLICATION_JSON));

        service.runDeltaTickAndRelease(Optional.empty(), new RunBudget(5, Duration.ofMinutes(5)));

        syncServer.verify();
        ArgumentCaptor<NvdCveSyncChunk> captor = ArgumentCaptor.forClass(NvdCveSyncChunk.class);
        verify(chunkRepository, atLeastOnce()).save(captor.capture());
        NvdCveSyncChunk enqueuedChunk = captor.getAllValues().get(0);
        assertThat(enqueuedChunk.getWindowStart())
                .as("must fall back to baselineStartedAt (minus the clock-skew safety margin), not "
                        + "now.minusDays(1), which would leave a multi-day gap between the backfill's "
                        + "chunk queue seed time and this first delta tick")
                .isEqualTo(baselineStartedAt.minus(Duration.ofHours(2)));
    }

    /** Closed-mode backlog item 202, REVISE round 2, point B: a delta window whose cursor falls back
     *  to a {@code baseline_started_at} more than {@code WINDOW_DAYS} (120) in the past must have its
     *  {@code window_end} clamped, not left open-ended out to {@code now} -- an uncapped range this
     *  wide exceeds NVD's documented {@code lastModStartDate}/{@code lastModEndDate} max span, and
     *  since a rejected request never advances {@code last_delta_synced_at}, every later tick would
     *  recompute the exact same oversized window and fail identically forever. */
    @Test
    void deltaTickClampsAWindowExceedingNvdsHundredTwentyDayRangeCap() {
        NvdCveSyncState state = freshState();
        state.setBaselineCompleted(true);
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        OffsetDateTime baselineStartedAt = now.minusDays(200);
        state.setBaselineStartedAt(baselineStartedAt);
        when(stateRepository.findById((short) 1)).thenReturn(Optional.of(state));
        syncServer.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(pageJson(0, "[]"), MediaType.APPLICATION_JSON));

        service.runDeltaTickAndRelease(Optional.empty(), new RunBudget(5, Duration.ofMinutes(5)));

        syncServer.verify();
        OffsetDateTime expectedWindowStart = baselineStartedAt.minus(Duration.ofHours(2));
        OffsetDateTime expectedWindowEnd = expectedWindowStart.plusDays(120);

        ArgumentCaptor<NvdCveSyncChunk> captor = ArgumentCaptor.forClass(NvdCveSyncChunk.class);
        verify(chunkRepository, atLeastOnce()).save(captor.capture());
        NvdCveSyncChunk enqueuedChunk = captor.getAllValues().get(0);
        assertThat(enqueuedChunk.getWindowEnd())
                .as("window_end must be clamped to window_start + 120 days, not left open to now")
                .isEqualTo(expectedWindowEnd)
                .isBefore(now);

        assertThat(state.getLastDeltaSyncedAt())
                .as("the high-water mark must advance only to the clamped window end, not all the "
                        + "way to now -- otherwise the clamped-off tail of the range is silently "
                        + "never synced")
                .isEqualTo(expectedWindowEnd);
    }
}
