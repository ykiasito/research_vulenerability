package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.queryParam;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.vulncheck.app.entity.CpeDictionarySyncState;
import com.vulncheck.app.repository.CpeDictionaryRepository;
import com.vulncheck.app.repository.CpeDictionarySyncStateRepository;
import com.vulncheck.app.service.NvdCpeSyncService.SyncOutcome;
import com.vulncheck.app.service.nvd.NvdRateLimiter;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

/**
 * {@link NvdCpeSyncService#tryBeginFullSync} / {@link NvdCpeSyncService#syncAllAndRelease} — the
 * shared full-sync "already running" guard added so {@code AdminController}'s admin-triggered
 * sync and {@code CpeDictionaryBootstrapSync}'s startup-triggered sync can't run concurrently
 * against the same NVD rate limit and {@code cpe_dictionary} table, and {@link
 * NvdCpeSyncService.SyncOutcome#completed}, which lets callers tell a clean finish from an early
 * abort instead of logging both as "finished" (task-backlog item 68 REVISE).
 */
class NvdCpeSyncServiceTest {

    private MockRestServiceServer syncServer;
    private CpeDictionaryRepository cpeDictionaryRepository;
    private CpeDictionarySyncStateRepository cpeDictionarySyncStateRepository;
    private NvdCpeSyncService service;

    @BeforeEach
    void setUp() {
        RestClient externalApiRestClient = RestClient.builder().build();
        RestClient.Builder syncClientBuilder = RestClient.builder();
        syncServer = MockRestServiceServer.bindTo(syncClientBuilder).build();
        cpeDictionaryRepository = mock(CpeDictionaryRepository.class);
        cpeDictionarySyncStateRepository = mock(CpeDictionarySyncStateRepository.class);
        service = new NvdCpeSyncService(externalApiRestClient, syncClientBuilder.build(), cpeDictionaryRepository,
                new NvdRateLimiter(), cpeDictionarySyncStateRepository);
    }

    @Test
    void tryBeginFullSyncReturnsFalseWhileASlotIsAlreadyHeld() {
        assertThat(service.tryBeginFullSync()).isTrue();
        assertThat(service.tryBeginFullSync())
                .as("a second caller must not be able to acquire the slot while the first still holds it")
                .isFalse();
    }

    @Test
    void syncAllAndReleaseFreesTheSlotOnNormalCompletion() {
        assertThat(service.tryBeginFullSync()).isTrue();
        syncServer.expect(method(HttpMethod.GET))
                .andRespond(withSuccess("{\"totalResults\":0,\"products\":[]}", MediaType.APPLICATION_JSON));

        SyncOutcome outcome = service.syncAllAndRelease(Optional.empty());

        assertThat(outcome.upserted()).isZero();
        assertThat(outcome.completed()).isTrue();
        assertThat(service.tryBeginFullSync())
                .as("the slot must be free again after a normal completion")
                .isTrue();
        syncServer.verify();
    }

    @Test
    void syncAllAndReleaseFreesTheSlotEvenWhenTheSyncThrows() {
        assertThat(service.tryBeginFullSync()).isTrue();
        syncServer.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(
                        "{\"totalResults\":1,\"products\":[{\"cpe\":{\"cpeName\":"
                                + "\"cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*\",\"titles\":[]}}]}",
                        MediaType.APPLICATION_JSON));
        doThrow(new RuntimeException("db down")).when(cpeDictionaryRepository).upsertBatch(anyList());

        assertThatThrownBy(() -> service.syncAllAndRelease(Optional.empty()))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("db down");

        assertThat(service.tryBeginFullSync())
                .as("the slot must be free again even when the sync itself throws")
                .isTrue();
        syncServer.verify();
    }

    @Test
    void releaseFullSyncGuardFreesTheSlotWithoutRunningASync() {
        // Stand-in for a caller whose worker-thread spawn/start itself failed after winning the
        // slot: syncAllAndRelease() (and its own finally-release) never runs, so this method is
        // the only way the slot gets freed again (task-backlog items 81/136/141).
        assertThat(service.tryBeginFullSync()).isTrue();

        service.releaseFullSyncGuard();

        assertThat(service.tryBeginFullSync())
                .as("the slot must be free again after an explicit release")
                .isTrue();
    }

    @Test
    void encodesCsvSuppliedKeywordCharactersInTheQueryStringToPreventParameterInjection() {
        // Backlog item 253 (senior review, 2026-09-03, PR#158 follow-up): keyword is the
        // CSV-supplied product name (see Stage1IdentificationService#syncKeywordSinglePage and
        // AdminController#syncByKeyword), and fetchPage() used to build the query string without
        // UriComponentsBuilder#encode() -- a product cell containing "&resultsPerPage=1" would
        // inject its own resultsPerPage ahead of the real one. Same class of bug as
        // NvdVulnerabilitySource's cpeName case (PR#163); confirms the "&" stays percent-encoded
        // (%26) and resultsPerPage keeps the app's real value.
        syncServer.expect(method(HttpMethod.GET))
                .andExpect(requestTo(Matchers.containsString("%26")))
                .andExpect(queryParam("resultsPerPage", "10000"))
                .andRespond(withSuccess("{\"totalResults\":0,\"products\":[]}", MediaType.APPLICATION_JSON));

        int upserted = service.syncByKeyword("apache&resultsPerPage=1", Optional.empty());

        assertThat(upserted).isZero();
        syncServer.verify();
    }

    // Balanced-brace/unbalanced-brace/literal-"%"/literal-"+" encoding edge cases used to be
    // duplicated here (and in NvdVulnerabilitySourceTest/NvdKeywordVulnerabilitySourceTest) --
    // exactly the maintenance problem task-backlog item 254 exists to fix. They now live once,
    // generically, in NvdUriBuilderTest; the ampersand-injection test above stays here as this call
    // site's own end-to-end smoke test that the shared builder is actually wired in and reaches the
    // real MockRestServiceServer request.

    @Test
    void syncReportsIncompleteWhenAPageFetchFailsPartWayThrough() {
        // fetchPage() treats a failed HTTP request as an empty result (caught, logged, returns
        // null) rather than throwing — sync() must not report that as a clean finish, since the
        // dictionary is then only partially synced (the bug this fix addresses: both a clean
        // finish and an early abort used to log identically as "finished").
        syncServer.expect(method(HttpMethod.GET)).andRespond(withServerError());

        SyncOutcome outcome = service.syncAllAndRelease(Optional.empty());

        assertThat(outcome.completed()).isFalse();
        syncServer.verify();
    }

    @Test
    void syncReportsIncompleteWhenAPageReportsResultsButReturnsNoProducts() {
        // Regression test for senior-reviewer REVISE (PR #207 round 1): NVD returning a 2xx
        // response whose totalResults says there's more to fetch, but whose products array is
        // empty, used to be treated identically to a legitimate "no more pages" signal (fetched ==
        // 0) -- silently recording this partial dictionary as a clean finish and, for an unfiltered
        // sync, advancing cpe_dictionary_sync_state past a window that was never actually ingested.
        syncServer.expect(method(HttpMethod.GET))
                .andRespond(withSuccess("{\"totalResults\":500,\"products\":[]}", MediaType.APPLICATION_JSON));

        SyncOutcome outcome = service.syncAllAndRelease(Optional.empty());

        assertThat(outcome.completed()).isFalse();
        verify(cpeDictionarySyncStateRepository, never()).save(any());
        syncServer.verify();
    }

    // --- closed-mode backlog item 283: delta sync -------------------------------------------

    @Test
    void hasCompletedInitialSyncReflectsPersistedState() {
        when(cpeDictionarySyncStateRepository.findById((short) 1)).thenReturn(Optional.empty());
        assertThat(service.hasCompletedInitialSync()).isFalse();

        CpeDictionarySyncState state = new CpeDictionarySyncState();
        state.setInitialSyncCompleted(true);
        when(cpeDictionarySyncStateRepository.findById((short) 1)).thenReturn(Optional.of(state));

        assertThat(service.hasCompletedInitialSync()).isTrue();
    }

    @Test
    void syncAllAndReleaseRecordsInitialSyncCompletedOnCleanFinish() {
        syncServer.expect(method(HttpMethod.GET))
                .andRespond(withSuccess("{\"totalResults\":0,\"products\":[]}", MediaType.APPLICATION_JSON));

        service.syncAllAndRelease(Optional.empty());

        ArgumentCaptor<CpeDictionarySyncState> captor = ArgumentCaptor.forClass(CpeDictionarySyncState.class);
        verify(cpeDictionarySyncStateRepository).save(captor.capture());
        assertThat(captor.getValue().isInitialSyncCompleted()).isTrue();
        assertThat(captor.getValue().getLastSyncedAt()).isNotNull();
        syncServer.verify();
    }

    @Test
    void syncAllAndReleaseDoesNotRecordStateOnEarlyAbort() {
        // An aborted-early full sync must not flip hasCompletedInitialSync() true -- the
        // dictionary is only partially synced, so the next scheduled run must still retry a full
        // sync, not switch to delta against an incomplete baseline.
        syncServer.expect(method(HttpMethod.GET)).andRespond(withServerError());

        service.syncAllAndRelease(Optional.empty());

        verify(cpeDictionarySyncStateRepository, never()).save(any());
    }

    @Test
    void syncByKeywordDoesNotRecordSyncState() {
        // A keyword-filtered sync only ever touches a subset of the dictionary -- it must never be
        // mistaken for "the whole dictionary is now this fresh".
        syncServer.expect(method(HttpMethod.GET))
                .andRespond(withSuccess("{\"totalResults\":0,\"products\":[]}", MediaType.APPLICATION_JSON));

        service.syncByKeyword("apache", Optional.empty());

        verify(cpeDictionarySyncStateRepository, never()).save(any());
    }

    @Test
    void syncDeltaAndReleaseIncludesLastModDateRangeQueryParams() {
        OffsetDateTime cursor = OffsetDateTime.now(ZoneOffset.UTC).minusDays(3);
        CpeDictionarySyncState state = new CpeDictionarySyncState();
        state.setInitialSyncCompleted(true);
        state.setLastSyncedAt(cursor);
        when(cpeDictionarySyncStateRepository.findById((short) 1)).thenReturn(Optional.of(state));

        syncServer.expect(method(HttpMethod.GET))
                .andExpect(requestTo(Matchers.containsString("lastModStartDate=")))
                .andExpect(requestTo(Matchers.containsString("lastModEndDate=")))
                .andRespond(withSuccess("{\"totalResults\":0,\"products\":[]}", MediaType.APPLICATION_JSON));

        SyncOutcome outcome = service.syncDeltaAndRelease(Optional.empty());

        assertThat(outcome.completed()).isTrue();
        syncServer.verify();
    }

    @Test
    void syncDeltaAndReleaseRecordsTheRequestedWindowEndAsTheNewCursorNotWallClockNow() {
        // Regression guard for the "chunk's own window_end, not now" rule NvdCveSyncService's
        // delta side follows: if the recorded cursor were wall-clock "now" instead of the actual
        // requested lastModEndDate, a clamped/partial window's untraveled tail would be silently
        // skipped on the next tick.
        OffsetDateTime cursor = OffsetDateTime.now(ZoneOffset.UTC).minusDays(3);
        CpeDictionarySyncState state = new CpeDictionarySyncState();
        state.setInitialSyncCompleted(true);
        state.setLastSyncedAt(cursor);
        when(cpeDictionarySyncStateRepository.findById((short) 1)).thenReturn(Optional.of(state));

        syncServer.expect(method(HttpMethod.GET))
                .andRespond(withSuccess("{\"totalResults\":0,\"products\":[]}", MediaType.APPLICATION_JSON));

        service.syncDeltaAndRelease(Optional.empty());

        ArgumentCaptor<CpeDictionarySyncState> captor = ArgumentCaptor.forClass(CpeDictionarySyncState.class);
        verify(cpeDictionarySyncStateRepository).save(captor.capture());
        OffsetDateTime recordedCursor = captor.getValue().getLastSyncedAt();
        // windowEnd == now here (uncapped, since cursor is only 3 days old) -- assert it lands
        // close to "now", not exactly equal to the pre-call cursor (i.e. it actually advanced).
        assertThat(recordedCursor).isAfter(cursor);
        assertThat(Duration.between(recordedCursor, OffsetDateTime.now(ZoneOffset.UTC)).abs())
                .isLessThan(Duration.ofMinutes(1));
    }

    @Test
    void syncDeltaAndReleaseClampsTheWindowToNvdsMaximumSpanWhenTheCursorIsVeryStale() {
        // NVD's documented lastModStartDate/lastModEndDate max span is 120 days -- a cursor far
        // older than that (e.g. the scheduler was disabled for months) must not produce an
        // out-of-range request; the recorded cursor should advance by roughly 120 days, not jump
        // straight to "now".
        OffsetDateTime cursor = OffsetDateTime.now(ZoneOffset.UTC).minusDays(200);
        CpeDictionarySyncState state = new CpeDictionarySyncState();
        state.setInitialSyncCompleted(true);
        state.setLastSyncedAt(cursor);
        when(cpeDictionarySyncStateRepository.findById((short) 1)).thenReturn(Optional.of(state));

        syncServer.expect(method(HttpMethod.GET))
                .andRespond(withSuccess("{\"totalResults\":0,\"products\":[]}", MediaType.APPLICATION_JSON));

        service.syncDeltaAndRelease(Optional.empty());

        ArgumentCaptor<CpeDictionarySyncState> captor = ArgumentCaptor.forClass(CpeDictionarySyncState.class);
        verify(cpeDictionarySyncStateRepository).save(captor.capture());
        OffsetDateTime recordedCursor = captor.getValue().getLastSyncedAt();
        assertThat(recordedCursor).isBefore(OffsetDateTime.now(ZoneOffset.UTC).minusDays(50));
        assertThat(Duration.between(cursor, recordedCursor)).isLessThanOrEqualTo(Duration.ofDays(121));
    }

    @Test
    void syncDeltaAndReleaseFallsBackToLastWeekWhenNoCursorIsRecorded() {
        // Defensive fallback: hasCompletedInitialSync() true but last_synced_at somehow still null
        // must not throw or silently sync nothing -- it should still page through a bounded window.
        when(cpeDictionarySyncStateRepository.findById((short) 1)).thenReturn(Optional.empty());

        syncServer.expect(method(HttpMethod.GET))
                .andRespond(withSuccess("{\"totalResults\":0,\"products\":[]}", MediaType.APPLICATION_JSON));

        SyncOutcome outcome = service.syncDeltaAndRelease(Optional.empty());

        assertThat(outcome.completed()).isTrue();
        syncServer.verify();
    }

    @Test
    void syncDeltaAndReleaseFreesTheGuardSlotOnCompletion() {
        assertThat(service.tryBeginFullSync()).isTrue();
        syncServer.expect(method(HttpMethod.GET))
                .andRespond(withSuccess("{\"totalResults\":0,\"products\":[]}", MediaType.APPLICATION_JSON));

        service.syncDeltaAndRelease(Optional.empty());

        assertThat(service.tryBeginFullSync())
                .as("the slot must be free again after a normal delta completion")
                .isTrue();
    }

    // --- closed-mode backlog item 330 (A): blank keyword must never fall through to an unfiltered
    // full sync ---------------------------------------------------------------------------------

    @Test
    void syncByKeywordRejectsNullKeywordWithoutMakingAnyRequest() {
        assertThatThrownBy(() -> service.syncByKeyword(null, Optional.empty()))
                .isInstanceOf(IllegalArgumentException.class);
        syncServer.verify();
    }

    @Test
    void syncByKeywordRejectsEmptyKeywordWithoutMakingAnyRequest() {
        assertThatThrownBy(() -> service.syncByKeyword("", Optional.empty()))
                .isInstanceOf(IllegalArgumentException.class);
        syncServer.verify();
    }

    @Test
    void syncByKeywordRejectsWhitespaceOnlyKeywordWithoutMakingAnyRequest() {
        assertThatThrownBy(() -> service.syncByKeyword("   ", Optional.empty()))
                .isInstanceOf(IllegalArgumentException.class);
        syncServer.verify();
    }

    @Test
    void syncKeywordSinglePageRejectsBlankKeywordWithoutMakingAnyRequest() {
        assertThatThrownBy(() -> service.syncKeywordSinglePage("  ", 1, Optional.empty()))
                .isInstanceOf(IllegalArgumentException.class);
        syncServer.verify();
    }

    @Test
    void syncDeltaAndReleaseFreesTheGuardSlotEvenWhenTheSyncThrows() {
        assertThat(service.tryBeginFullSync()).isTrue();
        syncServer.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(
                        "{\"totalResults\":1,\"products\":[{\"cpe\":{\"cpeName\":"
                                + "\"cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*\",\"titles\":[]}}]}",
                        MediaType.APPLICATION_JSON));
        doThrow(new RuntimeException("db down")).when(cpeDictionaryRepository).upsertBatch(anyList());

        assertThatThrownBy(() -> service.syncDeltaAndRelease(Optional.empty()))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("db down");

        assertThat(service.tryBeginFullSync())
                .as("the slot must be free again even when the delta sync itself throws")
                .isTrue();
    }
}
