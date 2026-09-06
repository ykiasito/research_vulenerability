package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.vulncheck.app.service.NvdCpeSyncService.SyncOutcome;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Unit coverage for {@link CpeDictionaryScheduledResync} — the {@code enabled} gate, the
 * concurrency guard hand-off with {@link NvdCpeSyncService#tryBeginFullSync}, and the
 * completed-vs-aborted-early outcome handling. {@link NvdCpeSyncService} itself is mocked: its own
 * guard/pagination behavior is covered by {@code NvdCpeSyncServiceTest}, so this class only needs
 * to verify that the scheduler calls it correctly and reacts correctly to what it returns.
 */
class CpeDictionaryScheduledResyncTest {

    private final NvdCpeSyncService nvdCpeSyncService = mock(NvdCpeSyncService.class);
    private final UserApiKeyService userApiKeyService = mock(UserApiKeyService.class);
    private final CpeDictionaryScheduledResync resync =
            new CpeDictionaryScheduledResync(nvdCpeSyncService, userApiKeyService);

    @Test
    void disabledByDefaultSkipsEntirelyWithoutTouchingTheGuard() {
        ReflectionTestUtils.setField(resync, "enabled", false);

        resync.resyncWeekly();

        verifyNoInteractions(nvdCpeSyncService);
    }

    @Test
    void enabledButAnotherFullSyncAlreadyRunningSkipsWithoutStartingASecondOne() {
        ReflectionTestUtils.setField(resync, "enabled", true);
        when(nvdCpeSyncService.tryBeginFullSync()).thenReturn(false);

        resync.resyncWeekly();

        verify(nvdCpeSyncService, times(1)).tryBeginFullSync();
        verify(nvdCpeSyncService, never()).syncAllAndRelease(Optional.empty());
    }

    @Test
    void enabledAndGuardWonRunsTheSyncOnAWorkerThread() throws InterruptedException {
        ReflectionTestUtils.setField(resync, "enabled", true);
        when(nvdCpeSyncService.tryBeginFullSync()).thenReturn(true);
        when(userApiKeyService.getAdminNvdApiKey()).thenReturn(Optional.empty());
        CountDownLatch syncInvoked = new CountDownLatch(1);
        when(nvdCpeSyncService.syncAllAndRelease(Optional.empty())).thenAnswer(invocation -> {
            syncInvoked.countDown();
            return new SyncOutcome(42, true);
        });

        resync.resyncWeekly();

        assertThat(syncInvoked.await(5, TimeUnit.SECONDS))
                .as("syncAllAndRelease should be invoked on the spawned worker thread")
                .isTrue();
        verify(nvdCpeSyncService, times(1)).tryBeginFullSync();
    }

    @Test
    void resyncWeeklyReleasesTheGuardWhenTheWorkerThreadFailsToStart() {
        // Regression test for task-backlog item 141: if starting the worker thread itself throws
        // (e.g. native-thread exhaustion) after tryBeginFullSync() already won the slot,
        // syncAllAndRelease()'s own finally-release never runs — resyncWeekly() must release the
        // guard itself instead of leaving fullSyncRunning stuck true until a restart.
        CpeDictionaryScheduledResync spyResync = spy(resync);
        ReflectionTestUtils.setField(spyResync, "enabled", true);
        when(nvdCpeSyncService.tryBeginFullSync()).thenReturn(true);
        doThrow(new RuntimeException("unable to create native thread")).when(spyResync).startWorker();

        spyResync.resyncWeekly();

        verify(nvdCpeSyncService, times(1)).releaseFullSyncGuard();
        verify(nvdCpeSyncService, never()).syncAllAndRelease(Optional.empty());
    }

    @Test
    void runScheduledResyncReleasesTheGuardWhenHasCompletedInitialSyncThrows() {
        // Regression test for senior-reviewer REVISE (PR #207 round 1): hasCompletedInitialSync()
        // is an unguarded JPA read running on the worker thread after tryBeginFullSync() already
        // won the slot. If it throws (a transient DB hiccup), runScheduledResync() must release the
        // guard itself -- neither syncAllAndRelease() nor syncDeltaAndRelease() would ever be
        // reached to do it via their own finally blocks, reintroducing the task-backlog items
        // 81/136/141 guard-leak failure mode. No full-sync fallback: this week's resync is simply
        // skipped and retried next week.
        when(nvdCpeSyncService.hasCompletedInitialSync())
                .thenThrow(new IllegalStateException("connection pool exhausted"));

        resync.runScheduledResync();

        verify(nvdCpeSyncService, times(1)).releaseFullSyncGuard();
        verify(nvdCpeSyncService, never()).syncAllAndRelease(any());
        verify(nvdCpeSyncService, never()).syncDeltaAndRelease(any());
    }

    @Test
    void runFullSyncLogsCompletedOutcomeWithoutThrowing() {
        when(userApiKeyService.getAdminNvdApiKey()).thenReturn(Optional.empty());
        when(nvdCpeSyncService.syncAllAndRelease(Optional.empty())).thenReturn(new SyncOutcome(1815263, true));

        resync.runFullSync();

        verify(nvdCpeSyncService, times(1)).syncAllAndRelease(Optional.empty());
    }

    @Test
    void runFullSyncLogsAbortedEarlyOutcomeWithoutThrowing() {
        when(userApiKeyService.getAdminNvdApiKey()).thenReturn(Optional.empty());
        when(nvdCpeSyncService.syncAllAndRelease(Optional.empty())).thenReturn(new SyncOutcome(500000, false));

        resync.runFullSync();

        verify(nvdCpeSyncService, times(1)).syncAllAndRelease(Optional.empty());
    }

    @Test
    void runFullSyncSwallowsAnExceptionFromSyncAllAndReleaseRatherThanPropagatingIt() {
        when(userApiKeyService.getAdminNvdApiKey()).thenReturn(Optional.empty());
        when(nvdCpeSyncService.syncAllAndRelease(Optional.empty())).thenThrow(new RuntimeException("NVD unreachable"));

        resync.runFullSync();

        verify(nvdCpeSyncService, times(1)).syncAllAndRelease(Optional.empty());
    }

    @Test
    void runFullSyncFallsBackToUnkeyedAndStillReleasesTheGuardWhenAdminKeyResolutionThrows() {
        // Regression test for task-backlog item 143: getAdminNvdApiKey() throwing (e.g. a decrypt
        // failure) must not prevent syncAllAndRelease() from being reached — that call's own
        // finally-block is the only place the fullSyncRunning guard gets released, so skipping it
        // would leak the guard until process restart, exactly the item 136/141 bug PR #82
        // reintroduced.
        when(userApiKeyService.getAdminNvdApiKey())
                .thenThrow(new IllegalStateException("Failed to decrypt secret"));
        when(nvdCpeSyncService.syncAllAndRelease(Optional.empty())).thenReturn(new SyncOutcome(0, true));

        resync.runFullSync();

        verify(nvdCpeSyncService, times(1)).syncAllAndRelease(Optional.empty());
    }

    @Test
    void runFullSyncPassesTheAdminNvdKeyThroughWhenOneIsConfigured() {
        // Regression test for task-backlog item 142: the scheduled resync must use whatever
        // UserApiKeyService#getAdminNvdApiKey() resolves — an unkeyed weekly run is ~10x slower
        // due to NVD's unkeyed 5 req/30s rate limit.
        when(userApiKeyService.getAdminNvdApiKey()).thenReturn(Optional.of("admin-nvd-key"));
        when(nvdCpeSyncService.syncAllAndRelease(Optional.of("admin-nvd-key")))
                .thenReturn(new SyncOutcome(1815263, true));

        resync.runFullSync();

        verify(nvdCpeSyncService, times(1)).syncAllAndRelease(Optional.of("admin-nvd-key"));
    }

    // --- closed-mode backlog item 283: full vs. delta dispatch -----------------------------

    @Test
    void runScheduledResyncRunsAFullSyncWhenTheInitialSyncHasNotCompletedYet() {
        when(nvdCpeSyncService.hasCompletedInitialSync()).thenReturn(false);
        when(userApiKeyService.getAdminNvdApiKey()).thenReturn(Optional.empty());
        when(nvdCpeSyncService.syncAllAndRelease(Optional.empty())).thenReturn(new SyncOutcome(1815263, true));

        resync.runScheduledResync();

        verify(nvdCpeSyncService, times(1)).syncAllAndRelease(Optional.empty());
        verify(nvdCpeSyncService, never()).syncDeltaAndRelease(Optional.empty());
    }

    @Test
    void runScheduledResyncRunsADeltaSyncWhenTheInitialSyncHasAlreadyCompleted() {
        when(nvdCpeSyncService.hasCompletedInitialSync()).thenReturn(true);
        when(userApiKeyService.getAdminNvdApiKey()).thenReturn(Optional.empty());
        when(nvdCpeSyncService.syncDeltaAndRelease(Optional.empty())).thenReturn(new SyncOutcome(120, true));

        resync.runScheduledResync();

        verify(nvdCpeSyncService, times(1)).syncDeltaAndRelease(Optional.empty());
        verify(nvdCpeSyncService, never()).syncAllAndRelease(Optional.empty());
    }

    @Test
    void runDeltaSyncLogsCompletedOutcomeWithoutThrowing() {
        when(userApiKeyService.getAdminNvdApiKey()).thenReturn(Optional.empty());
        when(nvdCpeSyncService.syncDeltaAndRelease(Optional.empty())).thenReturn(new SyncOutcome(120, true));

        resync.runDeltaSync();

        verify(nvdCpeSyncService, times(1)).syncDeltaAndRelease(Optional.empty());
    }

    @Test
    void runDeltaSyncLogsAbortedEarlyOutcomeWithoutThrowing() {
        when(userApiKeyService.getAdminNvdApiKey()).thenReturn(Optional.empty());
        when(nvdCpeSyncService.syncDeltaAndRelease(Optional.empty())).thenReturn(new SyncOutcome(30, false));

        resync.runDeltaSync();

        verify(nvdCpeSyncService, times(1)).syncDeltaAndRelease(Optional.empty());
    }

    @Test
    void runDeltaSyncSwallowsAnExceptionFromSyncDeltaAndReleaseRatherThanPropagatingIt() {
        when(userApiKeyService.getAdminNvdApiKey()).thenReturn(Optional.empty());
        when(nvdCpeSyncService.syncDeltaAndRelease(Optional.empty())).thenThrow(new RuntimeException("NVD unreachable"));

        resync.runDeltaSync();

        verify(nvdCpeSyncService, times(1)).syncDeltaAndRelease(Optional.empty());
    }

    @Test
    void runDeltaSyncFallsBackToUnkeyedWhenAdminKeyResolutionThrows() {
        when(userApiKeyService.getAdminNvdApiKey())
                .thenThrow(new IllegalStateException("Failed to decrypt secret"));
        when(nvdCpeSyncService.syncDeltaAndRelease(Optional.empty())).thenReturn(new SyncOutcome(0, true));

        resync.runDeltaSync();

        verify(nvdCpeSyncService, times(1)).syncDeltaAndRelease(Optional.empty());
    }

    @Test
    void runDeltaSyncPassesTheAdminNvdKeyThroughWhenOneIsConfigured() {
        when(userApiKeyService.getAdminNvdApiKey()).thenReturn(Optional.of("admin-nvd-key"));
        when(nvdCpeSyncService.syncDeltaAndRelease(Optional.of("admin-nvd-key")))
                .thenReturn(new SyncOutcome(120, true));

        resync.runDeltaSync();

        verify(nvdCpeSyncService, times(1)).syncDeltaAndRelease(Optional.of("admin-nvd-key"));
    }
}
