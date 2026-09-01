package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
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
    private final CpeDictionaryScheduledResync resync = new CpeDictionaryScheduledResync(nvdCpeSyncService);

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
    void runFullSyncLogsCompletedOutcomeWithoutThrowing() {
        when(nvdCpeSyncService.syncAllAndRelease(Optional.empty())).thenReturn(new SyncOutcome(1815263, true));

        resync.runFullSync();

        verify(nvdCpeSyncService, times(1)).syncAllAndRelease(Optional.empty());
    }

    @Test
    void runFullSyncLogsAbortedEarlyOutcomeWithoutThrowing() {
        when(nvdCpeSyncService.syncAllAndRelease(Optional.empty())).thenReturn(new SyncOutcome(500000, false));

        resync.runFullSync();

        verify(nvdCpeSyncService, times(1)).syncAllAndRelease(Optional.empty());
    }

    @Test
    void runFullSyncSwallowsAnExceptionFromSyncAllAndReleaseRatherThanPropagatingIt() {
        when(nvdCpeSyncService.syncAllAndRelease(Optional.empty())).thenThrow(new RuntimeException("NVD unreachable"));

        resync.runFullSync();

        verify(nvdCpeSyncService, times(1)).syncAllAndRelease(Optional.empty());
    }
}
