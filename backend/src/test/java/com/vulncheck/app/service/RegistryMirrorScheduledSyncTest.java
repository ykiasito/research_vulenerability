package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.vulncheck.app.service.registry.RegistryMirrorSyncService;
import com.vulncheck.app.service.registry.RegistryMirrorSyncService.SyncOutcome;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Unit coverage for {@link RegistryMirrorScheduledSync} — the {@code enabled} gate, the
 * concurrency guard hand-off with {@link RegistryMirrorSyncService#tryBeginFullSync}, and outcome
 * logging. {@link RegistryMirrorSyncService} itself is mocked: its own per-ecosystem sync behavior
 * is covered by {@code RegistryMirrorSyncServiceTest}, so this class only needs to verify that the
 * scheduler calls it correctly. Same structure as {@code CpeDictionaryScheduledResyncTest}.
 */
class RegistryMirrorScheduledSyncTest {

    private final RegistryMirrorSyncService registryMirrorSyncService = mock(RegistryMirrorSyncService.class);
    private final RegistryMirrorScheduledSync resync = new RegistryMirrorScheduledSync(registryMirrorSyncService);

    @Test
    void disabledByDefaultSkipsEntirelyWithoutTouchingTheGuard() {
        ReflectionTestUtils.setField(resync, "enabled", false);

        resync.resyncWeekly();

        verifyNoInteractions(registryMirrorSyncService);
    }

    @Test
    void enabledButAnotherSyncAlreadyRunningSkipsWithoutStartingASecondOne() {
        ReflectionTestUtils.setField(resync, "enabled", true);
        when(registryMirrorSyncService.tryBeginFullSync()).thenReturn(false);

        resync.resyncWeekly();

        verify(registryMirrorSyncService, times(1)).tryBeginFullSync();
        verify(registryMirrorSyncService, never()).syncAllAndRelease();
    }

    @Test
    void enabledAndGuardWonRunsTheSyncOnAWorkerThread() throws InterruptedException {
        ReflectionTestUtils.setField(resync, "enabled", true);
        when(registryMirrorSyncService.tryBeginFullSync()).thenReturn(true);
        CountDownLatch syncInvoked = new CountDownLatch(1);
        when(registryMirrorSyncService.syncAllAndRelease()).thenAnswer(invocation -> {
            syncInvoked.countDown();
            return new SyncOutcome(10, 1, Map.of("npm", 11));
        });

        resync.resyncWeekly();

        assertThat(syncInvoked.await(5, TimeUnit.SECONDS))
                .as("syncAllAndRelease should be invoked on the spawned worker thread")
                .isTrue();
        verify(registryMirrorSyncService, times(1)).tryBeginFullSync();
    }

    @Test
    void resyncWeeklyReleasesTheGuardWhenTheWorkerThreadFailsToStart() {
        RegistryMirrorScheduledSync spyResync = spy(resync);
        ReflectionTestUtils.setField(spyResync, "enabled", true);
        when(registryMirrorSyncService.tryBeginFullSync()).thenReturn(true);
        doThrow(new RuntimeException("unable to create native thread")).when(spyResync).startWorker();

        spyResync.resyncWeekly();

        verify(registryMirrorSyncService, times(1)).releaseFullSyncGuard();
        verify(registryMirrorSyncService, never()).syncAllAndRelease();
    }

    @Test
    void runFullSyncLogsOutcomeWithoutThrowing() {
        when(registryMirrorSyncService.syncAllAndRelease()).thenReturn(new SyncOutcome(1234, 56, Map.of("npm", 1290)));

        resync.runFullSync();

        verify(registryMirrorSyncService, times(1)).syncAllAndRelease();
    }

    @Test
    void runFullSyncSwallowsAnExceptionFromSyncAllAndReleaseRatherThanPropagatingIt() {
        when(registryMirrorSyncService.syncAllAndRelease()).thenThrow(new RuntimeException("registry unreachable"));

        resync.runFullSync();

        verify(registryMirrorSyncService, times(1)).syncAllAndRelease();
    }
}
