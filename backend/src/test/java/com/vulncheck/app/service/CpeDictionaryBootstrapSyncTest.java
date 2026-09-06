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

import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.boot.ApplicationArguments;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Unit coverage for {@link CpeDictionaryBootstrapSync} — the {@code enabled} gate, the
 * concurrency guard hand-off with {@link NvdCpeSyncService#tryBeginFullSync}, and (task-backlog
 * item 136) the guard-release path when starting the worker thread itself fails. {@link
 * NvdCpeSyncService} itself is mocked: its own guard/pagination behavior is covered by {@code
 * NvdCpeSyncServiceTest}, so this class only needs to verify that the runner calls it correctly.
 */
class CpeDictionaryBootstrapSyncTest {

    private final NvdCpeSyncService nvdCpeSyncService = mock(NvdCpeSyncService.class);
    private final UserApiKeyService userApiKeyService = mock(UserApiKeyService.class);
    private final CpeDictionaryBootstrapSync bootstrapSync =
            new CpeDictionaryBootstrapSync(nvdCpeSyncService, userApiKeyService);
    private final ApplicationArguments args = mock(ApplicationArguments.class);

    @Test
    void disabledByDefaultSkipsEntirelyWithoutTouchingTheGuard() {
        ReflectionTestUtils.setField(bootstrapSync, "enabled", false);

        bootstrapSync.run(args);

        verifyNoInteractions(nvdCpeSyncService);
    }

    @Test
    void enabledButAnotherFullSyncAlreadyRunningSkipsWithoutStartingASecondOne() {
        ReflectionTestUtils.setField(bootstrapSync, "enabled", true);
        when(nvdCpeSyncService.tryBeginFullSync()).thenReturn(false);

        bootstrapSync.run(args);

        verify(nvdCpeSyncService, times(1)).tryBeginFullSync();
        verify(nvdCpeSyncService, never()).syncAllAndRelease(Optional.empty());
    }

    @Test
    void enabledAndGuardWonRunsTheSyncOnAWorkerThread() throws InterruptedException {
        ReflectionTestUtils.setField(bootstrapSync, "enabled", true);
        when(nvdCpeSyncService.tryBeginFullSync()).thenReturn(true);
        CountDownLatch syncInvoked = new CountDownLatch(1);
        when(nvdCpeSyncService.syncAllAndRelease(Optional.empty())).thenAnswer(invocation -> {
            syncInvoked.countDown();
            return new NvdCpeSyncService.SyncOutcome(42, true);
        });

        bootstrapSync.run(args);

        assertThat(syncInvoked.await(5, TimeUnit.SECONDS))
                .as("syncAllAndRelease should be invoked on the spawned worker thread")
                .isTrue();
        verify(nvdCpeSyncService, times(1)).tryBeginFullSync();
    }

    @Test
    void enabledAndGuardWonPassesTheAdminNvdApiKeyWhenOneIsRegistered() throws InterruptedException {
        // Closed-mode backlog item 392: the startup full sync was previously hardcoded to
        // Optional.empty() (always unkeyed), unlike its scheduled twin (CpeDictionaryScheduledResync).
        ReflectionTestUtils.setField(bootstrapSync, "enabled", true);
        when(nvdCpeSyncService.tryBeginFullSync()).thenReturn(true);
        when(userApiKeyService.getAdminNvdApiKey()).thenReturn(Optional.of("admin-nvd-key"));
        CountDownLatch syncInvoked = new CountDownLatch(1);
        when(nvdCpeSyncService.syncAllAndRelease(Optional.of("admin-nvd-key"))).thenAnswer(invocation -> {
            syncInvoked.countDown();
            return new NvdCpeSyncService.SyncOutcome(42, true);
        });

        bootstrapSync.run(args);

        assertThat(syncInvoked.await(5, TimeUnit.SECONDS)).isTrue();
        verify(nvdCpeSyncService).syncAllAndRelease(Optional.of("admin-nvd-key"));
    }

    @Test
    void enabledAndGuardWonFallsBackToUnkeyedWhenAdminKeyResolutionThrows() throws InterruptedException {
        // Same fail-soft rationale as CpeDictionaryScheduledResync#resolveAdminKey: a decrypt
        // failure must never prevent syncAllAndRelease (and its guard-releasing finally) from
        // being reached.
        ReflectionTestUtils.setField(bootstrapSync, "enabled", true);
        when(nvdCpeSyncService.tryBeginFullSync()).thenReturn(true);
        when(userApiKeyService.getAdminNvdApiKey()).thenThrow(new RuntimeException("decrypt failed"));
        CountDownLatch syncInvoked = new CountDownLatch(1);
        when(nvdCpeSyncService.syncAllAndRelease(Optional.empty())).thenAnswer(invocation -> {
            syncInvoked.countDown();
            return new NvdCpeSyncService.SyncOutcome(42, true);
        });

        bootstrapSync.run(args);

        assertThat(syncInvoked.await(5, TimeUnit.SECONDS)).isTrue();
        verify(nvdCpeSyncService).syncAllAndRelease(Optional.empty());
    }

    @Test
    void runReleasesTheGuardWhenTheWorkerThreadFailsToStart() {
        // Regression test for task-backlog item 136: if starting the worker thread itself throws
        // (e.g. native-thread exhaustion) after tryBeginFullSync() already won the slot,
        // syncAllAndRelease()'s own finally-release never runs — run() must release the guard
        // itself instead of leaving fullSyncRunning stuck true until a restart.
        CpeDictionaryBootstrapSync spyBootstrapSync = spy(bootstrapSync);
        ReflectionTestUtils.setField(spyBootstrapSync, "enabled", true);
        when(nvdCpeSyncService.tryBeginFullSync()).thenReturn(true);
        doThrow(new RuntimeException("unable to create native thread")).when(spyBootstrapSync).startWorker();

        spyBootstrapSync.run(args);

        verify(nvdCpeSyncService, times(1)).releaseFullSyncGuard();
        verify(nvdCpeSyncService, never()).syncAllAndRelease(Optional.empty());
    }

    // --- closed-mode backlog item 330 (C): freshness gate ---------------------------------------

    @Test
    void freshMirrorWithinTheConfiguredWindowSkipsWithoutEverAcquiringTheGuard() {
        ReflectionTestUtils.setField(bootstrapSync, "enabled", true);
        ReflectionTestUtils.setField(bootstrapSync, "maxAgeDays", 30);
        when(nvdCpeSyncService.isMirrorFresherThan(Duration.ofDays(30))).thenReturn(true);

        bootstrapSync.run(args);

        verify(nvdCpeSyncService, never()).tryBeginFullSync();
        verify(nvdCpeSyncService, never()).syncAllAndRelease(Optional.empty());
    }

    @Test
    void staleOrNeverSyncedMirrorRunsTheStartupFullSyncNormally() throws InterruptedException {
        ReflectionTestUtils.setField(bootstrapSync, "enabled", true);
        ReflectionTestUtils.setField(bootstrapSync, "maxAgeDays", 30);
        when(nvdCpeSyncService.isMirrorFresherThan(Duration.ofDays(30))).thenReturn(false);
        when(nvdCpeSyncService.tryBeginFullSync()).thenReturn(true);
        CountDownLatch syncInvoked = new CountDownLatch(1);
        when(nvdCpeSyncService.syncAllAndRelease(Optional.empty())).thenAnswer(invocation -> {
            syncInvoked.countDown();
            return new NvdCpeSyncService.SyncOutcome(42, true);
        });

        bootstrapSync.run(args);

        assertThat(syncInvoked.await(5, TimeUnit.SECONDS))
                .as("a stale/never-synced mirror must still run the startup full sync")
                .isTrue();
        verify(nvdCpeSyncService, times(1)).tryBeginFullSync();
    }

    @Test
    void maxAgeDaysZeroOrNegativeDisablesTheGateAndAlwaysRunsRegardlessOfFreshness() throws InterruptedException {
        ReflectionTestUtils.setField(bootstrapSync, "enabled", true);
        ReflectionTestUtils.setField(bootstrapSync, "maxAgeDays", 0);
        when(nvdCpeSyncService.tryBeginFullSync()).thenReturn(true);
        CountDownLatch syncInvoked = new CountDownLatch(1);
        when(nvdCpeSyncService.syncAllAndRelease(Optional.empty())).thenAnswer(invocation -> {
            syncInvoked.countDown();
            return new NvdCpeSyncService.SyncOutcome(42, true);
        });

        bootstrapSync.run(args);

        assertThat(syncInvoked.await(5, TimeUnit.SECONDS))
                .as("maxAgeDays<=0 must disable the freshness gate entirely")
                .isTrue();
        verify(nvdCpeSyncService, never()).isMirrorFresherThan(any());
    }

    @Test
    void freshnessCheckThrowingSkipsWithoutAcquiringOrReleasingTheGuard() {
        // Fail-closed (skip), not fail-open -- see shouldSkipStartupFullSync's own javadoc for why
        // this differs from CpeDictionaryScheduledResync's guard-release choice: no slot has been
        // acquired yet at this point, so there is nothing to release, and releasing a slot that was
        // never acquired would just be a no-op with a misleading log message.
        ReflectionTestUtils.setField(bootstrapSync, "enabled", true);
        ReflectionTestUtils.setField(bootstrapSync, "maxAgeDays", 30);
        when(nvdCpeSyncService.isMirrorFresherThan(Duration.ofDays(30)))
                .thenThrow(new RuntimeException("db not ready yet"));

        bootstrapSync.run(args);

        verify(nvdCpeSyncService, never()).tryBeginFullSync();
        verify(nvdCpeSyncService, never()).releaseFullSyncGuard();
        verify(nvdCpeSyncService, never()).syncAllAndRelease(Optional.empty());
    }
}
