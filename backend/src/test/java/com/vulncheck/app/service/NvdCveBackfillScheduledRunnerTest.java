package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.vulncheck.app.service.NvdCveSyncService.RunBudget;
import com.vulncheck.app.service.NvdCveSyncService.SyncOutcome;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Unit coverage for {@link NvdCveBackfillScheduledRunner} — the {@code enabled} gate, the
 * concurrency guard hand-off with {@link NvdCveSyncService#tryBeginRun}, and the
 * baseline-completed-vs-still-in-progress outcome handling. {@link NvdCveSyncService} itself is
 * mocked: its own chunking/budget/split behavior is covered by {@code NvdCveSyncServiceTest}, so
 * this class only needs to verify the scheduler calls it correctly and reacts correctly to what it
 * returns. Same structure as {@code CpeDictionaryScheduledResyncTest}.
 */
class NvdCveBackfillScheduledRunnerTest {

    private final NvdCveSyncService nvdCveSyncService = mock(NvdCveSyncService.class);
    private final UserApiKeyService userApiKeyService = mock(UserApiKeyService.class);
    private final NvdCveBackfillScheduledRunner runner =
            new NvdCveBackfillScheduledRunner(nvdCveSyncService, userApiKeyService);

    @Test
    void disabledByDefaultSkipsEntirelyWithoutTouchingTheGuard() {
        ReflectionTestUtils.setField(runner, "enabled", false);

        runner.runBackfillTick();

        verifyNoInteractions(nvdCveSyncService);
    }

    @Test
    void enabledButAnotherRunAlreadyInProgressSkipsWithoutStartingASecondOne() {
        ReflectionTestUtils.setField(runner, "enabled", true);
        when(nvdCveSyncService.tryBeginRun()).thenReturn(false);

        runner.runBackfillTick();

        verify(nvdCveSyncService, times(1)).tryBeginRun();
        verify(nvdCveSyncService, never()).runBackfillTickAndRelease(any(), any());
    }

    @Test
    void enabledAndGuardWonRunsTheTickOnAWorkerThread() throws InterruptedException {
        ReflectionTestUtils.setField(runner, "enabled", true);
        when(nvdCveSyncService.tryBeginRun()).thenReturn(true);
        when(userApiKeyService.getAdminNvdApiKey()).thenReturn(Optional.empty());
        CountDownLatch tickInvoked = new CountDownLatch(1);
        when(nvdCveSyncService.runBackfillTickAndRelease(eq(Optional.empty()), any())).thenAnswer(invocation -> {
            tickInvoked.countDown();
            return new SyncOutcome(42, false);
        });

        runner.runBackfillTick();

        assertThat(tickInvoked.await(5, TimeUnit.SECONDS))
                .as("runBackfillTickAndRelease should be invoked on the spawned worker thread")
                .isTrue();
        verify(nvdCveSyncService, times(1)).tryBeginRun();
    }

    @Test
    void runBackfillTickReleasesTheGuardWhenTheWorkerThreadFailsToStart() {
        // Regression test for task-backlog items 81/136/141's exact failure mode: if starting the
        // worker thread itself throws after tryBeginRun() already won the slot,
        // runBackfillTickAndRelease()'s own finally-release never runs.
        NvdCveBackfillScheduledRunner spyRunner = spy(runner);
        ReflectionTestUtils.setField(spyRunner, "enabled", true);
        when(nvdCveSyncService.tryBeginRun()).thenReturn(true);
        doThrow(new RuntimeException("unable to create native thread")).when(spyRunner).startWorker();

        spyRunner.runBackfillTick();

        verify(nvdCveSyncService, times(1)).releaseRunGuard();
        verify(nvdCveSyncService, never()).runBackfillTickAndRelease(any(), any());
    }

    @Test
    void runTickLogsBaselineCompletedOutcomeWithoutThrowing() {
        when(userApiKeyService.getAdminNvdApiKey()).thenReturn(Optional.empty());
        when(nvdCveSyncService.runBackfillTickAndRelease(eq(Optional.empty()), any(RunBudget.class)))
                .thenReturn(new SyncOutcome(320_000, true));

        runner.runTick();

        verify(nvdCveSyncService, times(1)).runBackfillTickAndRelease(eq(Optional.empty()), any(RunBudget.class));
    }

    @Test
    void runTickLogsStillInProgressOutcomeWithoutThrowing() {
        when(userApiKeyService.getAdminNvdApiKey()).thenReturn(Optional.empty());
        when(nvdCveSyncService.runBackfillTickAndRelease(eq(Optional.empty()), any(RunBudget.class)))
                .thenReturn(new SyncOutcome(2000, false));

        runner.runTick();

        verify(nvdCveSyncService, times(1)).runBackfillTickAndRelease(eq(Optional.empty()), any(RunBudget.class));
    }

    @Test
    void runTickSwallowsAnExceptionFromTheServiceRatherThanPropagatingIt() {
        when(userApiKeyService.getAdminNvdApiKey()).thenReturn(Optional.empty());
        when(nvdCveSyncService.runBackfillTickAndRelease(eq(Optional.empty()), any(RunBudget.class)))
                .thenThrow(new RuntimeException("NVD unreachable"));

        runner.runTick();

        verify(nvdCveSyncService, times(1)).runBackfillTickAndRelease(eq(Optional.empty()), any(RunBudget.class));
    }

    @Test
    void runTickFallsBackToUnkeyedWhenAdminKeyResolutionThrows() {
        // Regression test for task-backlog item 143's lineage: getAdminNvdApiKey() throwing must
        // not prevent runBackfillTickAndRelease() from being reached — that call's own finally
        // block is the only place the run guard gets released.
        when(userApiKeyService.getAdminNvdApiKey()).thenThrow(new IllegalStateException("Failed to decrypt secret"));
        when(nvdCveSyncService.runBackfillTickAndRelease(eq(Optional.empty()), any(RunBudget.class)))
                .thenReturn(new SyncOutcome(0, false));

        runner.runTick();

        verify(nvdCveSyncService, times(1)).runBackfillTickAndRelease(eq(Optional.empty()), any(RunBudget.class));
    }

    @Test
    void runTickPassesTheAdminNvdKeyThroughWhenOneIsConfigured() {
        when(userApiKeyService.getAdminNvdApiKey()).thenReturn(Optional.of("admin-nvd-key"));
        when(nvdCveSyncService.runBackfillTickAndRelease(eq(Optional.of("admin-nvd-key")), any(RunBudget.class)))
                .thenReturn(new SyncOutcome(0, false));

        runner.runTick();

        verify(nvdCveSyncService, times(1))
                .runBackfillTickAndRelease(eq(Optional.of("admin-nvd-key")), any(RunBudget.class));
    }

    @Test
    void runTickBuildsTheBudgetFromTheConfiguredProperties() {
        ReflectionTestUtils.setField(runner, "maxRequestsPerRun", 10);
        ReflectionTestUtils.setField(runner, "maxDurationMinutes", 5);
        when(userApiKeyService.getAdminNvdApiKey()).thenReturn(Optional.empty());
        when(nvdCveSyncService.runBackfillTickAndRelease(eq(Optional.empty()), any(RunBudget.class)))
                .thenReturn(new SyncOutcome(0, false));

        runner.runTick();

        verify(nvdCveSyncService).runBackfillTickAndRelease(eq(Optional.empty()),
                eq(new RunBudget(10, java.time.Duration.ofMinutes(5))));
    }
}
