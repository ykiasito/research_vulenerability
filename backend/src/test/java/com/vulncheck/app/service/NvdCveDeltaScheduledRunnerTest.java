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

import com.vulncheck.app.entity.NvdCveSyncState;
import com.vulncheck.app.repository.NvdCveSyncStateRepository;
import com.vulncheck.app.service.NvdCveSyncService.RunBudget;
import com.vulncheck.app.service.NvdCveSyncService.SyncOutcome;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Unit coverage for {@link NvdCveDeltaScheduledRunner} — the {@code enabled} gate, the
 * baseline-completed pre-check (and that it short-circuits before ever touching {@link
 * NvdCveSyncService#tryBeginRun}), the concurrency guard hand-off, and outcome handling. {@link
 * NvdCveSyncService} itself is mocked: its own chunking/budget/delta-window behavior is covered by
 * {@code NvdCveSyncServiceTest}, so this class only needs to verify the scheduler calls it correctly
 * and reacts correctly to what it returns. Same structure as {@code
 * NvdCveBackfillScheduledRunnerTest}.
 */
class NvdCveDeltaScheduledRunnerTest {

    private final NvdCveSyncService nvdCveSyncService = mock(NvdCveSyncService.class);
    private final NvdCveSyncStateRepository nvdCveSyncStateRepository = mock(NvdCveSyncStateRepository.class);
    private final UserApiKeyService userApiKeyService = mock(UserApiKeyService.class);
    private final NvdCveDeltaScheduledRunner runner =
            new NvdCveDeltaScheduledRunner(nvdCveSyncService, nvdCveSyncStateRepository, userApiKeyService);

    private static NvdCveSyncState stateWithBaselineCompleted(boolean completed) {
        NvdCveSyncState state = new NvdCveSyncState();
        state.setBaselineCompleted(completed);
        return state;
    }

    @Test
    void disabledByDefaultSkipsEntirelyWithoutTouchingAnything() {
        ReflectionTestUtils.setField(runner, "enabled", false);

        runner.runDeltaScheduledTick();

        verifyNoInteractions(nvdCveSyncStateRepository);
        verifyNoInteractions(nvdCveSyncService);
    }

    @Test
    void enabledButBaselineNotCompletedSkipsWithoutTouchingTheRunGuard() {
        ReflectionTestUtils.setField(runner, "enabled", true);
        when(nvdCveSyncStateRepository.findById((short) 1))
                .thenReturn(Optional.of(stateWithBaselineCompleted(false)));

        runner.runDeltaScheduledTick();

        verifyNoInteractions(nvdCveSyncService);
    }

    @Test
    void enabledButSyncStateRowMissingIsTreatedAsBaselineNotCompleted() {
        ReflectionTestUtils.setField(runner, "enabled", true);
        when(nvdCveSyncStateRepository.findById((short) 1)).thenReturn(Optional.empty());

        runner.runDeltaScheduledTick();

        verifyNoInteractions(nvdCveSyncService);
    }

    @Test
    void enabledAndBaselineCompletedButAnotherRunAlreadyInProgressSkipsWithoutStartingASecondOne() {
        ReflectionTestUtils.setField(runner, "enabled", true);
        when(nvdCveSyncStateRepository.findById((short) 1))
                .thenReturn(Optional.of(stateWithBaselineCompleted(true)));
        when(nvdCveSyncService.tryBeginRun()).thenReturn(false);

        runner.runDeltaScheduledTick();

        verify(nvdCveSyncService, times(1)).tryBeginRun();
        verify(nvdCveSyncService, never()).runDeltaTickAndRelease(any(), any());
    }

    @Test
    void enabledAndBaselineCompletedAndGuardWonRunsTheTickOnAWorkerThread() throws InterruptedException {
        ReflectionTestUtils.setField(runner, "enabled", true);
        when(nvdCveSyncStateRepository.findById((short) 1))
                .thenReturn(Optional.of(stateWithBaselineCompleted(true)));
        when(nvdCveSyncService.tryBeginRun()).thenReturn(true);
        when(userApiKeyService.getAdminNvdApiKey()).thenReturn(Optional.empty());
        CountDownLatch tickInvoked = new CountDownLatch(1);
        when(nvdCveSyncService.runDeltaTickAndRelease(eq(Optional.empty()), any())).thenAnswer(invocation -> {
            tickInvoked.countDown();
            return new SyncOutcome(7, true);
        });

        runner.runDeltaScheduledTick();

        assertThat(tickInvoked.await(5, TimeUnit.SECONDS))
                .as("runDeltaTickAndRelease should be invoked on the spawned worker thread")
                .isTrue();
        verify(nvdCveSyncService, times(1)).tryBeginRun();
    }

    @Test
    void runDeltaScheduledTickReleasesTheGuardWhenTheWorkerThreadFailsToStart() {
        // Regression test for task-backlog items 81/136/141's exact failure mode (same lineage as
        // NvdCveBackfillScheduledRunner's own test): if starting the worker thread itself throws
        // after tryBeginRun() already won the slot, runDeltaTickAndRelease()'s own finally-release
        // never runs.
        NvdCveDeltaScheduledRunner spyRunner = spy(runner);
        ReflectionTestUtils.setField(spyRunner, "enabled", true);
        when(nvdCveSyncStateRepository.findById((short) 1))
                .thenReturn(Optional.of(stateWithBaselineCompleted(true)));
        when(nvdCveSyncService.tryBeginRun()).thenReturn(true);
        doThrow(new RuntimeException("unable to create native thread")).when(spyRunner).startWorker();

        spyRunner.runDeltaScheduledTick();

        verify(nvdCveSyncService, times(1)).releaseRunGuard();
        verify(nvdCveSyncService, never()).runDeltaTickAndRelease(any(), any());
    }

    @Test
    void runTickLogsChunkFinishedOutcomeWithoutThrowing() {
        when(userApiKeyService.getAdminNvdApiKey()).thenReturn(Optional.empty());
        when(nvdCveSyncService.runDeltaTickAndRelease(eq(Optional.empty()), any(RunBudget.class)))
                .thenReturn(new SyncOutcome(120, true));

        runner.runTick();

        verify(nvdCveSyncService, times(1)).runDeltaTickAndRelease(eq(Optional.empty()), any(RunBudget.class));
    }

    @Test
    void runTickLogsStillInProgressOutcomeWithoutThrowing() {
        when(userApiKeyService.getAdminNvdApiKey()).thenReturn(Optional.empty());
        when(nvdCveSyncService.runDeltaTickAndRelease(eq(Optional.empty()), any(RunBudget.class)))
                .thenReturn(new SyncOutcome(30, false));

        runner.runTick();

        verify(nvdCveSyncService, times(1)).runDeltaTickAndRelease(eq(Optional.empty()), any(RunBudget.class));
    }

    @Test
    void runTickSwallowsAnExceptionFromTheServiceRatherThanPropagatingIt() {
        when(userApiKeyService.getAdminNvdApiKey()).thenReturn(Optional.empty());
        when(nvdCveSyncService.runDeltaTickAndRelease(eq(Optional.empty()), any(RunBudget.class)))
                .thenThrow(new RuntimeException("NVD unreachable"));

        runner.runTick();

        verify(nvdCveSyncService, times(1)).runDeltaTickAndRelease(eq(Optional.empty()), any(RunBudget.class));
    }

    @Test
    void runTickFallsBackToUnkeyedWhenAdminKeyResolutionThrows() {
        // Regression test for task-backlog item 143's lineage: getAdminNvdApiKey() throwing must
        // not prevent runDeltaTickAndRelease() from being reached -- that call's own finally block
        // is the only place the run guard gets released.
        when(userApiKeyService.getAdminNvdApiKey()).thenThrow(new IllegalStateException("Failed to decrypt secret"));
        when(nvdCveSyncService.runDeltaTickAndRelease(eq(Optional.empty()), any(RunBudget.class)))
                .thenReturn(new SyncOutcome(0, false));

        runner.runTick();

        verify(nvdCveSyncService, times(1)).runDeltaTickAndRelease(eq(Optional.empty()), any(RunBudget.class));
    }

    @Test
    void runTickPassesTheAdminNvdKeyThroughWhenOneIsConfigured() {
        when(userApiKeyService.getAdminNvdApiKey()).thenReturn(Optional.of("admin-nvd-key"));
        when(nvdCveSyncService.runDeltaTickAndRelease(eq(Optional.of("admin-nvd-key")), any(RunBudget.class)))
                .thenReturn(new SyncOutcome(0, false));

        runner.runTick();

        verify(nvdCveSyncService, times(1))
                .runDeltaTickAndRelease(eq(Optional.of("admin-nvd-key")), any(RunBudget.class));
    }

    @Test
    void runTickBuildsTheBudgetFromTheConfiguredProperties() {
        ReflectionTestUtils.setField(runner, "maxRequestsPerRun", 10);
        ReflectionTestUtils.setField(runner, "maxDurationMinutes", 5);
        when(userApiKeyService.getAdminNvdApiKey()).thenReturn(Optional.empty());
        when(nvdCveSyncService.runDeltaTickAndRelease(eq(Optional.empty()), any(RunBudget.class)))
                .thenReturn(new SyncOutcome(0, false));

        runner.runTick();

        verify(nvdCveSyncService).runDeltaTickAndRelease(eq(Optional.empty()),
                eq(new RunBudget(10, java.time.Duration.ofMinutes(5))));
    }
}
