package com.vulncheck.app.service;

import com.vulncheck.app.entity.NvdCveSyncState;
import com.vulncheck.app.repository.NvdCveSyncStateRepository;
import com.vulncheck.app.service.NvdCveSyncService.RunBudget;
import com.vulncheck.app.service.NvdCveSyncService.SyncOutcome;
import java.time.Duration;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Daily driver for {@link NvdCveSyncService}'s delta sync (closed-mode backlog item 284, design in
 * {@code docs/spec/closed-mode-plan.md} §4-2-4). Deliberately deferred until now: items 241 (Phase
 * 3b A/B verification) and 251 (B4, {@code NvdVulnerabilitySource}'s mirror-only cutover) both had
 * to finish first so that enabling delta sync early wouldn't taint that verification with mirror
 * data-freshness drift — both completed 2026-09-03, so that constraint no longer applies. Off by
 * default ({@code app.nvd-cve-delta.enabled}), same safety-first convention as {@link
 * NvdCveBackfillScheduledRunner}/{@link CpeDictionaryScheduledResync}/{@code
 * RegistryMirrorScheduledSync}.
 *
 * <p><b>Baseline-completed guard is checked here, before ever touching {@link
 * NvdCveSyncService#tryBeginRun}</b> — same shape as {@link NvdCveBackfillScheduledRunner}, just
 * the mirror-image condition: delta sync is meaningless (and {@link
 * NvdCveSyncService#runDeltaTickAndRelease} already no-ops) *before* the baseline completes, which
 * for a fresh mirror can be the common case for several days straight (§4-2-4 estimates ~4-5 daily
 * backfill runs), whereas {@link NvdCveBackfillScheduledRunner} checks the same flag to stop
 * *after* the baseline is done. Checking {@code nvd_cve_sync_state.baseline_completed} directly
 * here means this scheduler never acquires the guard it shares with {@link
 * NvdCveBackfillScheduledRunner} during that whole window, so an in-progress backfill tick can
 * never lose a {@link NvdCveSyncService#tryBeginRun} race against a delta tick that would just
 * no-op anyway.
 *
 * <p>Same worker-thread/guard-release shape as {@link NvdCveBackfillScheduledRunner}: the actual
 * sync runs on its own daemon thread, not the shared {@code @Scheduled} pool thread, and {@link
 * #startWorker} failing to spawn releases {@link NvdCveSyncService#tryBeginRun}'s guard itself
 * (task-backlog items 81/136/141's exact failure mode — see that class's javadoc for the full
 * rationale).
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class NvdCveDeltaScheduledRunner {

    private final NvdCveSyncService nvdCveSyncService;
    private final NvdCveSyncStateRepository nvdCveSyncStateRepository;
    private final UserApiKeyService userApiKeyService;

    @Value("${app.nvd-cve-delta.enabled:false}")
    private boolean enabled;

    @Value("${app.nvd-cve-delta.max-requests-per-run:60}")
    private int maxRequestsPerRun;

    @Value("${app.nvd-cve-delta.max-duration-minutes:60}")
    private int maxDurationMinutes;

    /**
     * 06:30 UTC daily by default (overridable via {@code NVD_CVE_DELTA_CRON}) — 30 minutes after
     * the backfill's own 06:00 UTC slot ({@link NvdCveBackfillScheduledRunner#runBackfillTick}),
     * comfortably clear of every other sync job's window (see that method's javadoc for the full
     * list). Since this and the backfill runner share the same {@link
     * NvdCveSyncService#tryBeginRun} guard and the same process-wide {@link
     * com.vulncheck.app.service.nvd.NvdRateLimiter}, this slot is deliberately *not* the same
     * instant as the backfill's — a same-instant overlap would routinely cost one of the two ticks
     * a same-day no-op via the guard, rather than actually delta-syncing that day.
     */
    @Scheduled(cron = "${app.nvd-cve-delta.cron:0 30 6 * * *}", zone = "UTC")
    public void runDeltaScheduledTick() {
        if (!enabled) {
            return;
        }
        if (!isBaselineCompleted()) {
            log.info("Scheduled NVD CVE delta tick skipped: baseline backfill has not completed yet");
            return;
        }
        if (!nvdCveSyncService.tryBeginRun()) {
            log.warn("Scheduled NVD CVE delta tick skipped: another NVD CVE mirror run is already in progress");
            return;
        }
        try {
            startWorker();
        } catch (Throwable t) {
            // Same rationale as NvdCveBackfillScheduledRunner#runBackfillTick's equivalent catch
            // block (task-backlog items 81/136/141 lineage) -- see that method's javadoc.
            nvdCveSyncService.releaseRunGuard();
            log.error("Scheduled NVD CVE delta tick failed to start -- run guard released", t);
        }
    }

    /** {@code true} only once {@code nvd_cve_sync_state.baseline_completed} is set — a missing
     *  state row (should not happen once the V39 migration has run) is treated the same as "not
     *  completed", not an error, since this is purely a should-we-bother gate. */
    private boolean isBaselineCompleted() {
        return nvdCveSyncStateRepository.findById((short) 1)
                .map(NvdCveSyncState::isBaselineCompleted)
                .orElse(false);
    }

    /** Spawns and starts the worker thread that runs {@link #runTick}. Package-private so a unit
     *  test can force this step to fail without needing a real thread-creation failure — same
     *  rationale as {@code NvdCveBackfillScheduledRunner#startWorker}. */
    void startWorker() {
        Thread worker = new Thread(this::runTick, "nvd-cve-delta-scheduled");
        worker.setDaemon(true);
        worker.start();
    }

    /** The actual budgeted tick + outcome logging. Callers must have already won {@link
     *  NvdCveSyncService#tryBeginRun} before invoking this — package-private (rather than private)
     *  so a unit test can invoke it directly on the test thread. */
    void runTick() {
        long startedAt = System.currentTimeMillis();
        Optional<String> adminKey;
        try {
            adminKey = userApiKeyService.getAdminNvdApiKey();
        } catch (Throwable t) {
            // Same rationale as NvdCveBackfillScheduledRunner#runTick's equivalent catch block
            // (task-backlog items 142/143 lineage): resolving the key ahead of the guarded call
            // guarantees runDeltaTickAndRelease() -- the only place that releases the run guard --
            // is always reached.
            log.warn("Could not resolve the admin's NVD key -- running this delta tick unkeyed (slower)", t);
            adminKey = Optional.empty();
        }
        RunBudget budget = new RunBudget(maxRequestsPerRun, Duration.ofMinutes(maxDurationMinutes));
        log.info("Scheduled NVD CVE delta tick starting (admin NVD key present: {}, budget: {} requests / {} "
                + "minutes)", adminKey.isPresent(), maxRequestsPerRun, maxDurationMinutes);
        try {
            SyncOutcome outcome = nvdCveSyncService.runDeltaTickAndRelease(adminKey, budget);
            long seconds = (System.currentTimeMillis() - startedAt) / 1000;
            if (outcome.completed()) {
                log.info("Scheduled NVD CVE delta tick finished this tick's delta window: {} records upserted, "
                        + "{} seconds", outcome.upserted(), seconds);
            } else {
                log.info("Scheduled NVD CVE delta tick finished this tick's budget (delta window not yet fully "
                        + "synced): {} records upserted, {} seconds", outcome.upserted(), seconds);
            }
        } catch (Exception e) {
            log.error("Scheduled NVD CVE delta tick aborted", e);
        }
    }
}
