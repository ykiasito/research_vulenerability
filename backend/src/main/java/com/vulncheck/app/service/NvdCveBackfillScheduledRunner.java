package com.vulncheck.app.service;

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
 * Self-terminating daily driver for {@link NvdCveSyncService}'s baseline backfill (closed-mode
 * backlog item 202, design in {@code docs/spec/closed-mode-plan.md} §4-2-4). Off by default ({@code
 * app.nvd-cve-backfill.enabled}) — the DB-size impact (§4-2-6: ~2-3GB, on top of the existing 15GB
 * hard cap) must be an environment operator's deliberate opt-in, same safety-first convention as
 * {@link CpeDictionaryScheduledResync}/{@code RegistryMirrorScheduledSync}.
 *
 * <p><b>Self-terminating, unlike {@link CpeDictionaryScheduledResync}</b>: once {@code
 * nvd_cve_sync_state.baseline_completed} is true, {@link #runBackfillTick} returns immediately and
 * does nothing else, forever (no delta-sync fallback — see {@link NvdCveSyncService}'s class
 * javadoc for why delta isn't wired to any scheduler yet). At the default budget (60 requests/60
 * minutes per run), a full backfill (~245-300 requests, §4-2-3) finishes in roughly 4-5 daily runs;
 * every run after that is a cheap one-row {@code SELECT} that exits immediately.
 *
 * <p>Same worker-thread/guard shape as {@link CpeDictionaryScheduledResync}: the actual sync runs
 * on its own daemon thread, not the shared {@code @Scheduled} pool thread (this pool is already
 * shared by every other daily sync job — CVE.org, GHSA, both CSAF vendors, OSV, job retention
 * cleanup — a multi-minute run directly on it would starve all of them for however long this run
 * takes), and {@link #startWorker} failing to spawn releases {@link
 * NvdCveSyncService#tryBeginRun}'s guard itself (task-backlog items 81/136/141's exact failure
 * mode: without this, a thread-creation failure after the guard is already won would leave it stuck
 * held until process restart, permanently locking out every future trigger — scheduled and the
 * admin manual-kick screen alike).
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class NvdCveBackfillScheduledRunner {

    private final NvdCveSyncService nvdCveSyncService;
    private final UserApiKeyService userApiKeyService;

    @Value("${app.nvd-cve-backfill.enabled:false}")
    private boolean enabled;

    @Value("${app.nvd-cve-backfill.max-requests-per-run:60}")
    private int maxRequestsPerRun;

    @Value("${app.nvd-cve-backfill.max-duration-minutes:60}")
    private int maxDurationMinutes;

    /**
     * 06:00 UTC daily by default (overridable via {@code NVD_CVE_BACKFILL_CRON}) — deliberately far
     * from every other sync job's slot (CPE dictionary weekly resync Sun 01:30, registry mirror
     * weekly resync Sun 02:00, CVE.org daily 03:30, Siemens CSAF daily 03:45, GHSA daily 04:00, Red
     * Hat CSAF daily 04:15, job retention cleanup daily 04:00, OSV daily 05:30 — see each job's own
     * scheduling javadoc). Sharing {@link com.vulncheck.app.service.nvd.NvdRateLimiter} with the CPE
     * dictionary resync (both hit the same process-wide NVD rate gate) is the specific reason this
     * must not land in that Sunday 01:30-ish window, not just a generic "don't collide" preference.
     */
    @Scheduled(cron = "${app.nvd-cve-backfill.cron:0 0 6 * * *}", zone = "UTC")
    public void runBackfillTick() {
        if (!enabled) {
            return;
        }
        if (!nvdCveSyncService.tryBeginRun()) {
            log.warn("Scheduled NVD CVE backfill tick skipped: another NVD CVE mirror run is already in progress");
            return;
        }
        try {
            startWorker();
        } catch (Throwable t) {
            // Same rationale as CpeDictionaryScheduledResync#resyncWeekly's equivalent catch block
            // (task-backlog items 81/136/141 lineage) -- see that method's javadoc.
            nvdCveSyncService.releaseRunGuard();
            log.error("Scheduled NVD CVE backfill tick failed to start -- run guard released", t);
        }
    }

    /** Spawns and starts the worker thread that runs {@link #runTick}. Package-private so a unit
     *  test can force this step to fail without needing a real thread-creation failure — same
     *  rationale as {@code CpeDictionaryScheduledResync#startWorker}. */
    void startWorker() {
        Thread worker = new Thread(this::runTick, "nvd-cve-backfill-scheduled");
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
            // Same rationale as CpeDictionaryScheduledResync#runFullSync's equivalent catch block
            // (task-backlog items 142/143 lineage): resolving the key ahead of the guarded call
            // guarantees runBackfillTickAndRelease() -- the only place that releases the run guard
            // -- is always reached.
            log.warn("Could not resolve the admin's NVD key -- running this backfill tick unkeyed (slower)", t);
            adminKey = Optional.empty();
        }
        RunBudget budget = new RunBudget(maxRequestsPerRun, Duration.ofMinutes(maxDurationMinutes));
        log.info("Scheduled NVD CVE backfill tick starting (admin NVD key present: {}, budget: {} requests / {} "
                + "minutes)", adminKey.isPresent(), maxRequestsPerRun, maxDurationMinutes);
        try {
            SyncOutcome outcome = nvdCveSyncService.runBackfillTickAndRelease(adminKey, budget);
            long seconds = (System.currentTimeMillis() - startedAt) / 1000;
            if (outcome.completed()) {
                log.warn("Scheduled NVD CVE backfill tick finished the baseline: {} records upserted this tick, "
                        + "{} seconds", outcome.upserted(), seconds);
            } else {
                log.info("Scheduled NVD CVE backfill tick finished this tick's budget (baseline not yet complete): "
                        + "{} records upserted, {} seconds", outcome.upserted(), seconds);
            }
        } catch (Exception e) {
            log.error("Scheduled NVD CVE backfill tick aborted", e);
        }
    }
}
