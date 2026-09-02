package com.vulncheck.app.service;

import com.vulncheck.app.service.registry.RegistryMirrorSyncService;
import com.vulncheck.app.service.registry.RegistryMirrorSyncService.SyncOutcome;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Weekly automatic sync of the 9 registry mirrors (crates.io/RubyGems/Packagist/Hex/npm/PyPI/
 * NuGet/Go/pub.dev, {@code registry_package_mirror}) from every seed package name this app knows
 * about — both every name ever resolved via a live registry lookup ({@code identified_products})
 * and every name an admin has explicitly uploaded ({@code registry_mirror_seed_name}, closed-mode
 * backlog item 185) — see {@link RegistryMirrorSyncService}'s class javadoc for why both sources
 * exist (closed-mode backlog item 183). Same shape and rationale as {@link
 * CpeDictionaryScheduledResync} (its own javadoc explains why a scheduled resync is needed at all:
 * without one, a mirror only ever gets populated by a manually-triggered admin sync, which requires
 * a human to remember to act).
 *
 * <p>Off by default (env var {@code REGISTRY_MIRROR_SCHEDULED_SYNC_ENABLED}), matching every other
 * closed-mode-related sync flag's safety-first default — this never changes existing behavior for
 * a deployment that hasn't explicitly opted in.
 *
 * <p>Shares {@link RegistryMirrorSyncService}'s single {@code fullSyncRunning} guard (via {@link
 * RegistryMirrorSyncService#tryBeginFullSync}) with the admin-triggered sync ({@code
 * AdminController#registryMirrorFullSync}) — both trigger the exact same underlying operation
 * against the same 9 ecosystems' rate limits and the same {@code registry_package_mirror} upserts,
 * so only one may run at a time no matter which of the two started it.
 *
 * <p>The sync itself runs on its own daemon thread, not on the calling {@code @Scheduled}
 * invocation — same reasoning as {@link CpeDictionaryScheduledResync}: Spring's default task
 * scheduler is single-threaded, so a long-running sync directly on it would starve every other
 * {@code @Scheduled} job of its own slots for as long as the sync takes.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class RegistryMirrorScheduledSync {

    private final RegistryMirrorSyncService registryMirrorSyncService;

    @Value("${app.registry-mirror-scheduled-sync-enabled:false}")
    private boolean enabled;

    /**
     * Sunday 02:00 UTC by default (overridable via {@code REGISTRY_MIRROR_SCHEDULED_SYNC_CRON}) —
     * after the NVD CPE Dictionary weekly resync's 01:30 UTC start (see {@link
     * CpeDictionaryScheduledResync#resyncWeekly}, ~103 minutes measured), ahead of the daily
     * CVE.org/CSAF/GHSA/job-retention/OSV syncs (03:30 UTC onward — see those classes' own cron
     * values). Unlike the CPE full sync, this sync's duration scales with how many distinct package
     * names this app has actually observed (see {@link RegistryMirrorSyncService}'s class javadoc),
     * not a fixed multi-million-row registry, so it is expected to be much shorter in practice —
     * still scheduled with headroom ahead of the daily syncs in case observed-name volume grows.
     */
    @Scheduled(cron = "${app.registry-mirror-scheduled-sync-cron:0 0 2 * * SUN}", zone = "UTC")
    public void resyncWeekly() {
        if (!enabled) {
            return;
        }
        if (!registryMirrorSyncService.tryBeginFullSync()) {
            log.warn("Scheduled weekly registry mirror resync skipped: another registry mirror sync is already running");
            return;
        }
        try {
            startWorker();
        } catch (Throwable t) {
            // Same rationale as CpeDictionaryScheduledResync#resyncWeekly's equivalent catch block
            // (task-backlog items 81/136/141 lineage): tryBeginFullSync() above already won the
            // slot, but if the worker thread itself never got to run, syncAllAndRelease()'s own
            // finally-release never fires either — without this, the slot would stay held until
            // the process restarts.
            registryMirrorSyncService.releaseFullSyncGuard();
            log.error("Scheduled weekly registry mirror resync failed to start — sync slot released", t);
        }
    }

    /**
     * Spawns and starts the worker thread that runs {@link #runFullSync}. Package-private (rather
     * than inlined in {@link #resyncWeekly}) so a unit test can force this step to fail without
     * needing a real thread-creation failure to exercise {@link #resyncWeekly}'s guard-release
     * catch block.
     */
    void startWorker() {
        Thread worker = new Thread(this::runFullSync, "registry-mirror-scheduled-resync");
        worker.setDaemon(true);
        worker.start();
    }

    /**
     * The actual sync + outcome logging. Callers must have already won {@link
     * RegistryMirrorSyncService#tryBeginFullSync} before invoking this, exactly like {@link
     * RegistryMirrorSyncService#syncAllAndRelease} itself requires.
     *
     * <p>Package-private rather than private so a unit test can invoke it directly on the test
     * thread and assert on its logging/call behavior without having to synchronize with a real
     * background thread.
     */
    void runFullSync() {
        long startedAt = System.currentTimeMillis();
        log.warn("Scheduled weekly registry mirror resync starting");
        try {
            SyncOutcome outcome = registryMirrorSyncService.syncAllAndRelease();
            long minutes = (System.currentTimeMillis() - startedAt) / 60000;
            log.warn("Scheduled weekly registry mirror resync finished in {} minutes: {} synced, {} unresolved, "
                    + "candidate name counts (after freshness filter): {}", minutes, outcome.totalSynced(), outcome.totalUnresolved(),
                    outcome.observedNameCountByEcosystem());
        } catch (Exception e) {
            log.error("Scheduled weekly registry mirror resync aborted", e);
        }
    }
}
