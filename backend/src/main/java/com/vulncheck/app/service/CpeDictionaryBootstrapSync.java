package com.vulncheck.app.service;

import com.vulncheck.app.service.NvdCpeSyncService.SyncOutcome;
import java.time.Duration;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/**
 * One-shot full mirror of the NVD CPE Dictionary (~1.8M entries), triggered at startup and gated
 * behind {@code CPE_FULL_SYNC_ON_STARTUP} (default off).
 *
 * <p>Why a startup runner rather than the admin screen or a standalone script: the sync has to
 * share {@link com.vulncheck.app.service.nvd.NvdRateLimiter} with whatever research jobs are
 * running, and that limiter is an in-process singleton. Driving the sync from a second JVM (a test
 * harness, an ad-hoc script) would give it its own independent limiter and silently double this
 * deployment's real request rate against NVD — the exact mistake that had to be undone earlier
 * when a separate test process was run alongside the app against the package registries.
 *
 * <p>Runs on its own daemon thread so a multi-hour sync never blocks application startup.
 *
 * <p>Resolves the admin's NVD API key via {@link UserApiKeyService#getAdminNvdApiKey()} (closed-mode
 * backlog item 392) — there is no logged-in user context at startup, so the admin's own registered
 * key (rather than a per-request user key, as {@code AdminController#sync} uses) is the only key this
 * path can use, matching the scheduled twin's ({@code CpeDictionaryScheduledResync}) resolution. This
 * path was previously hardcoded to {@code Optional.empty()} (always unkeyed) on the assumption that a
 * key only shortens the per-request rate-limit wait from 6.5s to 0.7s against a sync dominated by
 * ~30s-per-page transfer time; the measured impact is larger than that (~18 minutes added to the
 * ~103-minute keyed baseline), so this now uses the admin key when one is registered.
 *
 * <p>Shares {@link NvdCpeSyncService}'s single {@code fullSyncRunning} guard (via {@link
 * NvdCpeSyncService#tryBeginFullSync}) with the admin-triggered full sync ({@code
 * AdminController#cpeFullSync}) — both are the same underlying operation on the same NVD rate
 * limit and the same {@code cpe_dictionary} upserts, so only one may run at a time regardless of
 * which trigger started it.
 *
 * <p><b>Freshness gate</b> (closed-mode backlog item 330): before this class existed, {@code
 * CPE_FULL_SYNC_ON_STARTUP=true} meant an unconditional ~103-minute, ~692MB full re-sync on
 * <em>every</em> restart, with no way to tell "already synced, this is just a redeploy" apart from
 * "never synced, this environment actually needs it" — the mirror had no DB-side completion state
 * at all until closed-mode backlog item 283 added {@link NvdCpeSyncService#isMirrorFresherThan}.
 * {@link #run} now checks that first: if the mirror's last unfiltered sync (full or delta) is
 * still within {@code app.cpe-full-sync-max-age-days}, the startup full sync is skipped entirely.
 * This is sound specifically because the weekly delta chain ({@link
 * NvdCpeSyncService#syncDeltaAndRelease}, {@code CpeDictionaryScheduledResync}) is structurally
 * gap-free once it's running — a fresh mirror by that measure really has no missing coverage to
 * make up for, so re-running the full sync on top of it would only reproduce work the delta chain
 * already did.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class CpeDictionaryBootstrapSync implements ApplicationRunner {

    private final NvdCpeSyncService nvdCpeSyncService;
    private final UserApiKeyService userApiKeyService;

    @Value("${app.cpe-full-sync-on-startup:false}")
    private boolean enabled;

    /** 0 or negative disables the freshness gate entirely (every enabled startup always runs the
     *  full sync) — same escape-hatch convention as {@code RegistryMirrorSyncService#freshnessDays}. */
    @Value("${app.cpe-full-sync-max-age-days:30}")
    private int maxAgeDays;

    @Override
    public void run(ApplicationArguments args) {
        if (!enabled) {
            return;
        }
        if (shouldSkipStartupFullSync()) {
            return;
        }
        if (!nvdCpeSyncService.tryBeginFullSync()) {
            log.warn("Full NVD CPE dictionary sync (startup-triggered) skipped: another full sync is already running");
            return;
        }
        try {
            startWorker();
        } catch (Throwable t) {
            // tryBeginFullSync() above already won the slot, but the worker thread itself never
            // got to run, so syncAllAndRelease()'s own finally-release never fires either —
            // without this, the slot would stay held until the process restarts (task-backlog
            // items 81/136/141).
            nvdCpeSyncService.releaseFullSyncGuard();
            log.error("Full NVD CPE dictionary sync (startup-triggered) failed to start — sync slot released", t);
        }
    }

    /**
     * The freshness gate itself (closed-mode backlog item 330) — deliberately evaluated here,
     * <em>before</em> {@link NvdCpeSyncService#tryBeginFullSync} is ever called: no sync slot is
     * held yet at this point, so this method has nothing to release on failure, unlike {@link
     * #run}'s own catch block or {@code CpeDictionaryScheduledResync#runScheduledResync}'s
     * equivalent {@link NvdCpeSyncService#hasCompletedInitialSync()} read (which runs
     * <em>after</em> that scheduler already won its slot, and therefore must release it on
     * failure instead of merely skipping).
     *
     * <p>Fails closed (skips the full sync) on any read failure — the opposite choice from
     * fail-open — because a read this early in the app lifecycle can plausibly fail simply
     * because postgres itself is still coming up; fail-open would force a ~103-minute full sync on
     * every one of those slow-DB-startup boots, defeating the entire point of this gate. Skipping
     * is safe operationally either way: {@code /admin/cpe-dictionary/sync-all} remains available,
     * unconditionally, to force a full sync by hand.
     */
    private boolean shouldSkipStartupFullSync() {
        if (maxAgeDays <= 0) {
            return false;
        }
        try {
            boolean fresh = nvdCpeSyncService.isMirrorFresherThan(Duration.ofDays(maxAgeDays));
            if (fresh) {
                log.info("CPE dictionary mirror's last unfiltered sync (cpe_dictionary_sync_state."
                        + "last_synced_at) is within the configured {}-day freshness window "
                        + "(app.cpe-full-sync-max-age-days) — skipping the startup full sync. Use "
                        + "/admin/cpe-dictionary/sync-all to force one.", maxAgeDays);
            } else {
                log.warn("CPE dictionary mirror has never completed an unfiltered sync, or its last one is "
                        + "older than the configured {}-day freshness window (app.cpe-full-sync-max-age-days) "
                        + "— running the startup full sync.", maxAgeDays);
            }
            return fresh;
        } catch (Throwable t) {
            log.warn("Could not determine CPE dictionary mirror freshness — skipping the startup full sync "
                    + "(use /admin/cpe-dictionary/sync-all to force one)", t);
            return true;
        }
    }

    /**
     * Resolves the admin's NVD API key (closed-mode backlog item 392), wrapped in its own
     * try/catch — same fail-soft rationale as {@code
     * CpeDictionaryScheduledResync#resolveAdminKey}/{@code NvdCveBackfillScheduledRunner#runTick}'s
     * equivalent resolution: a decrypt failure here must never prevent {@link
     * NvdCpeSyncService#syncAllAndRelease} (the only place that releases the sync guard acquired by
     * {@link #run}) from being reached.
     */
    private Optional<String> resolveAdminKey() {
        try {
            return userApiKeyService.getAdminNvdApiKey();
        } catch (Throwable t) {
            log.warn("Could not resolve the admin's NVD key — running the startup full sync unkeyed (slower)", t);
            return Optional.empty();
        }
    }

    /**
     * Spawns and starts the worker thread that runs the actual sync. Package-private (rather than
     * inlined in {@link #run}) so a unit test can force this step to fail (e.g. via a Mockito spy)
     * without needing a real thread-creation failure (native-thread exhaustion, a SecurityManager
     * denial) to exercise {@link #run}'s guard-release catch block.
     */
    void startWorker() {
        Optional<String> adminKey = resolveAdminKey();
        Thread worker = new Thread(() -> {
            log.warn("Full NVD CPE dictionary sync starting (admin NVD key present: {}) — this takes hours; safe "
                    + "to leave CPE_FULL_SYNC_ON_STARTUP=true across future restarts (app.cpe-full-sync-max-age-"
                    + "days's freshness gate will skip this again on the next boot once the mirror is up to date)",
                    adminKey.isPresent());
            long startedAt = System.currentTimeMillis();
            try {
                SyncOutcome outcome = nvdCpeSyncService.syncAllAndRelease(adminKey);
                long minutes = (System.currentTimeMillis() - startedAt) / 60000;
                if (outcome.completed()) {
                    log.warn("Full NVD CPE dictionary sync finished: {} entries upserted in {} minutes",
                            outcome.upserted(), minutes);
                } else {
                    log.error("Full NVD CPE dictionary sync aborted early after {} entries in {} minutes — "
                            + "dictionary is only partially synced", outcome.upserted(), minutes);
                }
            } catch (Exception e) {
                log.error("Full NVD CPE dictionary sync aborted", e);
            }
        }, "cpe-full-sync");
        worker.setDaemon(true);
        worker.start();
    }
}
