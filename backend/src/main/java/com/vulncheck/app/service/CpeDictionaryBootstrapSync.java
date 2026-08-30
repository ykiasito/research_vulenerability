package com.vulncheck.app.service;

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
 * <p>Runs on its own daemon thread so a multi-hour sync never blocks application startup, and is
 * deliberately unauthenticated (no NVD API key): a key would only shorten the per-request rate-limit
 * wait from 6.5s to 0.7s, which is a small share of a sync dominated by ~30s-per-page transfer time,
 * and this way the sync needs no credential wiring at all.
 *
 * <p>Shares {@link NvdCpeSyncService}'s single {@code fullSyncRunning} guard (via {@link
 * NvdCpeSyncService#tryBeginFullSync}) with the admin-triggered full sync ({@code
 * AdminController#cpeFullSync}) — both are the same underlying operation on the same NVD rate
 * limit and the same {@code cpe_dictionary} upserts, so only one may run at a time regardless of
 * which trigger started it.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class CpeDictionaryBootstrapSync implements ApplicationRunner {

    private final NvdCpeSyncService nvdCpeSyncService;

    @Value("${app.cpe-full-sync-on-startup:false}")
    private boolean enabled;

    @Override
    public void run(ApplicationArguments args) {
        if (!enabled) {
            return;
        }
        if (!nvdCpeSyncService.tryBeginFullSync()) {
            log.warn("Full NVD CPE dictionary sync (startup-triggered) skipped: another full sync is already running");
            return;
        }
        Thread worker = new Thread(() -> {
            log.warn("Full NVD CPE dictionary sync starting — this takes hours; set "
                    + "CPE_FULL_SYNC_ON_STARTUP=false once it has completed so it doesn't re-run on every boot");
            long startedAt = System.currentTimeMillis();
            try {
                int upserted = nvdCpeSyncService.syncAllAndRelease(Optional.empty());
                log.warn("Full NVD CPE dictionary sync finished: {} entries upserted in {} minutes",
                        upserted, (System.currentTimeMillis() - startedAt) / 60000);
            } catch (Exception e) {
                log.error("Full NVD CPE dictionary sync aborted", e);
            }
        }, "cpe-full-sync");
        worker.setDaemon(true);
        worker.start();
    }
}
