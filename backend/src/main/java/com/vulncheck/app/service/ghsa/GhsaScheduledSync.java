package com.vulncheck.app.service.ghsa;

import com.vulncheck.app.service.ghsa.GhsaSyncService.SyncResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Daily automatic delta sync for the GHSA mirror — measured 14-50 new/updated github-reviewed
 * advisories/day (plan §5-1), well within one REST API page. {@link GhsaSyncService#syncBaseline}
 * is deliberately NOT scheduled here, same rationale as {@code CveOrgScheduledSync}/{@code
 * SiemensCsafScheduledSync}: a full tarball re-walk is meant to be triggered once manually (see
 * {@code AdminController}), not routinely. {@link GhsaSyncService#syncDelta} itself no-ops until a
 * baseline has completed at least once.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class GhsaScheduledSync {

    private final GhsaSyncService ghsaSyncService;

    /** Offset from {@code CveOrgScheduledSync}'s 03:30 UTC and {@code SiemensCsafScheduledSync}'s
     *  03:45 UTC slots so none of the three background syncs contend for the same minute. */
    @Scheduled(cron = "0 0 4 * * *", zone = "UTC")
    public void syncDailyDelta() {
        log.info("GHSA scheduled daily delta sync starting");
        SyncResult result = ghsaSyncService.syncDelta();
        log.info("GHSA scheduled daily delta sync complete: {} upserted, {} failed", result.upserted(), result.failed());
    }
}
