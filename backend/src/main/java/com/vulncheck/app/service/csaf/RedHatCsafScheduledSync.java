package com.vulncheck.app.service.csaf;

import com.vulncheck.app.service.csaf.RedHatCsafSyncService.SyncResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Daily automatic delta sync for Red Hat CSAF advisories ({@code changes.csv}/{@code
 * deletions.csv}) — {@link RedHatCsafSyncService#syncBaseline} is deliberately NOT scheduled here,
 * same rationale as {@code SiemensCsafScheduledSync}/{@code CveOrgScheduledSync}: a full archive
 * reload is meant to be triggered once manually (see {@code AdminController}), not routinely.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class RedHatCsafScheduledSync {

    private final RedHatCsafSyncService redHatCsafSyncService;

    /** Offset from {@code CveOrgScheduledSync}'s 03:30 UTC, {@code SiemensCsafScheduledSync}'s 03:45
     *  UTC, and {@code GhsaSyncService}'s 04:00 UTC slots so none of these background syncs contend
     *  for the same minute. */
    @Scheduled(cron = "0 15 4 * * *", zone = "UTC")
    public void syncDailyDelta() {
        log.info("Red Hat CSAF scheduled daily delta sync starting");
        SyncResult result = redHatCsafSyncService.syncDelta();
        log.info("Red Hat CSAF scheduled daily delta sync complete: {} upserted, {} failed", result.upserted(), result.failed());
    }
}
