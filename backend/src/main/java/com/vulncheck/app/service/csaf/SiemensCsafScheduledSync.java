package com.vulncheck.app.service.csaf;

import com.vulncheck.app.service.csaf.SiemensCsafSyncService.SyncResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Daily automatic delta sync for Siemens CSAF advisories — small (a handful of new/updated
 * advisories on a typical day), safe to run unattended. {@link SiemensCsafSyncService#syncBaseline}
 * is deliberately NOT scheduled here, same rationale as {@code CveOrgScheduledSync}: a full re-walk
 * of the feed is meant to be triggered once manually (see {@code AdminController}), not routinely.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class SiemensCsafScheduledSync {

    private final SiemensCsafSyncService siemensCsafSyncService;

    /** Offset from {@code CveOrgScheduledSync}'s 03:30 UTC slot so the two background syncs don't
     *  contend for the same minute. */
    @Scheduled(cron = "0 45 3 * * *", zone = "UTC")
    public void syncDailyDelta() {
        log.info("Siemens CSAF scheduled daily delta sync starting");
        SyncResult result = siemensCsafSyncService.syncDelta();
        log.info("Siemens CSAF scheduled daily delta sync complete: {} upserted, {} failed", result.upserted(), result.failed());
    }
}
