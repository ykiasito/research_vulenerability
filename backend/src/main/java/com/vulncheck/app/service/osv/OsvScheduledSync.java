package com.vulncheck.app.service.osv;

import com.vulncheck.app.service.osv.OsvSyncService.SyncResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Daily automatic delta sync for the OSV mirror — measured ~60 in-scope changes/day (plan §2-2),
 * well within {@code MAX_DOCUMENTS_PER_DELTA_RUN}. {@link OsvSyncService#syncBaseline} is
 * deliberately NOT scheduled here, same rationale as {@code GhsaScheduledSync}/{@code
 * CveOrgScheduledSync}: a full 10-zip re-walk is meant to be triggered once manually, not routinely.
 *
 * <p>05:30 UTC — plan §11's final recommendation (revised from an initial 04:30 UTC once the
 * measured {@code Go/all.zip} {@code last-modified} of ~04:19 UTC showed that slot risked running
 * during the upstream export's own generation window), offset from the other background syncs'
 * 03:30/03:45/04:00/04:15 UTC slots.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class OsvScheduledSync {

    private final OsvSyncService osvSyncService;

    @Scheduled(cron = "0 30 5 * * *", zone = "UTC")
    public void syncDailyDelta() {
        log.info("OSV scheduled daily delta sync starting");
        SyncResult result = osvSyncService.syncDelta();
        log.info("OSV scheduled daily delta sync complete: {} upserted, {} failed", result.upserted(), result.failed());
    }
}
