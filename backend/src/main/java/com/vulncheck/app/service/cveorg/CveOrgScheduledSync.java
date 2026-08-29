package com.vulncheck.app.service.cveorg;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Daily automatic delta sync — small (typically tens of records), safe to run unattended. The full
 * baseline load ({@link CveOrgSyncService#syncBaseline()}) is deliberately NOT scheduled here; see
 * its javadoc for why (size, meant to be triggered once manually after deploying to a properly
 * sized server).
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class CveOrgScheduledSync {

    private final CveOrgSyncService cveOrgSyncService;

    @Scheduled(cron = "0 30 3 * * *", zone = "UTC")
    public void syncDailyDelta() {
        log.info("CVE.org scheduled daily delta sync starting");
        int upserted = cveOrgSyncService.syncDelta();
        log.info("CVE.org scheduled daily delta sync complete: {} records upserted", upserted);
    }
}
