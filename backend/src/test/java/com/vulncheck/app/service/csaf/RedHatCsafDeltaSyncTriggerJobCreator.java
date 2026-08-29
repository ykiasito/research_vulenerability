package com.vulncheck.app.service.csaf;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Live smoke-test trigger for {@link RedHatCsafSyncService#syncDelta()} against the real Red Hat
 * CSAF feed — deliberately NOT {@code syncBaseline()}: baseline processes the whole ~27,930-document
 * archive in one unbounded call (~6GB raw JSON, ~6M rows), while delta is naturally bounded to
 * {@link RedHatCsafSyncService#MAX_DOCUMENTS_PER_RUN} (2,000) per run — with {@code csaf_sync_state}
 * currently empty, this exercises the code's own documented "no prior baseline" behavior (oldest
 * ~2,000 eligible {@code changes.csv} entries), giving bounded, real ingestion for the smoke test
 * without inventing a new capping mechanism. Throwaway; not part of the permanent suite (same
 * convention as {@code ReverifyJobCreator}/{@code FpCheckJobCreator} — not named {@code *Test} so
 * Surefire's default discovery skips it; run explicitly via {@code -Dtest=...}).
 */
@SpringBootTest
class RedHatCsafDeltaSyncTriggerJobCreator {

    @Autowired
    private RedHatCsafSyncService redHatCsafSyncService;

    @Test
    void triggerDeltaSync() {
        RedHatCsafSyncService.SyncResult result = redHatCsafSyncService.syncDelta();
        System.out.println("\n=== RED HAT CSAF DELTA SYNC RESULT: upserted=" + result.upserted()
                + " failed=" + result.failed() + " alreadyRunning=" + result.alreadyRunning() + " ===\n");
    }
}
