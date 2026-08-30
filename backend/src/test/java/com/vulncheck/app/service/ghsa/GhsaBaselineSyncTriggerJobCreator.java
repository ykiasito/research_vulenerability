package com.vulncheck.app.service.ghsa;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Live smoke-test trigger for {@link GhsaSyncService#syncBaseline()} against the real GHSA
 * advisory-database tarball — the mirror's baseline has never completed successfully (see
 * {@code ghsa_sync_state.last_sync_error}), so this exercises the actual full ~34,768-document
 * download+walk against the real DB, the same way {@code RedHatCsafDeltaSyncTriggerJobCreator}
 * exercises Red Hat CSAF's delta sync. Throwaway; not part of the permanent suite (same
 * convention as {@code ReverifyJobCreator}/{@code FpCheckJobCreator} — not named {@code *Test} so
 * Surefire's default discovery skips it; run explicitly via {@code -Dtest=...}).
 */
@SpringBootTest
class GhsaBaselineSyncTriggerJobCreator {

    @Autowired
    private GhsaSyncService ghsaSyncService;

    @Test
    void triggerBaselineSync() {
        GhsaSyncService.SyncResult result = ghsaSyncService.syncBaseline();
        System.out.println("\n=== GHSA BASELINE SYNC RESULT: upserted=" + result.upserted()
                + " failed=" + result.failed() + " alreadyRunning=" + result.alreadyRunning() + " ===\n");
    }
}
