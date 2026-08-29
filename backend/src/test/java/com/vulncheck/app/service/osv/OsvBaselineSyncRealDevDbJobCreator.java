package com.vulncheck.app.service.osv;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

/**
 * One-off, task-directed trigger for {@link OsvSyncService#syncBaseline()} against the REAL dev
 * database ({@code vulncheck}), not {@code vulncheck_test} — step 5 of the OSV mirror A/B gate
 * follow-up task (V25 rollout). {@code src/test/resources/application.yml} deliberately hardcodes
 * every test to {@code vulncheck_test} (see that file's own comment) specifically so `mvn test`
 * can never accidentally touch the real dev database; the {@link TestPropertySource} below
 * overrides the datasource for THIS CLASS ONLY (higher precedence than the classpath test
 * application.yml — does not affect any other test class or a plain `mvn test` run) and must only
 * ever be invoked explicitly via {@code -Dtest=OsvBaselineSyncRealDevDbJobCreator}, never picked up
 * by a routine test run (hence no {@code *Test} suffix, same convention as {@code
 * OsvMirrorLiveApiComparisonJobCreator}/{@code GhsaBaselineSyncTriggerJobCreator}).
 *
 * <p>{@code osvSyncService.syncBaseline()} only ever touches {@code osv_advisories}/{@code
 * osv_affected_packages}/{@code osv_affected_ranges}/{@code osv_affected_versions}/{@code
 * osv_sync_state}/{@code osv_sync_failures} (see that service's own javadoc) — it does not read or
 * write {@code research_jobs}, {@code ghsa_advisories}, {@code csaf_advisories}, {@code users}, or
 * any other existing real-data table, so this is safe to run against the real dev database.
 *
 * <p>Throwaway; delete after the V25 rollout task is done (or leave as a documented one-off — same
 * convention as the other {@code *JobCreator} classes in this package).
 */
@SpringBootTest
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:postgresql://postgres:5432/vulncheck",
        "spring.datasource.username=vulncheck",
        "spring.datasource.password=vulncheck"
})
class OsvBaselineSyncRealDevDbJobCreator {

    @Autowired
    private OsvSyncService osvSyncService;

    @Test
    void runBaselineSyncAgainstRealDevDb() {
        System.out.println("\n=== OSV BASELINE SYNC AGAINST REAL DEV DB (vulncheck) — starting ===\n");
        OsvSyncService.SyncResult result = osvSyncService.syncBaseline();
        System.out.println("\n=== OSV BASELINE SYNC AGAINST REAL DEV DB (vulncheck) — RESULT: upserted="
                + result.upserted() + " failed=" + result.failed() + " alreadyRunning=" + result.alreadyRunning()
                + " ===\n");
    }
}
