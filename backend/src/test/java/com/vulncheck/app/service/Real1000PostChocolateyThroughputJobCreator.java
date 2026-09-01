package com.vulncheck.app.service;

import com.vulncheck.app.entity.ResearchJob;
import java.io.InputStream;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

/**
 * Re-measures the 1,000-item throughput job (closed-mode backlog item 175, 2026-09-02) against
 * {@code test-data/real-1000.csv} — the same CSV, same {@code bundledComponentCheckEnabled=false},
 * and the same user_id=5 (only an {@code nvd} provider secret configured, no Claude key, so
 * processing runs static Tier1+Tier2 only, no real Claude API spend) as job 167
 * ({@link Real1000ThroughputJobCreator}, 2026-08-28, wall clock 28m22s). Job 167 predates the full
 * removal of the Chocolatey registry (PR#55, {@code feature/remove-chocolatey-integration}, merged
 * to {@code master}) — job 167's own per-item timings showed Chocolatey queries accounted for 68%
 * of registry wait time (8,599,991ms), so this re-measurement is needed to get a current wall-clock
 * number for {@code docs/spec/nfr-status-2026-08.md} section 3 now that that path no longer runs.
 *
 * <p>Same real-dev-DB {@code @TestPropertySource} override as {@link Golden300JobCreator} /
 * {@link HighConfidenceVerificationPilotJobCreator} — user_id=5's {@code nvd} secret and the job
 * 167 history this is compared against only exist in the real dev DB, not {@code vulncheck_test}.
 * Runs through the real {@link ResearchJobService} so processing happens in the app's own JVM;
 * this class only persists the job (PENDING), it never processes it — starting it is done
 * separately by spoofing {@code research_jobs.status} to {@code PROCESSING} and letting
 * {@link StuckJobResumer} pick it up on the next backend restart, per this project's established
 * manual-launch convention. Throwaway; not part of the permanent suite.
 *
 * <p>Disabled by default (see prior incidents with {@code RealAiValidationJobCreator} /
 * {@code Real400V2JobCreator} / {@link Real1000ThroughputJobCreator}): a live job-creating
 * {@code @SpringBootTest} left enabled would silently create another 1,000-item job against the
 * real dev DB on every {@code mvn test} run. Re-enable deliberately, by hand, never left on.</p>
 */
@SpringBootTest
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:postgresql://postgres:5432/vulncheck",
        "spring.datasource.username=vulncheck",
        // Resolved from the real POSTGRES_PASSWORD env var passed to this docker run invocation
        // (e.g. `docker run --env-file .env ...`) rather than a literal value checked into source.
        "spring.datasource.password=${POSTGRES_PASSWORD}"
})
@Disabled("Run once (2026-09-02, job 204) to create the post-Chocolatey-removal re-measurement of "
        + "job 167's 1,000-item throughput run against the real dev DB. Left disabled so it can "
        + "never re-fire (and re-persist) on a routine mvn test run -- see class javadoc.")
class Real1000PostChocolateyThroughputJobCreator {

    private static final Long REAL_USER_ID = 5L;

    @Autowired
    private ResearchJobService researchJobService;

    @Test
    void createReal1000PostChocolateyThroughputJob() throws Exception {
        try (InputStream csv = getClass().getClassLoader().getResourceAsStream("real-1000.csv")) {
            ResearchJob job = researchJobService.createJob(
                    REAL_USER_ID, "real-1000.csv", csv, ColumnMapping.identity(), false);
            System.out.println("\n=== CREATED REAL1000-POST-CHOCOLATEY-THROUGHPUT JOB ID: "
                    + job.getId() + " ===\n");
        }
    }
}
