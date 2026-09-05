package com.vulncheck.app.service;

import com.vulncheck.app.entity.ResearchJob;
import java.io.InputStream;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

/**
 * Creates the 1.0-gate clean 1,000-item throughput + static-accuracy job (2026-08-29) against
 * {@code test-data/real-1000.csv} (real registry versions + desktop software + generic-name
 * collisions + fictitious products; already reviewed by tester/senior-reviewer per
 * {@code docs/spec/test-design-policy.md}). Deliberately created with
 * {@code bundledComponentCheckEnabled=false} — this run measures the core identification
 * pipeline only, not the opt-in bundled-package feature. Owned by user_id=5, same as the prior
 * job 30 (1000-item stress test) and job 31 (350-item real-version run) this supersedes — as of
 * this run that user has no provider secret configured at all ({@code user_secrets} is empty in
 * the real dev DB, not just missing a Claude key as previously assumed here), so processing runs
 * static Tier1 only, no real Claude API spend either way. Runs through the real
 * {@link ResearchJobService} so processing happens in the app's own JVM; this class only
 * persists the job (PENDING), it never processes it — starting it is done separately by
 * spoofing {@code research_jobs.status} to {@code PROCESSING} and letting
 * {@link StuckJobResumer} pick it up on the next backend restart, per this project's
 * established manual-launch convention. Throwaway; not part of the permanent suite.
 *
 * <p>Same {@code @TestPropertySource} pattern as {@link Golden300JobCreator} to target the real
 * {@code vulncheck} database rather than {@code vulncheck_test}: user_id=5's job history and any
 * provider secrets only exist in the real dev DB, and {@code vulncheck_test} would not have them
 * (this class previously lacked this override, so its default {@code mvn test} run pointed at
 * {@code vulncheck_test} and failed on the {@code research_jobs_user_id_fkey} constraint).
 *
 * <p>Disabled by default (see prior incidents with {@code RealAiValidationJobCreator} /
 * {@code Real400V2JobCreator}): a live job-creating {@code @SpringBootTest} left enabled would
 * silently create another 1,000-item job against the real dev DB on every {@code mvn test} run.
 * Re-enable deliberately (remove the annotation, run once by hand, re-add it) rather than
 * leaving it on.</p>
 */
@SpringBootTest
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:postgresql://postgres:5432/vulncheck",
        "spring.datasource.username=vulncheck",
        // Resolved from the real POSTGRES_PASSWORD env var passed to this docker run invocation
        // (e.g. `docker run --env-file .env ...`) rather than a literal value checked into source.
        "spring.datasource.password=${POSTGRES_PASSWORD}"
})
@Disabled("Live job-creating @SpringBootTest that would persist another 1,000-item job against "
        + "the real dev DB on every mvn test invocation. Re-enable deliberately, by hand, never "
        + "left on — see class javadoc.")
class Real1000ThroughputJobCreator {

    private static final Long REAL_USER_ID = 5L;

    @Autowired
    private ResearchJobService researchJobService;

    @Test
    void createReal1000ThroughputJob() throws Exception {
        try (InputStream csv = getClass().getClassLoader().getResourceAsStream("real-1000.csv")) {
            ResearchJob job = researchJobService.createJob(
                    REAL_USER_ID, "real-1000.csv", csv, ColumnMapping.identity(), false);
            System.out.println("\n=== CREATED REAL1000-THROUGHPUT JOB ID: " + job.getId() + " ===\n");
        }
    }
}
