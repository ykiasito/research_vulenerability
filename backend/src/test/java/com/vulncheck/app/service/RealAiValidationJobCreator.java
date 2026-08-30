package com.vulncheck.app.service;

import com.vulncheck.app.entity.ResearchJob;
import java.io.InputStream;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

/**
 * Creates a 150-item real-cost-measurement research job (sampled from real-1000.csv, excluding
 * every product+version pair already present in golden-300.csv so this run doesn't double up with
 * the separate accuracy benchmark) to measure real, actual Claude API spend end-to-end against the
 * real, running pipeline with a real Claude API key — see docs/spec/nfr-status-2026-08.md for the
 * $5/1,000-item cost target this measures against. Owned by user_id=5 (has a Claude key configured
 * in user_secrets as of 2026-08-28; corrected from an earlier hardcoded user_id=4, which has no key
 * configured and would have silently fallen back to the no-AI-key degraded path instead of
 * exercising real billed calls).
 *
 * <p>{@code src/test/resources/application.yml} deliberately hardcodes every test to {@code
 * vulncheck_test} (no real users/secrets live there) so `mvn test` can never accidentally touch the
 * real dev database — the {@link TestPropertySource} below overrides the datasource for THIS CLASS
 * ONLY, same precedented pattern as {@code
 * com.vulncheck.app.service.osv.OsvBaselineSyncRealDevDbJobCreator}, so this job actually lands in
 * {@code vulncheck} where user_id=5's real Claude key lives.
 *
 * <p>Runs through the real ResearchJobService so processing happens in the app's own JVM (shared
 * rate limiters); this class only persists the job (PENDING) — starting it is done separately by
 * spoofing {@code research_jobs.status} to {@code PROCESSING} and letting {@link StuckJobResumer}
 * pick it up on the next backend restart. Throwaway; not part of the permanent suite. Disable (add
 * {@code @Disabled}) immediately after use, same lesson as {@code Real1000ThroughputJobCreator}'s
 * javadoc — a live job-creating {@code @SpringBootTest} left enabled would re-fire (and re-bill)
 * against the real dev DB on every subsequent {@code mvn test} run.
 */
@SpringBootTest
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:postgresql://postgres:5432/vulncheck",
        "spring.datasource.username=vulncheck",
        "spring.datasource.password=vulncheck"
})
@Disabled("Already run once (job 185, 2026-08-29) to create the 150-item real-cost-measurement "
        + "job against the real dev DB. Left disabled so it can never re-fire (and re-bill) on a "
        + "routine mvn test run — see class javadoc.")
class RealAiValidationJobCreator {

    private static final Long REAL_USER_ID = 5L;

    @Autowired
    private ResearchJobService researchJobService;

    @Test
    void createRealAiValidationJob() throws Exception {
        try (InputStream csv = getClass().getClassLoader().getResourceAsStream("real-150-cost-test.csv")) {
            ResearchJob job = researchJobService.createJob(
                    REAL_USER_ID, "real-150-cost-test.csv", csv, ColumnMapping.identity(), false);
            System.out.println("\n=== CREATED REAL-AI-VALIDATION JOB ID: " + job.getId() + " ===\n");
        }
    }
}
