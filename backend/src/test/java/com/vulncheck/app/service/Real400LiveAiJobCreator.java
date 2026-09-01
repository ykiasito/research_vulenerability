package com.vulncheck.app.service;

import com.vulncheck.app.entity.ResearchJob;
import java.io.InputStream;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

/**
 * Creates the full 400-item AI-included live-cost run (approved 2026-08-29 against the
 * then-available Claude balance, with the spending risk acknowledged) against the corrected
 * {@code real-400.csv} (usage_text round-robin bug fixed 2026-08-25). Owned by user_id=5, which
 * has both an {@code nvd} and a {@code claude} key configured in {@code user_secrets} as of
 * 2026-08-29 (see {@link RealAiValidationJobCreator} for the earlier 150-item cost-measurement
 * run against the same user).
 *
 * <p>Static-only baseline for comparison: job 37 (400 items, 387 IDENTIFIED / 13 UNIDENTIFIED, zero
 * AI cost) — see {@code docs/spec/nfr-status-2026-08.md} section 1.
 *
 * <p>Same {@code @TestPropertySource} pattern as {@link RealAiValidationJobCreator} and {@code
 * com.vulncheck.app.service.osv.OsvBaselineSyncRealDevDbJobCreator} to target the real {@code
 * vulncheck} dev database (not {@code vulncheck_test}) so this job actually lands where user_id=5's
 * real Claude key lives.
 *
 * <p>Runs through the real ResearchJobService so processing happens in the app's own JVM (shared
 * rate limiters); this class only persists the job (PENDING) — starting it is done separately by
 * spoofing {@code research_jobs.status} to {@code PROCESSING} and letting {@link StuckJobResumer}
 * pick it up on the next backend restart. Throwaway; not part of the permanent suite. Disable (add
 * {@code @Disabled}) immediately after use so it can never re-fire (and re-bill) on a routine
 * {@code mvn test} run.
 */
@SpringBootTest
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:postgresql://postgres:5432/vulncheck",
        "spring.datasource.username=vulncheck",
        // Resolved from the real POSTGRES_PASSWORD env var passed to this docker run invocation
        // (e.g. `docker run --env-file .env ...`) rather than a literal value checked into source.
        "spring.datasource.password=${POSTGRES_PASSWORD}"
})
@Disabled("Already run once (job 188, 2026-08-29) to create the 400-item live-AI-cost run job "
        + "against the real dev DB. Left disabled so it can never re-fire (and re-bill) on a "
        + "routine mvn test run — see class javadoc.")
class Real400LiveAiJobCreator {

    private static final Long REAL_USER_ID = 5L;

    @Autowired
    private ResearchJobService researchJobService;

    @Test
    void createReal400LiveAiJob() throws Exception {
        try (InputStream csv = getClass().getClassLoader().getResourceAsStream("real-400.csv")) {
            ResearchJob job = researchJobService.createJob(
                    REAL_USER_ID, "real-400.csv", csv, ColumnMapping.identity(), false);
            System.out.println("\n=== CREATED REAL-400-LIVE-AI JOB ID: " + job.getId() + " ===\n");
        }
    }
}
