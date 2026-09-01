package com.vulncheck.app.service;

import com.vulncheck.app.entity.ResearchJob;
import java.io.InputStream;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

/**
 * Creates the first AI-included run of the golden-300 accuracy benchmark (approved 2026-08-29
 * against the then-available Claude balance). golden-300.csv has only ever been run static-only
 * before (job 168, no Claude key configured) — this is the first measurement of AI-included
 * accuracy on this dataset. Full 300 items would have risked exceeding the available balance at
 * the $0.005/item cost cap, so this runs a stratified ~250-item subsample instead ({@code
 * test-data/sample_golden_250.py}, seed 20260829, preserves the IDENTIFIED_REGISTRY /
 * IDENTIFIED_CPE / UNIDENTIFIED ratio from golden-300.csv): {@code golden-250-ai-test.csv}, run
 * with a total budget cap set below the available balance.
 *
 * <p>Owned by user_id=5, which has both an {@code nvd} and a {@code claude} key configured in
 * {@code user_secrets} as of 2026-08-29 (see {@link RealAiValidationJobCreator} and {@link
 * Real400LiveAiJobCreator} for the earlier AI-cost-measurement runs against the same user).
 *
 * <p>Same {@code @TestPropertySource} pattern as the other real-dev-DB job creators above, to
 * target the real {@code vulncheck} database (not {@code vulncheck_test}) so this job actually
 * lands where user_id=5's real Claude key lives.
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
@Disabled("Already run once (job 189, 2026-08-29) to create the golden-250-ai-test.csv AI-included "
        + "accuracy run against the real dev DB. Left disabled so it can never re-fire (and "
        + "re-bill) on a routine mvn test run — see class javadoc.")
class Golden250AiJobCreator {

    private static final Long REAL_USER_ID = 5L;

    @Autowired
    private ResearchJobService researchJobService;

    @Test
    void createGolden250AiJob() throws Exception {
        try (InputStream csv = getClass().getClassLoader().getResourceAsStream("golden-250-ai-test.csv")) {
            ResearchJob job = researchJobService.createJob(
                    REAL_USER_ID, "golden-250-ai-test.csv", csv, ColumnMapping.identity(), false);
            System.out.println("\n=== CREATED GOLDEN-250-AI JOB ID: " + job.getId() + " ===\n");
        }
    }
}
