package com.vulncheck.app.service;

import com.vulncheck.app.entity.ResearchJob;
import java.io.InputStream;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

/**
 * Tiny (4-item) real-cost pilot for {@code HighConfidenceVerificationService} — run BEFORE the
 * full 68-item {@link HighConfidenceVerificationRealAiJobCreator} batch, per the task's own
 * staged-rollout requirement (confirm no errors at ~$0.10-$0.15 scale before the larger run,
 * given a prior session's Anthropic balance had run down to $0.04). Same real-dev-DB /
 * real-key-already-in-user_secrets pattern as {@link RealAiValidationJobCreator} (job 185).
 *
 * <p>4 rows sampled from the front of {@code golden300-identified-cpe.csv} (see
 * {@code test-data/extract_identified_cpe.py}) — the golden-300 IDENTIFIED_CPE bucket, i.e.
 * exactly the population {@code HighConfidenceVerificationService} exists to double-check.
 *
 * <p>This class only persists the job row — the actual per-job AI-spend cap ({@code
 * JobCostBudgetService#costCapPerItemUsd}) is applied when the real {@code backend} container
 * processes it, via the {@code APP_COST_CAP_PER_ITEM_USD} environment variable (see
 * docker-compose.yml). The default $0.005/1,000-item cap must be raised for this run: this CSV is
 * deliberately 100% AI-eligible items, which the default (sized for a realistic job where most
 * items resolve for free) would starve after a small handful of calls — see that field's own
 * javadoc. $0.05/item x 4 items = $0.20 cap, comfortably covering 4 verification calls ($0.035
 * reservation each = $0.14 worst case) plus any Tier2/Stage4 spend the same items might also draw.
 *
 * <p>Only persists the job (PENDING); starting it is done separately by spoofing {@code
 * research_jobs.status} to {@code PROCESSING} and restarting the backend (with {@code
 * HIGH_CONFIDENCE_VERIFICATION_ENABLED=true} and a raised {@code APP_COST_CAP_PER_ITEM_USD} passed
 * to that container — see docker-compose.yml) so {@link StuckJobResumer} picks it up. Throwaway;
 * disabled immediately after use for the same reason as every other real-cost job creator in this
 * package — left enabled, it would re-fire (and re-bill) on every subsequent {@code mvn test} run.
 */
@SpringBootTest
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:postgresql://postgres:5432/vulncheck",
        "spring.datasource.username=vulncheck",
        // Resolved from the real POSTGRES_PASSWORD env var passed to this docker run invocation
        // (e.g. `docker run --env-file .env ...`) rather than a literal value checked into source —
        // the hardcoded "vulncheck" placeholder other job-creator classes in this package use is
        // stale against the real dev DB's current password (confirmed live, 2026-08-29: password
        // authentication failed), so it is not repeated here.
        "spring.datasource.password=${POSTGRES_PASSWORD}"
})
@Disabled("Run once (2026-08-29, job 190) to create the 4-item high-confidence-verification pilot "
        + "job against the real dev DB. Left disabled so it can never re-fire (and re-bill) on a "
        + "routine mvn test run — see class javadoc.")
class HighConfidenceVerificationPilotJobCreator {

    private static final Long REAL_USER_ID = 5L;

    @Autowired
    private ResearchJobService researchJobService;

    @Test
    void createPilotJob() throws Exception {
        try (InputStream csv = getClass().getClassLoader().getResourceAsStream("golden300-identified-cpe-pilot.csv")) {
            ResearchJob job = researchJobService.createJob(
                    REAL_USER_ID, "golden300-identified-cpe-pilot.csv", csv, ColumnMapping.identity(), false);
            System.out.println("\n=== CREATED HIGH-CONFIDENCE-VERIFICATION PILOT JOB ID: " + job.getId() + " ===\n");
        }
    }
}
