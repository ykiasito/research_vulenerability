package com.vulncheck.app.service;

import com.vulncheck.app.entity.ResearchJob;
import java.io.InputStream;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

/**
 * Creates the real-cost golden-300 IDENTIFIED_CPE-bucket verification job (68 items, every row from
 * {@code test-data/golden-300.csv} with {@code expected_outcome=IDENTIFIED_CPE} — see
 * {@code test-data/extract_identified_cpe.py}) to measure whether {@code
 * HighConfidenceVerificationService} actually catches the known-limitations "registry match's
 * confidence is lent to an independently-derived CPE" false positives this bucket concentrates.
 * Run only after {@link HighConfidenceVerificationPilotJobCreator}'s 4-item pilot succeeded with no
 * errors, per the task's staged-rollout requirement.
 *
 * <p>Same real-dev-DB / real-key-already-in-user_secrets pattern as {@link RealAiValidationJobCreator}
 * (job 185): {@code src/test/resources/application.yml} hardcodes every ordinary test to {@code
 * vulncheck_test}, so the {@link TestPropertySource} below overrides the datasource for THIS CLASS
 * ONLY so the job actually lands in {@code vulncheck} where user_id=5's real Claude key lives.
 *
 * <p>Cost estimate at creation time: 68 items x up to ~$0.035 (verification) each = ~$2.38 worst
 * case if every single item triggers a verification call and none also draw Tier2/Tier3/Stage4 —
 * real Stage4/Tier2 spend on top of that is possible for whichever of these 68 items also has zero
 * Stage2 findings, but {@code JobCostBudgetService}'s own per-job cap (raised via {@code
 * APP_COST_CAP_PER_ITEM_USD} on the processing container — see {@link
 * HighConfidenceVerificationPilotJobCreator}'s javadoc) is the actual hard backstop: this job is
 * created with the cap set low enough (see the value used when restarting the backend for this run)
 * to keep total realized spend for this one job under $5 regardless of how many of the 68 items
 * actually draw an AI call, without needing pre-flight padding-row guesswork.
 *
 * <p>Only persists the job (PENDING); starting it is done separately by spoofing {@code
 * research_jobs.status} to {@code PROCESSING} and restarting the backend so {@link StuckJobResumer}
 * picks it up. Throwaway; disabled immediately after use, same lesson as every other real-cost job
 * creator in this package.
 */
@SpringBootTest
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:postgresql://postgres:5432/vulncheck",
        "spring.datasource.username=vulncheck",
        // See HighConfidenceVerificationPilotJobCreator's own comment: resolved from the real
        // POSTGRES_PASSWORD env var (docker run --env-file .env ...), not a literal checked-in value.
        "spring.datasource.password=${POSTGRES_PASSWORD}"
})
@Disabled("Run once (2026-08-29) to create the 68-item golden-300 IDENTIFIED_CPE verification job "
        + "against the real dev DB. Left disabled so it can never re-fire (and re-bill) on a "
        + "routine mvn test run — see class javadoc.")
class HighConfidenceVerificationRealAiJobCreator {

    private static final Long REAL_USER_ID = 5L;

    @Autowired
    private ResearchJobService researchJobService;

    @Test
    void createGolden300IdentifiedCpeVerificationJob() throws Exception {
        try (InputStream csv = getClass().getClassLoader().getResourceAsStream("golden300-identified-cpe.csv")) {
            ResearchJob job = researchJobService.createJob(
                    REAL_USER_ID, "golden300-identified-cpe.csv", csv, ColumnMapping.identity(), false);
            System.out.println("\n=== CREATED HIGH-CONFIDENCE-VERIFICATION GOLDEN-300 JOB ID: " + job.getId() + " ===\n");
        }
    }
}
