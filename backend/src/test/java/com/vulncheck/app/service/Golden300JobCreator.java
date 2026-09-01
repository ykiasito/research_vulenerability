package com.vulncheck.app.service;

import com.vulncheck.app.entity.ResearchJob;
import java.io.InputStream;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

/**
 * Creates the 1.0-gate static-accuracy golden benchmark job (2026-08-29) against {@code
 * test-data/golden-300.csv} (300 rows, every row carrying an independently-verified
 * expected_outcome/expected_ecosystem/expected_package_name/expected_cpe_vendor/
 * expected_cpe_product ground-truth column set — see {@code test-data/golden-300.design.md}).
 * Owned by user_id=5, same as the prior job 30/31/167 this measurement is meant to finally
 * put a real number behind — that user has only an {@code nvd} provider secret configured
 * (no Claude key), so processing runs static Tier1 only, no real Claude API spend. Runs
 * through the real {@link ResearchJobService} so processing happens in the app's own JVM;
 * this class only persists the job (PENDING), it never processes it — starting it is done
 * separately by spoofing {@code research_jobs.status} to {@code PROCESSING} and letting
 * {@link StuckJobResumer} pick it up on the next backend restart, per this project's
 * established manual-launch convention. Throwaway; not part of the permanent suite.
 *
 * <p>Same {@code @TestPropertySource} pattern as {@link HighConfidenceVerificationPilotJobCreator}
 * to target the real {@code vulncheck} database rather than {@code vulncheck_test}: user_id=5's
 * {@code nvd} secret and the job history (168, 189, 190, ...) this re-measurement is meant to be
 * compared against only exist in the real dev DB, and {@code vulncheck_test} would not have them.
 *
 * <p>Disabled by default (see prior incidents with {@code RealAiValidationJobCreator} /
 * {@code Real400V2JobCreator} / {@code Real1000ThroughputJobCreator}): a live job-creating
 * {@code @SpringBootTest} left enabled would silently create another job against the real
 * dev DB on every {@code mvn test} run. Re-enable deliberately, by hand, never left on.</p>
 */
@SpringBootTest
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:postgresql://postgres:5432/vulncheck",
        "spring.datasource.username=vulncheck",
        // Resolved from the real POSTGRES_PASSWORD env var passed to this docker run invocation
        // (e.g. `docker run --env-file .env ...`) rather than a literal value checked into source.
        "spring.datasource.password=${POSTGRES_PASSWORD}"
})
@Disabled("Run once (2026-08-29, job 191) to create the golden-300 no-cost re-measurement job "
        + "against the real dev DB, verifying the Chocolatey/usage_text-tie-break/part=o accuracy "
        + "fixes. Re-run once more (2026-08-30, job 193) for the backlog item 15 P1/P2 chocolatey "
        + "target_sw gate / version-coverage tie-break re-measurement. Re-run once more "
        + "(2026-09-01, job 203) for closed-mode-backlog.md item 172, a static-only no-cost "
        + "regression check of PR#91/item166 (Stage1RegistryIdentification/Stage1AiArbitration "
        + "extracted out of Stage1IdentificationService, claimed zero behavior change) against "
        + "job191's baseline -- user_id=5 has only the nvd secret at the time of this run (no "
        + "claude secret), so this stays Tier1-only. Left disabled so it can never re-fire (and "
        + "re-persist) on a routine mvn test run -- see class javadoc.")
class Golden300JobCreator {

    private static final Long REAL_USER_ID = 5L;

    @Autowired
    private ResearchJobService researchJobService;

    @Test
    void createGolden300Job() throws Exception {
        try (InputStream csv = getClass().getClassLoader().getResourceAsStream("golden-300.csv")) {
            ResearchJob job = researchJobService.createJob(
                    REAL_USER_ID, "golden-300.csv", csv, ColumnMapping.identity(), false);
            System.out.println("\n=== CREATED GOLDEN-300 JOB ID: " + job.getId() + " ===\n");
        }
    }
}
