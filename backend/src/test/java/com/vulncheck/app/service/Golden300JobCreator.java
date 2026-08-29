package com.vulncheck.app.service;

import com.vulncheck.app.entity.ResearchJob;
import java.io.InputStream;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

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
 * <p>Disabled by default (see prior incidents with {@code RealAiValidationJobCreator} /
 * {@code Real400V2JobCreator} / {@code Real1000ThroughputJobCreator}): a live job-creating
 * {@code @SpringBootTest} left enabled would silently create another job against the real
 * dev DB on every {@code mvn test} run. Re-enable deliberately, by hand, never left on.</p>
 */
@SpringBootTest
@Disabled("Live job-creating @SpringBootTest that would persist another job against the real "
        + "dev DB on every mvn test invocation. Re-enable deliberately, by hand, never left on "
        + "-- see class javadoc.")
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
