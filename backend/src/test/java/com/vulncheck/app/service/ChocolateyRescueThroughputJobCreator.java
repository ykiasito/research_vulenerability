package com.vulncheck.app.service;

import com.vulncheck.app.entity.ResearchJob;
import java.io.InputStream;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

/**
 * REVISE item 3 (senior review 2026-08-29, round 1) throughput measurement: creates a job from {@code
 * chocolatey-rescue-45.csv} — the exact 45 items from job 167 (real-1000.csv) that resolved to a
 * sole Chocolatey match with no corroborating CPE (i.e. {@code ecosystem='chocolatey' AND cpe IS
 * NULL}, extracted 2026-08-29 via {@code SELECT ... FROM identified_products ip JOIN
 * research_job_items rji ... WHERE rji.job_id = 167 AND ip.ecosystem = 'chocolatey' AND ip.cpe IS
 * NULL}) — precisely the population the new {@code rescueCpeAfterRegistryMatchRejected} call in
 * the {@code isSoleChocolateyMatch} branch now fires for on every single row, giving a real,
 * non-extrapolated per-item overhead measurement instead of a guess.
 *
 * <p>Same real-dev-DB {@code @TestPropertySource} pattern as {@link HighConfidenceVerificationPilotJobCreator}
 * / {@link Golden300JobCreator} — user_id=5's {@code nvd} secret (needed so the rescue's live NVD
 * lookup runs at the keyed 700ms interval, not the keyless 6500ms one) only exists in the real
 * {@code vulncheck} DB, not {@code vulncheck_test}.
 *
 * <p>Only persists the job (PENDING); starting it is done separately via the established
 * PROCESSING-spoof + backend restart convention. Throwaway; disabled immediately after use.
 */
@SpringBootTest
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:postgresql://postgres:5432/vulncheck",
        "spring.datasource.username=vulncheck",
        "spring.datasource.password=${POSTGRES_PASSWORD}"
})
@Disabled("Run once (2026-08-29, job 192) to create the chocolatey-rescue throughput measurement "
        + "job against the real dev DB for REVISE item 3. Left disabled so it can never re-fire on "
        + "a routine mvn test run — see class javadoc.")
class ChocolateyRescueThroughputJobCreator {

    private static final Long REAL_USER_ID = 5L;

    @Autowired
    private ResearchJobService researchJobService;

    @Test
    void createChocolateyRescueThroughputJob() throws Exception {
        try (InputStream csv = getClass().getClassLoader().getResourceAsStream("chocolatey-rescue-45.csv")) {
            ResearchJob job = researchJobService.createJob(
                    REAL_USER_ID, "chocolatey-rescue-45.csv", csv, ColumnMapping.identity(), false);
            System.out.println("\n=== CREATED CHOCOLATEY RESCUE THROUGHPUT JOB ID: " + job.getId() + " ===\n");
        }
    }
}
