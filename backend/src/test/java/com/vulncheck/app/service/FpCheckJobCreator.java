package com.vulncheck.app.service;

import com.vulncheck.app.entity.ResearchJob;
import java.io.InputStream;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Creates a research job containing exactly the items that came back UNIDENTIFIED from jobs 30/31,
 * so the CPE-matching redesign + full-dictionary sync can be measured against the precise set of
 * cases they were meant to fix. Runs through the real ResearchJobService so processing happens in
 * the app's own JVM (shared rate limiters). Throwaway; not part of the permanent suite.
 */
@SpringBootTest
class FpCheckJobCreator {

    private static final Long REAL_USER_ID = 5L;

    @Autowired
    private ResearchJobService researchJobService;

    @Test
    void createFpCheckJob() throws Exception {
        try (InputStream csv = getClass().getClassLoader().getResourceAsStream("fpcheck.csv")) {
            ResearchJob job = researchJobService.createJob(
                    REAL_USER_ID, "fpcheck.csv", csv, ColumnMapping.identity(), false);
            System.out.println("\n=== CREATED FPCHECK JOB ID: " + job.getId() + " ===\n");
        }
    }
}
