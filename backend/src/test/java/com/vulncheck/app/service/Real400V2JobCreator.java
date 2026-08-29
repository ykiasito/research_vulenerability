package com.vulncheck.app.service;

import com.vulncheck.app.entity.ResearchJob;
import java.io.InputStream;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Creates a re-run of the 400-item real400 validation job (see {@link RealAiValidationJobCreator},
 * job 34) against the corrected {@code real-400.csv} (usage_text round-robin bug fixed 2026-08-25,
 * see {@code test-data/real-400.design.md}), now that the file has passed mandatory second-engineer
 * review (PASS-with-notes) per {@code docs/spec/test-design-policy.md}. Owned by user_id=5 (has a
 * Claude key configured in user_secrets — the only row in that table). Runs through the real
 * ResearchJobService so processing happens in the app's own JVM (shared rate limiters); this class
 * only persists the job, it never processes it. Throwaway; not part of the permanent suite.
 *
 * <p><b>Disabled (senior review, round 4, 2026-08-26):</b> despite its own javadoc above saying
 * "throwaway, not part of the permanent suite", this is a live {@code @SpringBootTest} that runs on
 * every {@code mvn test} invocation, creating a real 400-item research job against this dev
 * environment's production-pattern database, hardcoded to {@code user_id=5}. Currently harmless
 * because {@code user_id=5} only has an {@code nvd} provider secret (no Claude key) in
 * {@code user_secrets} — but the moment a Claude key is ever configured for that user, every future
 * {@code mvn test} run would silently spend real API money creating (and, via the app's own job
 * processing, running) a full 400-item job. Left in place rather than deleted since this exact
 * one-off "create a real job via the real ResearchJobService" pattern was reused for jobs 36/37/38's
 * validation and is useful institutional knowledge of how that was done — re-enable deliberately
 * (remove this annotation, run once by hand, re-add it) rather than letting it run unattended.</p>
 */
@SpringBootTest
@Disabled("Live job-creating @SpringBootTest that runs on every mvn test invocation against a "
        + "production-pattern DB (hardcoded user_id=5) — currently harmless only because that user "
        + "has no Claude key configured; would silently spend real API money the moment one is "
        + "added. See class javadoc (senior review, round 4, 2026-08-26). Re-enable deliberately, "
        + "by hand, never left on.")
class Real400V2JobCreator {

    private static final Long REAL_USER_ID = 5L;

    @Autowired
    private ResearchJobService researchJobService;

    @Test
    void createReal400V2Job() throws Exception {
        try (InputStream csv = getClass().getClassLoader().getResourceAsStream("real400v2.csv")) {
            ResearchJob job = researchJobService.createJob(
                    REAL_USER_ID, "real400v2.csv", csv, ColumnMapping.identity(), false);
            System.out.println("\n=== CREATED REAL400V2 JOB ID: " + job.getId() + " ===\n");
        }
    }
}
