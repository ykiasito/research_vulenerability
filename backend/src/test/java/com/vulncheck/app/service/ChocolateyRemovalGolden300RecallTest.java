package com.vulncheck.app.service;

import com.vulncheck.app.entity.IdentifiedProduct;
import com.vulncheck.app.entity.ResearchJob;
import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.repository.ResearchJobItemRepository;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Transactional;

/**
 * Backlog item 99 (Chocolatey integration removal) no-cost recall re-measurement: runs {@code
 * golden-300.csv} through the real {@link Stage1IdentificationService} directly (static Tier1 +
 * CPE dictionary only — {@code REAL_USER_ID}=5 has only an {@code nvd} provider secret, no Claude
 * key, same as {@link Golden300JobCreator}, so Tier2/Tier3 never fire and this costs nothing)
 * against the real dev DB's populated CPE dictionary/live NVD fallback.
 *
 * <p>Unlike every prior golden-300 measurement (job191/193/195/196, all created via a throwaway
 * {@code *JobCreator} + {@code research_jobs.status} PROCESSING-spoof + backend restart, i.e. a
 * durable write picked up by the real async pipeline), this test method is itself {@link
 * Transactional @Transactional} — {@link ResearchJobService#createJob} joins this same
 * transaction (plain {@code @Transactional}, default {@code REQUIRED} propagation, same calling
 * thread) rather than committing on its own, and Spring's test framework rolls the whole thing
 * back at the end of the test method regardless of outcome. No job, item, or identified-product
 * row from this run is ever visible outside this one JVM process — no backend restart, no durable
 * write, matching this task's own request for a no-write in-process check.
 *
 * <p>Disabled by default, same convention as every other real-dev-DB test in this package — run
 * once by hand (temporarily remove {@code @Disabled}, {@code mvn -Dtest=ChocolateyRemovalGolden300RecallTest test}),
 * read the printed metrics, then restore {@code @Disabled}. Never left enabled for a routine
 * {@code mvn test} run.
 */
@SpringBootTest
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:postgresql://postgres:5432/vulncheck",
        "spring.datasource.username=vulncheck",
        // Resolved from the real POSTGRES_PASSWORD env var passed to this docker run invocation,
        // same as every other real-dev-DB test in this package.
        "spring.datasource.password=${POSTGRES_PASSWORD}"
})
@Disabled("Item 303 (task B, install_url-hostname-driven passesTargetSwGate generalization) "
        + "regression re-check (2026-09-05) against the real dev DB: recall out of 268 (denominator "
        + "updated 2026-09-05 for item 320's Blender/Rufus ground-truth correction, which moved those "
        + "2 rows from the 266-row target bucket's complement into it -- NEEDS RE-MEASUREMENT, the "
        + "265 numerator below predates that correction and is no longer reported), control-row "
        + "false-positive rate out of 32 (denominator updated same way from 34 -- NEEDS "
        + "RE-MEASUREMENT, the 3 numerator below predates the correction) -- both were same-or-better "
        + "than the prior re-measurement below out of the pre-correction 266/34 denominators. "
        + "golden-300.csv has zero non-blank install_url rows, so item 303's own code change (a "
        + "strictly additive install_url-derived declaredTargetSw source) is a structural no-op here "
        + "-- every item still resolves through exactly the same registry-ecosystem-or-none gating "
        + "path as before. The improvement seen is attributable to other already-merged work on this "
        + "branch (item 302's (vendor, product) exact-match fallback), not to this item, and is "
        + "recorded here only to confirm no regression. Run once (2026-08-31, backlog item 99 "
        + "Chocolatey-removal recall re-measurement) against "
        + "the real dev DB -- static/no-AI recall out of 268 (denominator updated 2026-09-05 for item "
        + "320, NEEDS RE-MEASUREMENT, the original 264/266=99.25% predates the correction), "
        + "control-row false-positive rate out of 32 (denominator updated 2026-09-05 for item 320, "
        + "NEEDS RE-MEASUREMENT -- the original 5/34=14.71% predates the correction, and 2 of that "
        + "count's 5 false positives were Blender and Rufus, which item 320 moved out of the control "
        + "bucket entirely, so that original numerator no longer even applies to this denominator), "
        + "no new misses/false-positives attributable to the Chocolatey removal at the time of the "
        + "original measurement (the 2 misses -- Metasploit Framework, OpenSSL -- and, of the "
        + "then-control-row false positives, the 3 still applicable today -- Android Studio, Directory "
        + "Opus, Ditto -- resolved via ecosystem=null, i.e. the untouched CPE-dictionary path, not the "
        + "removed registry). Left disabled so it can "
        + "never re-fire on a routine mvn test run — see class javadoc.")
class ChocolateyRemovalGolden300RecallTest {

    private static final Long REAL_USER_ID = 5L;

    @Autowired
    private ResearchJobService researchJobService;
    @Autowired
    private ResearchJobItemRepository researchJobItemRepository;
    @Autowired
    private Stage1IdentificationService stage1IdentificationService;

    @Test
    @Transactional
    void measureGolden300RecallAfterChocolateyRemoval() throws Exception {
        ResearchJob job;
        try (InputStream csv = getClass().getClassLoader().getResourceAsStream("golden-300.csv")) {
            job = researchJobService.createJob(
                    REAL_USER_ID, "golden-300-no-chocolatey-recheck.csv", csv, ColumnMapping.identity(), false);
        }
        List<ResearchJobItem> items = researchJobItemRepository.findByJobIdOrderById(job.getId());

        // Keyed on (raw product_name, version) — the same pair test-data/compute_golden_300_metrics*.py
        // uses to join golden-300.csv's ground truth against a job's actual results. A record key
        // (rather than a delimiter-joined string) avoids any separator-character collision risk and
        // keeps this file plain text for `git diff`/`gh pr diff` (backlog item 323 — a literal "\0"
        // separator here previously made git treat the whole file as binary).
        Map<ProductKey, String> expectedOutcomeByKey = new HashMap<>();
        try (InputStream csv = getClass().getClassLoader().getResourceAsStream("golden-300.csv");
                CSVParser parser = CSVParser.parse(new InputStreamReader(csv, StandardCharsets.UTF_8),
                        CSVFormat.DEFAULT.builder().setHeader().setSkipHeaderRecord(true).build())) {
            for (CSVRecord record : parser) {
                expectedOutcomeByKey.put(key(record.get("product_name"), record.get("version")),
                        record.get("expected_outcome"));
            }
        }

        int targetTotal = 0;
        int targetIdentified = 0;
        int controlTotal = 0;
        int controlFalsePositive = 0;
        int missingExpected = 0;

        for (ResearchJobItem item : items) {
            String expectedOutcome = expectedOutcomeByKey.get(key(item.getRawProductName(), item.getVersion()));
            if (expectedOutcome == null) {
                missingExpected++;
                System.out.println("NO EXPECTED OUTCOME FOUND FOR: " + item.getRawProductName() + " " + item.getVersion());
                continue;
            }
            Optional<IdentifiedProduct> result = stage1IdentificationService.identify(item, REAL_USER_ID);
            boolean identified = result.isPresent();
            if ("UNIDENTIFIED".equals(expectedOutcome)) {
                controlTotal++;
                if (identified) {
                    controlFalsePositive++;
                    System.out.println("CONTROL-ROW FALSE POSITIVE: " + item.getRawProductName() + " "
                            + item.getVersion() + " -> ecosystem=" + result.get().getEcosystem()
                            + " cpe=" + result.get().getCpe());
                }
            } else {
                targetTotal++;
                if (identified) {
                    targetIdentified++;
                } else {
                    System.out.println("IDENTIFICATION-TARGET MISS: " + item.getRawProductName() + " " + item.getVersion());
                }
            }
        }

        System.out.println("\n=== backlog item 99 (Chocolatey removal) golden-300 static recall re-measurement ===");
        System.out.println("missingExpected=" + missingExpected);
        System.out.printf("identification recall: %d/%d = %.4f%n", targetIdentified, targetTotal,
                targetTotal == 0 ? 0.0 : (double) targetIdentified / targetTotal);
        System.out.printf("control-row false-positive rate: %d/%d = %.4f%n", controlFalsePositive, controlTotal,
                controlTotal == 0 ? 0.0 : (double) controlFalsePositive / controlTotal);
    }

    private record ProductKey(String productName, String version) {
    }

    private static ProductKey key(String productName, String version) {
        return new ProductKey(productName, version);
    }
}
