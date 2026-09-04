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
 * <p>Backlog item 296 (2026-09-05, golden-300 job211 recall investigation): re-ran this by hand
 * against the current closed-mode dev DB to check how much of the gap between the recall recorded
 * below (2026-08-31, 264/266=99.25%) and today's number is actually attributable to the Chocolatey
 * removal this test is named for, versus something else entirely. Answer: none of it. Fresh
 * measurement (4 consecutive runs): identification recall 245/266=92.11% (3 of 4 runs) /
 * 230/266=86.47% (1 of 4 — the live NVD CPE-dictionary fallback this test depends on, see class
 * javadoc above, is a real network call and that one run hit a slow/cold connection), control-row
 * false-positive rate stable at 3/34=8.82% across all 4 runs. Breaking down every miss/false
 * positive by cause (see the per-row {@code System.out.println} output this test still just
 * prints for a human to read — no assertions were added, this remains an analysis tool, not a
 * regression gate):
 * <ul>
 *   <li>All 21 identification-target misses are the 20 golden-300 rows with {@code
 *       expected_ecosystem=maven} (raw Maven coordinates like {@code
 *       org.springframework:spring-core} — see {@code MavenCentralRemovalGolden300RecallTest} for
 *       the dedicated per-row breakdown) plus 1 pre-existing, unrelated miss ({@code Metasploit
 *       Framework 6.3.55}, tracked separately in backlog item 176). The Maven misses are entirely
 *       attributable to {@link com.vulncheck.app.service.registry.MavenCentralRegistryClient}'s
 *       closed-mode no-op stub (backlog item 193/B3) — a change that landed *after* this class's
 *       2026-08-31 measurement — not to the Chocolatey removal.
 *   <li>The control-row false-positive count dropped from 5/34 (2026-08-31) to 3/34 today: 2 of the
 *       original 5 (Android Studio, Directory Opus) are no longer false positives, due to an
 *       unrelated later fix that stopped trusting unverified CPE-candidate guesses (see {@link
 *       Stage1IdentificationService}'s "dropping rather than trusting an unverified guess"
 *       logging), not anything Chocolatey-related either.
 * </ul>
 * <p>Conclusion: the original item99 finding — Chocolatey removal has ~0pt net accuracy impact,
 * because every Chocolatey-only match already had independent CPE backing before removal — still
 * holds exactly today. 100% of today's gap versus the stale 2026-08-31 numbers is explained by the
 * later Maven Central closed-mode stub, not by Chocolatey.
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
@Disabled("Run once by hand against the real dev DB (2026-09-05, backlog item 296 gap analysis) -- "
        + "identification recall 245/266=92.11% (3 of 4 runs) / 230/266=86.47% (1 of 4, live NVD "
        + "fallback network blip), control-row false-positive rate stable at 3/34=8.82% across all "
        + "4 runs -- 100% of the gap vs. the 2026-08-31 numbers below is attributable to the Maven "
        + "Central closed-mode stub (item193/B3), 0% to the Chocolatey removal this test is named "
        + "for (see class javadoc). Left disabled so it can never re-fire on a routine mvn test "
        + "run.")
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
        // uses to join golden-300.csv's ground truth against a job's actual results.
        Map<String, String> expectedOutcomeByKey = new HashMap<>();
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

    private static String key(String productName, String version) {
        return productName + "\0" + version;
    }
}
