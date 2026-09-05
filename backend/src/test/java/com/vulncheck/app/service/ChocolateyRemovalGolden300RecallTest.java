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
 * against the real dev DB's populated {@code cpe_dictionary} mirror. This is a 100% local-DB-read
 * measurement with zero network calls in Tier1 — see {@link Stage1IdentificationService}'s own
 * class javadoc (closed-mode backlog item 273/B4): {@link Stage1IdentificationService#fuzzyMatchCpe}
 * itself still exists, but the live, single-page NVD CPE API call it used to fall back to has been
 * physically deleted on this branch, not just disabled, so despite this class's name there is no
 * "live NVD fallback" for this test to depend on (a first-pass version of the writeup below
 * incorrectly claimed there was — see the correction paragraph further down).
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
 * measurement, taken after also syncing {@code backend/src/test/resources/golden-300.csv} from the
 * canonical {@code test-data/golden-300.csv} (backlog item 300 — the two copies had drifted: 2
 * rows, Blender 4.2.1 and Rufus 4.5, were stale here as UNIDENTIFIED control rows from before a
 * deeper NVD CPE paging re-check corrected them to IDENTIFIED_CPE in the canonical file), run 3
 * consecutive times with identical results every time (fully deterministic, as expected for a
 * 100% local-DB-read path — see above): identification recall 247/268=92.16%, control-row
 * false-positive rate 1/32=3.13% (just {@code Ditto 3.24.234.0}). 247/268=92.16% is an exact match
 * for the separately-run, full-pipeline job216 measurement recorded in {@code
 * docs/spec/closed-mode-plan.md} §6-2 — this static-only, no-cost, in-process check cross-verifies
 * against that job.
 *
 * <p><b>Correction (2026-09-05, senior review caught this in the first pass of this writeup):</b>
 * the first pass claimed a single divergent run seen at the time (230/266, vs. a stable 245/266
 * the other 3 times, both numbers from before the golden-300.csv sync above) was caused by "live
 * NVD fallback network flakiness". That mechanism does not exist on this branch — see the opening
 * paragraph above; {@code identify()}'s CPE-dictionary path ({@link
 * Stage1IdentificationService#localCpeLookup}/{@link Stage1IdentificationService#findByNameVariants})
 * is 100% local reads, and re-running 3 times after the CSV sync produced the identical 247/268
 * every single time, confirming this path really is fully deterministic. The actual cause of that
 * one earlier divergent run is unknown; the most plausible explanation is a DB-state difference at
 * the time (e.g. a registry/CPE mirror sync running concurrently against the same dev DB), not
 * anything intrinsic to this test, to network I/O, or to Chocolatey.
 *
 * <p>Breaking down every miss/false positive by cause (see the per-row {@code
 * System.out.println} output this test still just prints for a human to read — no assertions were
 * added, this remains an analysis tool, not a regression gate). The old (2026-08-31) measurement
 * had 2 identification-target misses ({@code Metasploit Framework 6.3.55}, {@code OpenSSL 3.3.1})
 * out of 266 targets; today's has 21 misses out of 268 targets. The full accounting of that
 * difference (+2 targets, +19 misses) is three independent effects, not two — one of them not
 * fully identified when the second-to-last revision of this writeup was reviewed:
 * <ul>
 *   <li><b>+20 misses, Maven Central (item193/B3):</b> all 20 golden-300 rows with {@code
 *       expected_ecosystem=maven} (raw Maven coordinates like {@code
 *       org.springframework:spring-core} — see {@code MavenCentralRemovalGolden300RecallTest} for
 *       the dedicated per-row breakdown) are now misses, entirely attributable to {@link
 *       com.vulncheck.app.service.registry.MavenCentralRegistryClient}'s closed-mode no-op stub — a
 *       change that landed *after* this class's 2026-08-31 measurement. Not Chocolatey-related.
 *   <li><b>&minus;1 miss, {@code OpenSSL 3.3.1} (backlog item 176):</b> this was one of the 2
 *       original misses and is a hit today. Confirmed in code, not guessed: {@link
 *       Stage1IdentificationService#selectFallbackCpeCandidateAfterRegistryDistrust} (added for
 *       backlog item 176, job203 root-cause — see that method's own call site's comment, which
 *       names {@code openssl:openssl} directly as the motivating case) re-checks the remaining CPE
 *       candidate pool after a registry match is distrusted, instead of silently going
 *       UNIDENTIFIED the way this class's 2026-08-31 measurement predates. Not Chocolatey-related
 *       either — {@code Metasploit Framework 6.3.55}, the other original miss, is untouched by this
 *       fix and is still a miss today (one of 5 static CPE-dictionary vendor/product mismatches
 *       tracked separately in closed-mode backlog item 299).
 *   <li><b>+2 targets, 0 net miss change, golden-300.csv ground-truth correction (item300):</b> the
 *       sync moved Blender and Rufus out of the control-row bucket entirely — they were never real
 *       false positives this app produced, they were mis-labeled ground truth this test was scoring
 *       against. Both now correctly land in the identification-target bucket as IDENTIFIED_CPE, and
 *       both resolve to exactly the expected CPE ({@code cpe:2.3:a:blender:blender:...} and {@code
 *       cpe:2.3:a:akeo:rufus:...} respectively — see the {@code BLENDER/RUFUS RESOLVED-CPE CHECK}
 *       output this test now prints for these two rows), so this widens the denominator by 2
 *       without adding or removing any miss.
 * </ul>
 * <p>Separately, the control-row false-positive count dropped from 5/34 (2026-08-31, stale
 * numbers) to 1/32 today, for two reasons — neither Chocolatey-related: the item300 CSV sync
 * above (Blender/Rufus leaving the control-row bucket, as described above), plus Android Studio
 * and Directory Opus independently no longer being false positives due to an unrelated later code
 * fix that stopped trusting unverified CPE-candidate guesses (see {@link
 * Stage1IdentificationService}'s "dropping rather than trusting an unverified guess" logging).
 * <p>Conclusion: the original item99 finding — Chocolatey removal has ~0pt net accuracy impact,
 * because every Chocolatey-only match already had independent CPE backing before removal — still
 * holds exactly today: 0% of today's gap versus the stale 2026-08-31 numbers is attributable to
 * Chocolatey. The gap itself is explained by three independent, unrelated-to-each-other causes
 * (Maven Central item193/B3, the OpenSSL item176 fix, and the item300 ground-truth correction), not
 * a clean two-factor split.
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
@Disabled("Run once by hand against the real dev DB (2026-09-05, backlog item 296/300 gap analysis, "
        + "post golden-300.csv sync) -- identification recall 247/268=92.16%, fully deterministic "
        + "across 3 repeated runs (this path is 100% local DB reads, see class javadoc), and an "
        + "exact match for job216's full-pipeline measurement (docs/spec/closed-mode-plan.md §6-2). "
        + "control-row false-positive rate 1/32=3.13% (just Ditto). 0% of the gap vs. the stale "
        + "2026-08-31 numbers below is attributable to the Chocolatey removal this test is named "
        + "for -- see class javadoc for the full breakdown. Left disabled so it can never re-fire "
        + "on a routine mvn test run.")
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
                // Backlog item 300: Blender/Rufus only just moved from this file's UNIDENTIFIED
                // control-row bucket into IDENTIFIED_CPE targets (golden-300.csv re-sync, see class
                // javadoc) -- result.isPresent() alone can't tell whether they resolved to the
                // *correct* CPE (blender:blender / akeo:rufus) or merely to some other CPE, so print
                // the resolved vendor/product explicitly for these two rows.
                if (("Blender".equals(item.getRawProductName()) && "4.2.1".equals(item.getVersion()))
                        || ("Rufus".equals(item.getRawProductName()) && "4.5".equals(item.getVersion()))) {
                    System.out.println("BLENDER/RUFUS RESOLVED-CPE CHECK: " + item.getRawProductName() + " "
                            + item.getVersion() + " -> identified=" + identified
                            + " cpe=" + (identified ? result.get().getCpe() : "n/a"));
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
