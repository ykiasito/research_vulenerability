package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;

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
 * Item 302 golden-300 regression: verifies the {@code (vendor, product)} exact-match candidate-pool
 * fallback ({@link Stage1IdentificationService#localCpeLookup}, backed by {@link
 * com.vulncheck.app.repository.CpeDictionaryRepositoryCustom#findByVendorProductPairs}) does not
 * regress golden-300's existing static-pipeline accuracy. Same real-dev-DB, no-cost, in-process
 * shape as {@link ChocolateyRemovalGolden300RecallTest} (static Tier1 + CPE dictionary only —
 * {@code REAL_USER_ID}=5 has only an {@code nvd} provider secret, no Claude key, so Tier2/3 never
 * fire) — see that class's own javadoc for why this is safe to run without a job-creation/backend-
 * restart round trip.
 *
 * <p><b>Scope: {@code golden300-cpe-and-control-subset.csv}, not the full {@code golden-300.csv}.</b>
 * This subset (generated 2026-09-05 from {@code golden-300.csv}) keeps only the 66 {@code
 * IDENTIFIED_CPE} rows and the 34 {@code UNIDENTIFIED} control rows, dropping the 200 {@code
 * IDENTIFIED_REGISTRY} rows. Measured live (2026-09-05): the full 300-row set takes multiple hours
 * per run because {@code Stage1RegistryIdentification}'s registry fan-out makes real, deliberately
 * rate-limited network calls to external package registries (~1 req/sec per {@code
 * ExternalRegistryRateLimiter}) for every row that has a plausible same-named registry candidate —
 * true for most of the 200 registry-bucket rows, each needing several such calls, but not for the
 * CPE/control rows this fallback can actually affect. Excluding the registry bucket is safe for this
 * specific regression check because this fallback only ever changes the local CPE candidate pool
 * (never an item's registry/ecosystem match), and a registry-bucket row's {@code
 * IdentifiedProduct.isPresent()} outcome — the only thing golden-300's recall/false-positive metric
 * reads — depends on ecosystem match succeeding, not on which CPE (if any) ends up attached; this
 * fallback can only ever add a CPE candidate to an already-identified registry row's result, never
 * revoke its identified status. That leaves the CPE-bucket recall and the control-bucket false-
 * positive rate as the only two numbers this fallback could plausibly move, which is exactly what
 * this subset measures with full fidelity.
 *
 * <p>The fallback only ever fires when the existing trigram+containment candidate pool comes back
 * completely empty for an item (see {@code localCpeLookup}'s own javadoc), so it can never change
 * the outcome of an item that already had candidates — a plain equality assertion on the recall/
 * false-positive counts is therefore the right regression check here (not just a "no worse than"
 * bound), matching item 302's own backlog description. Empirically confirmed live (2026-09-05, real
 * dev DB) by running this exact subset twice — once with {@link Stage1IdentificationService}'s
 * fallback branch temporarily disabled (a hardcoded {@code false &&} short-circuit), once with it
 * enabled as shipped — and both runs produced byte-for-byte identical results: identification recall
 * 64/66 = 96.97%, control-row false-positive rate 3/34 = 8.82% (the same 3 known pre-existing false
 * positives — Blender, Rufus, Ditto — none newly introduced; none of golden-300's rows happen to hit
 * this fallback's short-slug-vs-long-query shape, see docs/spec/closed-mode-backlog.md item 299 for
 * the residual CPE-matching misses this fallback does not address).
 *
 * <p>Disabled by default, same convention as every other real-dev-DB test in this package — run
 * once by hand (temporarily remove {@code @Disabled},
 * {@code mvn -Dtest=VendorProductExactMatchFallbackGolden300Test test}), read the printed metrics,
 * then restore {@code @Disabled}. Never left enabled for a routine {@code mvn test} run.
 */
@SpringBootTest
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:postgresql://postgres:5432/vulncheck",
        "spring.datasource.username=vulncheck",
        // Resolved from the real POSTGRES_PASSWORD env var passed to this docker run invocation,
        // same as every other real-dev-DB test in this package.
        "spring.datasource.password=${POSTGRES_PASSWORD}"
})
@Disabled("Run once (2026-09-05, backlog item 302 vendor/product exact-match fallback) against the "
        + "real dev DB -- identification recall 64/66=96.97%, control-row false-positive rate "
        + "3/34=8.82%, confirmed byte-for-byte identical with the fallback temporarily disabled (see "
        + "class javadoc) -- this fallback never fires for any row in this subset. Left disabled so "
        + "it can never re-fire on a routine mvn test run.")
class VendorProductExactMatchFallbackGolden300Test {

    private static final Long REAL_USER_ID = 5L;
    private static final String SUBSET_CSV = "golden300-cpe-and-control-subset.csv";

    @Autowired
    private ResearchJobService researchJobService;
    @Autowired
    private ResearchJobItemRepository researchJobItemRepository;
    @Autowired
    private Stage1IdentificationService stage1IdentificationService;

    @Test
    @Transactional
    void measureGolden300CpeAndControlSubsetAfterVendorProductExactMatchFallback() throws Exception {
        ResearchJob job;
        try (InputStream csv = getClass().getClassLoader().getResourceAsStream(SUBSET_CSV)) {
            job = researchJobService.createJob(
                    REAL_USER_ID, "item302-subset-recheck.csv", csv, ColumnMapping.identity(), false);
        }
        List<ResearchJobItem> items = researchJobItemRepository.findByJobIdOrderById(job.getId());

        // Keyed on (raw product_name, version) -- the same pair test-data/compute_golden_300_metrics*.py
        // uses to join golden-300.csv's ground truth against a job's actual results.
        Map<String, String> expectedOutcomeByKey = new HashMap<>();
        try (InputStream csv = getClass().getClassLoader().getResourceAsStream(SUBSET_CSV);
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

        System.out.println("\n=== backlog item 302 (vendor/product exact-match fallback) golden-300 CPE+control subset regression ===");
        System.out.println("missingExpected=" + missingExpected);
        System.out.printf("identification recall: %d/%d = %.4f%n", targetIdentified, targetTotal,
                targetTotal == 0 ? 0.0 : (double) targetIdentified / targetTotal);
        System.out.printf("control-row false-positive rate: %d/%d = %.4f%n", controlFalsePositive, controlTotal,
                controlTotal == 0 ? 0.0 : (double) controlFalsePositive / controlTotal);

        // Item 302's own design guarantee, empirically confirmed (see class javadoc): the fallback
        // only ever fires on an already-empty candidate pool, and running this exact subset with the
        // fallback disabled produced byte-for-byte identical numbers -- so both counts must come out
        // exactly unchanged from that confirmed baseline, not just "no worse".
        assertThat(targetIdentified).isEqualTo(64);
        assertThat(targetTotal).isEqualTo(66);
        assertThat(controlFalsePositive).isEqualTo(3);
        assertThat(controlTotal).isEqualTo(34);
    }

    private static String key(String productName, String version) {
        return productName + " " + version;
    }
}
