package com.vulncheck.app.service;

import com.vulncheck.app.entity.IdentifiedProduct;
import com.vulncheck.app.entity.ResearchJob;
import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.repository.ResearchJobItemRepository;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
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
 * Backlog item 296 (2026-09-05, golden-300 job211 recall investigation): companion to {@link
 * ChocolateyRemovalGolden300RecallTest} for the other registry lost to closed mode — Maven Central
 * (backlog item 193/B3, see {@code MavenCentralRegistryClient}'s own javadoc: {@code lookup} is a
 * fixed no-op in closed mode, no mirror exists). {@code docs/spec/closed-mode-plan.md} §6-2
 * scenario C *assumes* every golden-300 row with {@code expected_ecosystem=maven} has no
 * independent CPE-dictionary backing and therefore flips from {@code IDENTIFIED_REGISTRY} to
 * {@code UNIDENTIFIED} once the Maven registry is gone — this test actually measures that, row by
 * row, against the real {@link Stage1IdentificationService} (static Tier1 + CPE dictionary only,
 * same no-cost setup as the sibling Chocolatey test's own javadoc explains), rather than trusting
 * the assumption.
 *
 * <p>Measured 2026-09-05 against the real dev DB (closed-mode branch, current HEAD, after the
 * golden-300.csv sync described in {@link ChocolateyRemovalGolden300RecallTest}'s own javadoc —
 * backlog item 300 — which didn't touch any {@code expected_ecosystem=maven} row): all 20 of the
 * 20 {@code expected_ecosystem=maven} rows in golden-300.csv come back {@code UNIDENTIFIED} — zero
 * CPE-dictionary rescue for any of them. There is no live NVD fallback to even consider here — see
 * {@link Stage1IdentificationService}'s own class javadoc (closed-mode backlog item 273/B4): that
 * path was physically deleted on this branch. The only CPE-matching paths that exist are local
 * {@code cpe_dictionary} reads — {@link Stage1IdentificationService#localCpeLookup}'s literal/
 * pg_trgm-similarity search, falling back to {@link Stage1IdentificationService#findByNameVariants}'s
 * contraction/expansion/vendor-prefix-strip search — and neither has anything to match against
 * these rows' {@code product_name} values, which are raw Maven coordinates ({@code
 * groupId:artifactId}, e.g. {@code org.springframework:spring-core}) rather than human-readable
 * product names; there is no coincidental-CPE-match path the way there sometimes is for ordinary
 * desktop-software names. This confirms §6-2 scenario C's assumption is exactly right for the
 * current dataset/code, not merely a plausible projection: closed mode has literally no path back
 * to identifying these 20 rows short of standing up an actual Maven Central mirror (ruled out
 * elsewhere in the plan doc on ToS/effort grounds) or teaching the CPE-dictionary path to parse a
 * Maven coordinate into a heuristic product-name guess (not implemented, speculative, out of scope
 * of this investigation).
 *
 * <p>This is an analysis tool, not a regression gate — no assertions, same convention as the
 * sibling {@link ChocolateyRemovalGolden300RecallTest}: it prints a per-row breakdown plus a
 * summary for a human to read.
 *
 * <p>Disabled by default, same convention as every other real-dev-DB test in this package — run
 * once by hand (temporarily remove {@code @Disabled}, {@code mvn
 * -Dtest=MavenCentralRemovalGolden300RecallTest test}), read the printed metrics, then restore
 * {@code @Disabled}. Never left enabled for a routine {@code mvn test} run.
 */
@SpringBootTest
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:postgresql://postgres:5432/vulncheck",
        "spring.datasource.username=vulncheck",
        // Resolved from the real POSTGRES_PASSWORD env var passed to this docker run invocation,
        // same as every other real-dev-DB test in this package.
        "spring.datasource.password=${POSTGRES_PASSWORD}"
})
@Disabled("Run once by hand against the real dev DB (2026-09-05, backlog item 296 gap analysis, "
        + "post golden-300.csv sync -- item300) -- all 20/20 golden-300 expected_ecosystem=maven "
        + "rows still come back UNIDENTIFIED, zero rescued via the local CPE dictionary (no live "
        + "NVD fallback exists on this branch to consider either, see class javadoc) -- confirms "
        + "docs/spec/closed-mode-plan.md's own scenario C assumption is exact, not just a plausible "
        + "projection. See class javadoc. Left disabled so it can never re-fire on a routine mvn "
        + "test run.")
class MavenCentralRemovalGolden300RecallTest {

    private static final Long REAL_USER_ID = 5L;

    @Autowired
    private ResearchJobService researchJobService;
    @Autowired
    private ResearchJobItemRepository researchJobItemRepository;
    @Autowired
    private Stage1IdentificationService stage1IdentificationService;

    @Test
    @Transactional
    void measureGolden300RecallForMavenCoordinateRows() throws Exception {
        ResearchJob job;
        try (InputStream csv = getClass().getClassLoader().getResourceAsStream("golden-300.csv")) {
            job = researchJobService.createJob(
                    REAL_USER_ID, "golden-300-maven-removal-recheck.csv", csv, ColumnMapping.identity(), false);
        }
        List<ResearchJobItem> items = researchJobItemRepository.findByJobIdOrderById(job.getId());

        // Keyed on (raw product_name, version) -- same pair-key convention as the sibling
        // Chocolatey test -- restricted here to rows whose ground truth says expected_ecosystem=maven.
        Set<String> mavenRowKeys = new HashSet<>();
        try (InputStream csv = getClass().getClassLoader().getResourceAsStream("golden-300.csv");
                CSVParser parser = CSVParser.parse(new InputStreamReader(csv, StandardCharsets.UTF_8),
                        CSVFormat.DEFAULT.builder().setHeader().setSkipHeaderRecord(true).build())) {
            for (CSVRecord record : parser) {
                if ("maven".equals(record.get("expected_ecosystem"))) {
                    mavenRowKeys.add(key(record.get("product_name"), record.get("version")));
                }
            }
        }

        int mavenRowTotal = 0;
        int mavenRowStillIdentified = 0;
        Set<String> seenMavenRowKeys = new HashSet<>();

        for (ResearchJobItem item : items) {
            String itemKey = key(item.getRawProductName(), item.getVersion());
            if (!mavenRowKeys.contains(itemKey)) {
                continue;
            }
            seenMavenRowKeys.add(itemKey);
            mavenRowTotal++;
            Optional<IdentifiedProduct> result = stage1IdentificationService.identify(item, REAL_USER_ID);
            if (result.isPresent()) {
                mavenRowStillIdentified++;
                System.out.println("MAVEN ROW STILL IDENTIFIED (via non-registry path): " + item.getRawProductName()
                        + " " + item.getVersion() + " -> ecosystem=" + result.get().getEcosystem()
                        + " package=" + result.get().getPackageName() + " cpe=" + result.get().getCpe());
            } else {
                System.out.println("MAVEN ROW NOW UNIDENTIFIED: " + item.getRawProductName() + " " + item.getVersion());
            }
        }

        // Sanity check, same idea as the sibling Chocolatey test's missingExpected counter: every
        // key collected from golden-300.csv's expected_ecosystem=maven rows should also show up
        // among this job's created ResearchJobItems. If it doesn't, something upstream (CSV
        // parsing, column mapping, job creation) silently dropped or renamed a row, and mavenRowTotal
        // would undercount without this warning ever being visible.
        if (mavenRowTotal != mavenRowKeys.size()) {
            Set<String> missingKeys = new HashSet<>(mavenRowKeys);
            missingKeys.removeAll(seenMavenRowKeys);
            System.out.println("WARNING: expected " + mavenRowKeys.size() + " expected_ecosystem=maven rows from "
                    + "golden-300.csv but only matched " + mavenRowTotal + " ResearchJobItems -- missing keys: "
                    + missingKeys);
        }

        System.out.println("\n=== backlog item 296 (Maven Central closed-mode removal) golden-300 per-row measurement ===");
        System.out.printf("expected_ecosystem=maven rows still identified via a non-registry (e.g. CPE dictionary) "
                + "path: %d/%d%n", mavenRowStillIdentified, mavenRowTotal);
    }

    private static String key(String productName, String version) {
        return productName + "\0" + version;
    }
}
