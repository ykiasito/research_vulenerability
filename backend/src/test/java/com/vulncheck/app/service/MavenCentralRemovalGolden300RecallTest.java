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
 * path was physically deleted on this branch. This confirms §6-2 scenario C's assumption is
 * exactly right for the current dataset/code, not merely a plausible projection: whatever the
 * exact mechanism (see the correction paragraph below), these 20 rows end up {@code UNIDENTIFIED}
 * either way.
 *
 * <p><b>Correction (2026-09-06, senior review caught this):</b> an earlier version of this javadoc
 * claimed "neither {@link Stage1IdentificationService#localCpeLookup}'s pg_trgm search nor {@link
 * Stage1IdentificationService#findByNameVariants} has anything to match against these rows'
 * {@code product_name} values ... there is no coincidental-CPE-match path". That claim does not
 * hold at the search stage: the CPE dictionary does have well-known entries for several of these
 * Maven coordinates' underlying libraries (confirmed directly against the real dev DB's {@code
 * cpe_dictionary}: {@code google:guava}, {@code fasterxml:jackson-databind}, {@code netty:netty},
 * {@code apache:log4j} — note {@code apache:log4j}, not a {@code log4j-core} slug, which does not
 * exist in the dictionary). {@code similarity('com.google.guava:guava', 'guava') = 0.375} exceeds
 * {@link Stage1IdentificationService}'s product-side pg_trgm threshold (0.3), and running the same
 * trigram query {@link #localCpeLookup} itself uses confirms {@code google:guava} does enter the
 * candidate pool for that row. So the 20/20 UNIDENTIFIED outcome is not explained by "the search
 * never finds anything" — the rejection, for at least this row, happens at a later stage (most
 * likely the containment/{@code explainsQuery} admission gate rejecting the coordinate's
 * unexplained leading tokens, e.g. {@code com}/{@code google}, but this has not been confirmed row
 * by row for all 20). Tracked for further investigation as backlog item 367; do not cite the
 * removed claim above as settled fact until that lands.
 *
 * <p><b>Backlog item 367 fix landed, re-measured 2026-09-06:</b> the follow-up investigation
 * confirmed the correction paragraph above row by row — 14 of the 20 rows really do enter the
 * candidate pool and get rejected downstream, 6 (lombok, mockito-core, HikariCP, micrometer-core,
 * plus kafka-clients/log4j-core which fail the pg_trgm threshold itself) are genuinely
 * unidentifiable with the current dictionary. Of those 14, 9 shared one root cause: {@link
 * Stage1IdentificationService#explainsQuery}'s Direction 2 leading-token loop required every query
 * token ahead of a match to be explained by the candidate's own CPE vendor, but a Maven {@code
 * groupId}'s leading reverse-DNS segment ({@code com}/{@code org}/{@code io}/{@code ch}, ...) is
 * essentially never itself a CPE vendor slug. The fix (a small {@code
 * REVERSE_DNS_PACKAGE_PREFIXES} allowlist consulted only for that leading-token check) recovered
 * <b>6 of the 9</b> rows sharing this root cause — {@code com.google.guava:guava}, {@code
 * com.fasterxml.jackson.core:jackson-databind} (resolves to the sibling {@code
 * fasterxml:jackson-core} CPE rather than {@code jackson-databind} itself — a ranking nuance,
 * out of this fix's scope), {@code org.slf4j:slf4j-api}, {@code com.squareup.okhttp3:okhttp},
 * {@code io.netty:netty-all}, and {@code ch.qos.logback:logback-classic}. The remaining 3 of the 9
 * ({@code com.squareup.retrofit2:retrofit}, {@code org.apache.httpcomponents:httpclient}, {@code
 * org.springframework.boot:spring-boot-starter-web}) are still {@code UNIDENTIFIED}: each has a
 * second unexplained token between the reverse-DNS prefix and the actual match ({@code retrofit2},
 * {@code httpcomponents}, {@code boot}) that this narrowly-scoped fix deliberately does not touch.
 * The other 5 of the 14-row gap ({@code spring-core}, {@code commons-lang3}, {@code gson}, {@code
 * hibernate-core}, {@code junit}) have their own distinct root causes (see backlog item 367's own
 * write-up) and are unaffected by this fix, as expected. Net result: {@code
 * expected_ecosystem=maven} recall went from 0/20 to 6/20. {@link
 * CpeVendorProductGolden300RecallTest} and {@link Backlog299CpeRankingGolden300RecallTest} were
 * both re-run after this fix landed and stayed at 64/68 — no regression for non-Maven
 * identification.
 *
 * <p><b>Peer review REVISE (2026-09-06):</b> the version of the fix measured above consulted
 * {@code REVERSE_DNS_PACKAGE_PREFIXES} unconditionally for any bare leading token, which is a real
 * false-positive risk for a non-Maven query that happens to tokenize with one of those words leading
 * (e.g. {@code ".NET Framework"} → {@code ["net", "framework"]}) — see {@link
 * Stage1IdentificationService#queryLooksLikeReverseDnsCoordinate} for the narrowed fix, which now
 * additionally requires the query itself to structurally look like a genuine Maven coordinate
 * ({@code segment.segment:artifact}) before the allowlist bypass fires at all. Re-measured against
 * this same real dev DB after the narrowing landed: identical 6/20, same 6 rows recovered, same 3
 * still {@code UNIDENTIFIED} — the narrowing closes the false-positive class without costing any of
 * the recovered Maven rows.
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
@Disabled("Re-measured 2026-09-06 after backlog item 367's Stage1IdentificationService#explainsQuery "
        + "Direction 2 leading-token fix landed -- expected_ecosystem=maven recall is now 6/20 (up "
        + "from the pre-fix 0/20 baseline confirmed 2026-09-05/2026-09-06, see class javadoc's "
        + "earlier paragraphs). 6 of the 9 rows sharing item 367's dominant root cause are now "
        + "identified: com.google.guava:guava, com.fasterxml.jackson.core:jackson-databind (as "
        + "fasterxml:jackson-core), org.slf4j:slf4j-api, com.squareup.okhttp3:okhttp, "
        + "io.netty:netty-all, ch.qos.logback:logback-classic. 3 of that same 9 remain UNIDENTIFIED "
        + "(com.squareup.retrofit2:retrofit, org.apache.httpcomponents:httpclient, "
        + "org.springframework.boot:spring-boot-starter-web -- each has an additional unexplained "
        + "token beyond item 367's narrow scope). The other 14 rows are unchanged: 6 genuinely "
        + "unidentifiable (no dictionary entry or below the pg_trgm threshold) and 5 rejected for "
        + "distinct, item-367-unrelated reasons. See class javadoc's own \"backlog item 367 fix "
        + "landed\" paragraph for the full breakdown. Left disabled so it can never re-fire on a "
        + "routine mvn test run.")
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
