package com.vulncheck.app.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
 * Backlog item 304 (marketplace-extension fixture) baseline measurement: runs {@code
 * marketplace-extension-fixture.csv} through the real {@link Stage1IdentificationService}
 * directly (static Tier1 + CPE dictionary only — same {@code REAL_USER_ID}=5 setup as {@link
 * ChocolateyRemovalGolden300RecallTest}/{@link Golden300JobCreator}, so Tier2/Tier3 never fire and
 * this costs nothing) against the real dev DB's populated CPE dictionary.
 *
 * <p>Purpose: item 303 (taskB, {@code install_url}-hostname-driven {@code passesTargetSwGate}
 * generalization) has no fixture to measure improvement/regression against today — golden-300 and
 * real-1000 both have zero non-blank {@code install_url} rows and zero marketplace-extension input
 * rows. This fixture (29 rows: VS Code/Chrome/JetBrains/Firefox extension rows with {@code
 * install_url} filled in, plus mandatory negative controls — the base platforms themselves, the
 * backlog-item-299-case-5 Visual Studio/Visual Studio Code regression row, and a confusing-name
 * decoy whose real product is Coder's unrelated {@code code-server}, not Visual Studio Code itself)
 * exists purely to record the <em>current</em> (pre-item-303) baseline, so item 303's own recall
 * measurement has something to diff against. See {@code test-data/marketplace-extension-fixture.csv}
 * ground_truth_source column for how every expected_outcome/expected_cpe_vendor/expected_cpe_product
 * was verified — direct read-only {@code cpe_dictionary} SELECTs against the real dev DB
 * (2026-09-05), not live NVD API calls.
 *
 * <p>Same in-process, no-durable-write approach as {@link ChocolateyRemovalGolden300RecallTest}:
 * this test method is itself {@link Transactional @Transactional}, {@link
 * ResearchJobService#createJob} joins that same transaction, and Spring rolls the whole thing back
 * at the end regardless of outcome — no job/item/identified-product row survives outside this one
 * JVM process.
 *
 * <p>Disabled by default, same convention as every other real-dev-DB test in this package — run
 * once by hand (temporarily remove {@code @Disabled}, {@code mvn
 * -Dtest=MarketplaceExtensionFixtureRecallTest test}), read the printed metrics, then restore
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
@Disabled("Post-item-303 remeasurement (2026-09-05, task B: install_url-hostname-driven "
        + "passesTargetSwGate generalization) against the real dev DB: 19/23=0.8261 extension rows "
        + "now match ground truth (up from the pre-item-303 baseline's 12/23=0.5217 -- GitLens, "
        + "ESLint, Adblock Plus, Evernote Web Clipper, McAfee WebAdvisor, FireGPG and Avira Password "
        + "Manager all newly resolve correctly, exactly the set that was previously rejected purely "
        + "by the no-registry-match gate despite install_url declaring the right platform). Remaining "
        + "4 extension mismatches are NOT target_sw-gate failures and are out of this item's scope: "
        + "Python resolves to the wrong CPE (python:python instead of microsoft:python_extension) via "
        + "an unrelated static path; Continue and Grammarly still come back UNIDENTIFIED (no matching "
        + "candidate ever reaches the gate at all); Live Share was already flagged in this fixture's "
        + "own ground_truth_source note as unsavable by task B alone (no visual_studio_code-scoped "
        + "dictionary row exists for it, only visual_studio-scoped). The 6 negative-control rows are "
        + "unchanged at 5/6=0.8333 -- no new false positive, Microsoft Visual Studio (item 299 case 5's "
        + "own regression control) still resolves to microsoft:visual_studio and never to "
        + "microsoft:visual_studio_code; the sole remaining control mismatch is the pre-existing, "
        + "out-of-scope item 319 bug (Visual Studio Code Server misresolving to a nonexistent "
        + "microsoft:visual_studio_code version instead of coder:code-server). "
        + "Run once (2026-09-05, backlog item 304 marketplace-extension fixture baseline; ground "
        + "truth corrected and re-measured twice 2026-09-05 per two rounds of senior-reviewer "
        + "REVISE on PR#224 -- round 1: Visual Studio Code Server/Prettier/Tab Session Manager; "
        + "round 2: Live Share flipped to IDENTIFIED_CPE, Prettier reverted back to UNIDENTIFIED) "
        + "against the real dev DB -- pre-item-303 baseline (actually re-run both times, not "
        + "arithmetic-only): 23 extension rows (install_url filled in) score 12/23=0.5217 against "
        + "their ground truth -- of the 13 rows expected IDENTIFIED_CPE, only the 2 LastPass rows "
        + "(Chrome/Firefox) actually resolve correctly (via a registry-match-adjacent static path, "
        + "not the target_sw gate); the other 11 (GitLens, Python, ESLint, Continue, Live Share, "
        + "Adblock Plus, Grammarly, Evernote Web Clipper, McAfee WebAdvisor, FireGPG, Avira Password "
        + "Manager) come back UNIDENTIFIED or with a wrong slug (McAfee resolves to mcafee:webadvisor, "
        + "not the dictionary's real mcafee:web_advisor; Live Share's real CPE microsoft:"
        + "visual_studio_live_share is target_sw=visual_studio-scoped only, no visual_studio_code-"
        + "scoped row exists) -- consistent with passesTargetSwGate rejecting a target_sw-scoped CPE "
        + "candidate whenever there's no registry match, regardless of what install_url says "
        + "(item305/306); the 10 rows expected UNIDENTIFIED (Prettier - Code formatter, Honey, "
        + "Momentum, all 5 JetBrains-plugin rows, Firefox Multi-Account Containers, Tab Session "
        + "Manager) all correctly come back UNIDENTIFIED. The 6 negative-control rows score "
        + "5/6=0.8333 -- Visual Studio Code/Google Chrome/Mozilla Firefox/IntelliJ IDEA/Microsoft "
        + "Visual Studio all resolve correctly to their own platform CPE, but 'Visual Studio Code "
        + "Server' (real product is Coder's unrelated code-server) incorrectly resolves to "
        + "microsoft:visual_studio_code:4.9.3 (a version that doesn't even exist for that CPE) "
        + "instead of coder:code-server -- filed as backlog item 319, not fixed here (out of this "
        + "task's scope). Left disabled so it can never re-fire on a routine mvn test run -- see "
        + "class javadoc.")
class MarketplaceExtensionFixtureRecallTest {

    private static final Long REAL_USER_ID = 5L;
    private static final String FIXTURE_CSV = "marketplace-extension-fixture.csv";

    @Autowired
    private ResearchJobService researchJobService;
    @Autowired
    private ResearchJobItemRepository researchJobItemRepository;
    @Autowired
    private Stage1IdentificationService stage1IdentificationService;

    private record ExpectedRow(String outcome, String cpeVendor, String cpeProduct) {
    }

    @Test
    @Transactional
    void measureMarketplaceExtensionFixtureBaseline() throws Exception {
        ResearchJob job;
        try (InputStream csv = getClass().getClassLoader().getResourceAsStream(FIXTURE_CSV)) {
            job = researchJobService.createJob(
                    REAL_USER_ID, "marketplace-extension-fixture-recheck.csv", csv, ColumnMapping.identity(), false);
        }
        List<ResearchJobItem> items = researchJobItemRepository.findByJobIdOrderById(job.getId());

        // Keyed on (raw product_name, version) — same convention as ChocolateyRemovalGolden300RecallTest.
        // A duplicate key here would silently overwrite one row's ground truth with another's and
        // under-count both extensionTotal/controlTotal below — fail loudly instead (senior-reviewer
        // REVISE on PR#224, item 3) rather than let that happen quietly as this fixture grows for item303.
        Map<String, ExpectedRow> expectedByKey = new HashMap<>();
        int fixtureRowCount = 0;
        try (InputStream csv = getClass().getClassLoader().getResourceAsStream(FIXTURE_CSV);
                CSVParser parser = CSVParser.parse(new InputStreamReader(csv, StandardCharsets.UTF_8),
                        CSVFormat.DEFAULT.builder().setHeader().setSkipHeaderRecord(true).build())) {
            for (CSVRecord record : parser) {
                fixtureRowCount++;
                String rowKey = key(record.get("product_name"), record.get("version"));
                ExpectedRow row = new ExpectedRow(record.get("expected_outcome"), record.get("expected_cpe_vendor"),
                        record.get("expected_cpe_product"));
                validateExpectedRow(rowKey, row);
                ExpectedRow previous = expectedByKey.put(rowKey, row);
                if (previous != null) {
                    throw new IllegalStateException(
                            "Duplicate (product_name, version) key in " + FIXTURE_CSV + ": " + rowKey);
                }
            }
        }

        int extensionTotal = 0;
        int extensionIdentifiedCorrectly = 0;
        int controlTotal = 0;
        int controlCorrect = 0;
        int missingExpected = 0;

        for (ResearchJobItem item : items) {
            ExpectedRow expected = expectedByKey.get(key(item.getRawProductName(), item.getVersion()));
            if (expected == null) {
                missingExpected++;
                System.out.println("NO EXPECTED ROW FOUND FOR: " + item.getRawProductName() + " " + item.getVersion());
                continue;
            }
            Optional<IdentifiedProduct> result = stage1IdentificationService.identify(item, REAL_USER_ID);
            boolean isControlRow = item.getInstallUrl() == null || item.getInstallUrl().isBlank();
            boolean matchesExpectation = matches(result, expected);

            if (isControlRow) {
                controlTotal++;
                if (matchesExpectation) {
                    controlCorrect++;
                } else {
                    System.out.println("CONTROL-ROW MISMATCH: " + item.getRawProductName() + " " + item.getVersion()
                            + " expected=" + expected.outcome() + "/" + expected.cpeVendor() + ":" + expected.cpeProduct()
                            + " actual=" + describe(result));
                }
            } else {
                extensionTotal++;
                if (matchesExpectation) {
                    extensionIdentifiedCorrectly++;
                } else {
                    System.out.println("EXTENSION-ROW MISMATCH: " + item.getRawProductName() + " " + item.getVersion()
                            + " expected=" + expected.outcome() + "/" + expected.cpeVendor() + ":" + expected.cpeProduct()
                            + " actual=" + describe(result));
                }
            }
        }

        System.out.println("\n=== backlog item 304 marketplace-extension fixture baseline ===");
        System.out.println("missingExpected=" + missingExpected);
        System.out.printf("extension rows matching ground truth: %d/%d = %.4f%n", extensionIdentifiedCorrectly,
                extensionTotal, extensionTotal == 0 ? 0.0 : (double) extensionIdentifiedCorrectly / extensionTotal);
        System.out.printf("control rows matching ground truth: %d/%d = %.4f%n", controlCorrect, controlTotal,
                controlTotal == 0 ? 0.0 : (double) controlCorrect / controlTotal);

        // Sanity guards on the measurement itself (senior-reviewer REVISE on PR#224, item 3) --
        // printed metrics above are useless if some job item silently had no ground truth row, or
        // if the extension/control split silently dropped rows.
        assertEquals(0, missingExpected, "every job item must have a matching fixture row by (product_name, version)");
        assertEquals(fixtureRowCount, extensionTotal + controlTotal,
                "every fixture row must be counted as exactly one of extension/control");
    }

    /** Ground-truth self-consistency guard (senior-reviewer REVISE on PR#224, round 2, item 4) --
     *  this fixture's own ground truth has already had multiple authoring mistakes caught by later
     *  review passes (Visual Studio Code Server, Prettier, Live Share), and {@link #matches}
     *  compares expected_cpe_vendor/expected_cpe_product against the actual CPE's parts as plain
     *  strings — a blank or nonsensical value there wouldn't throw, it would just silently mismatch
     *  every row that legitimately resolves. Fail at parse time instead of letting that hide behind
     *  a plausible-looking printed score. */
    private static void validateExpectedRow(String rowKey, ExpectedRow row) {
        if (!"IDENTIFIED_CPE".equals(row.outcome()) && !"UNIDENTIFIED".equals(row.outcome())) {
            throw new IllegalStateException(
                    "Row " + rowKey + " has an unrecognized expected_outcome: " + row.outcome());
        }
        boolean vendorBlank = row.cpeVendor() == null || row.cpeVendor().isBlank();
        boolean productBlank = row.cpeProduct() == null || row.cpeProduct().isBlank();
        if ("IDENTIFIED_CPE".equals(row.outcome()) && (vendorBlank || productBlank)) {
            throw new IllegalStateException(
                    "Row " + rowKey + " is IDENTIFIED_CPE but expected_cpe_vendor/expected_cpe_product is blank");
        }
        if ("UNIDENTIFIED".equals(row.outcome()) && (!vendorBlank || !productBlank)) {
            throw new IllegalStateException(
                    "Row " + rowKey + " is UNIDENTIFIED but expected_cpe_vendor/expected_cpe_product is non-blank");
        }
    }

    /** For {@code UNIDENTIFIED} expectations, only presence/absence of a result matters. For
     *  {@code IDENTIFIED_CPE} expectations, the actual CPE's vendor:product must match exactly —
     *  a wrong-but-present identification (e.g. resolving to a sibling extension) is not "close
     *  enough" and must count as a mismatch. */
    private static boolean matches(Optional<IdentifiedProduct> result, ExpectedRow expected) {
        if ("UNIDENTIFIED".equals(expected.outcome())) {
            return result.isEmpty();
        }
        if (result.isEmpty()) {
            return false;
        }
        String cpe = result.get().getCpe();
        if (cpe == null) {
            return false;
        }
        String[] parts = cpe.split(":");
        if (parts.length < 5) {
            return false;
        }
        String actualVendor = parts[3];
        String actualProduct = parts[4];
        return expected.cpeVendor().equals(actualVendor) && expected.cpeProduct().equals(actualProduct);
    }

    private static String describe(Optional<IdentifiedProduct> result) {
        return result.map(p -> "ecosystem=" + p.getEcosystem() + " cpe=" + p.getCpe()).orElse("UNIDENTIFIED");
    }

    private static String key(String productName, String version) {
        return productName + " " + version;
    }
}
