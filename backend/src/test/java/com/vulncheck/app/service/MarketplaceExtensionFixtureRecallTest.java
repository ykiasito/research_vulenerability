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
 * decoy that is neither Visual Studio Code nor the real Coder {@code code-server} it resembles)
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
@Disabled("Run once (2026-09-05, backlog item 304 marketplace-extension fixture baseline) against "
        + "the real dev DB -- pre-item-303 baseline (measured 2026-09-05): 23 extension rows (the "
        + "ones with install_url filled in) score 13/23=0.5652 against their ground truth -- of the "
        + "12 rows expected IDENTIFIED_CPE, only the 2 LastPass rows (Chrome/Firefox) actually "
        + "resolve correctly (via a registry-match-adjacent static path, not the target_sw gate); "
        + "the other 10 (GitLens, Python, ESLint, Continue, Adblock Plus, Grammarly, Evernote Web "
        + "Clipper, McAfee WebAdvisor, FireGPG, Avira Password Manager) come back UNIDENTIFIED or "
        + "with a wrong slug (McAfee resolves to mcafee:webadvisor, not the dictionary's real "
        + "mcafee:web_advisor) -- consistent with passesTargetSwGate rejecting a target_sw-scoped "
        + "CPE candidate whenever there's no registry match, regardless of what install_url says "
        + "(item305/306); the 11 rows expected UNIDENTIFIED (Prettier, Live Share, Honey, Momentum, "
        + "all 5 JetBrains-plugin rows, Firefox Multi-Account Containers, Tab Session Manager) all "
        + "correctly come back UNIDENTIFIED. The 6 negative-control rows score 5/6=0.8333 -- Visual "
        + "Studio Code/Google Chrome/Mozilla Firefox/IntelliJ IDEA/Microsoft Visual Studio all "
        + "resolve correctly to their own platform CPE, but 'Visual Studio Code Server' (the "
        + "confusing-name decoy, real product is Coder's unrelated code-server) incorrectly "
        + "resolves to microsoft:visual_studio_code:4.9.3 (a version that doesn't even exist for "
        + "that CPE) instead of staying UNIDENTIFIED -- filed as a new finding, backlog item 319, "
        + "not fixed here (out of this task's scope). Left disabled so it can never re-fire on a "
        + "routine mvn test run -- see class javadoc.")
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
        Map<String, ExpectedRow> expectedByKey = new HashMap<>();
        try (InputStream csv = getClass().getClassLoader().getResourceAsStream(FIXTURE_CSV);
                CSVParser parser = CSVParser.parse(new InputStreamReader(csv, StandardCharsets.UTF_8),
                        CSVFormat.DEFAULT.builder().setHeader().setSkipHeaderRecord(true).build())) {
            for (CSVRecord record : parser) {
                expectedByKey.put(key(record.get("product_name"), record.get("version")),
                        new ExpectedRow(record.get("expected_outcome"), record.get("expected_cpe_vendor"),
                                record.get("expected_cpe_product")));
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
