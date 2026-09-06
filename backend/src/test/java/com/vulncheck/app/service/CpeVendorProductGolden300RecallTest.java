package com.vulncheck.app.service;

import com.vulncheck.app.entity.IdentifiedProduct;
import com.vulncheck.app.entity.ResearchJob;
import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.repository.ResearchJobItemRepository;
import com.vulncheck.app.service.nvd.CpeUtils;
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
 * Public accuracy write-up measurement: CPE {@code vendor:product} exact-match rate against the
 * golden-300 dataset's 68 {@code IDENTIFIED_CPE} rows, run against this branch's (closed-mode)
 * current {@link Stage1IdentificationService} directly — same no-cost setup as {@link
 * ChocolateyRemovalGolden300RecallTest} ({@code REAL_USER_ID}=5 has no Claude key, so Tier2/Tier3
 * never fire), same rolled-back-transaction, no-durable-write pattern.
 *
 * <p>Unlike {@link ChocolateyRemovalGolden300RecallTest} (identified-vs-not recall only), this
 * additionally compares the resolved CPE's own vendor:product against golden-300's {@code
 * expected_cpe_vendor}/{@code expected_cpe_product} columns for every {@code IDENTIFIED_CPE} row —
 * catching the "identified but the wrong product" failure mode a bare identified/not check misses.
 * This class intentionally does not depend on any CPE-ranking tie-break work that only exists on
 * the non-closed-mode pipeline (this branch's {@code rankCpeCandidates} is whatever this branch
 * currently has); it measures this branch's own current behavior only.
 *
 * <p>Disabled by default, same convention as every other real-dev-DB test in this package — run
 * once by hand ({@code mvn -Dtest=CpeVendorProductGolden300RecallTest test}), read the printed
 * metrics, then restore {@code @Disabled}.
 */
@SpringBootTest
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:postgresql://postgres:5432/vulncheck",
        "spring.datasource.username=vulncheck",
        // Resolved from the real POSTGRES_PASSWORD env var passed to this docker run invocation,
        // same as every other real-dev-DB test in this package.
        "spring.datasource.password=${POSTGRES_PASSWORD}"
})
@Disabled("Post-item360-Step2-sync remeasurement (2026-09-06) against the real dev DB -- CPE "
        + "vendor:product exact match on this branch's current code is now 64/68 = 0.9412 (up from "
        + "the pre-sync baseline's 62/68 = 0.9118), matching master's own 64/68 for this same class: "
        + "the sibling-product mismatches (VirtualBox and Microsoft Visual Studio) are now resolved "
        + "correctly thanks to master's outlier-guard/sibling-derivation-suppression logic landing via "
        + "the item360 Step2 sync merge. 4 mismatches remain, unchanged in kind from before: Metasploit "
        + "Framework unidentified; Notepad++/Zoom/Kibana resolve to an aliased vendor name. See class "
        + "javadoc. Left disabled so it can never re-fire on a routine mvn test run.")
class CpeVendorProductGolden300RecallTest {

    private static final Long REAL_USER_ID = 5L;

    @Autowired
    private ResearchJobService researchJobService;
    @Autowired
    private ResearchJobItemRepository researchJobItemRepository;
    @Autowired
    private Stage1IdentificationService stage1IdentificationService;

    private record GoldenRow(String expectedOutcome, String expectedCpeVendor, String expectedCpeProduct) {
    }

    @Test
    @Transactional
    void measureCpeVendorProductAccuracy() throws Exception {
        ResearchJob job;
        try (InputStream csv = getClass().getClassLoader().getResourceAsStream("golden-300.csv")) {
            job = researchJobService.createJob(
                    REAL_USER_ID, "golden-300-cpe-vendor-product-recheck.csv", csv, ColumnMapping.identity(), false);
        }
        List<ResearchJobItem> items = researchJobItemRepository.findByJobIdOrderById(job.getId());

        Map<String, GoldenRow> expectedByKey = new HashMap<>();
        try (InputStream csv = getClass().getClassLoader().getResourceAsStream("golden-300.csv");
                CSVParser parser = CSVParser.parse(new InputStreamReader(csv, StandardCharsets.UTF_8),
                        CSVFormat.DEFAULT.builder().setHeader().setSkipHeaderRecord(true).build())) {
            for (CSVRecord record : parser) {
                expectedByKey.put(key(record.get("product_name"), record.get("version")),
                        new GoldenRow(record.get("expected_outcome"),
                                record.get("expected_cpe_vendor"), record.get("expected_cpe_product")));
            }
        }

        int cpeTargetTotal = 0;
        int cpeVendorProductCorrect = 0;
        int missingExpected = 0;

        for (ResearchJobItem item : items) {
            GoldenRow expected = expectedByKey.get(key(item.getRawProductName(), item.getVersion()));
            if (expected == null) {
                missingExpected++;
                continue;
            }
            if (!"IDENTIFIED_CPE".equals(expected.expectedOutcome())
                    || expected.expectedCpeVendor() == null || expected.expectedCpeVendor().isBlank()
                    || expected.expectedCpeProduct() == null || expected.expectedCpeProduct().isBlank()) {
                continue;
            }
            cpeTargetTotal++;
            Optional<IdentifiedProduct> result = stage1IdentificationService.identify(item, REAL_USER_ID);
            String actualCpe = result.map(IdentifiedProduct::getCpe).orElse(null);
            CpeUtils.VendorProduct actual = actualCpe == null ? null : CpeUtils.parseVendorProduct(actualCpe);
            boolean correct = actual != null
                    && expected.expectedCpeVendor().equalsIgnoreCase(actual.vendor())
                    && expected.expectedCpeProduct().equalsIgnoreCase(actual.product());
            if (correct) {
                cpeVendorProductCorrect++;
            } else {
                System.out.println("CPE VENDOR:PRODUCT MISMATCH: " + item.getRawProductName() + " " + item.getVersion()
                        + " -> expected=" + expected.expectedCpeVendor() + ":" + expected.expectedCpeProduct()
                        + " actual=" + (actual == null ? "UNIDENTIFIED/no-cpe" : actual.vendor() + ":" + actual.product()));
            }
        }

        System.out.println("\n=== closed-mode golden-300 CPE vendor:product accuracy measurement ===");
        System.out.println("missingExpected=" + missingExpected);
        System.out.printf("CPE vendor:product exact match: %d/%d = %.4f%n", cpeVendorProductCorrect, cpeTargetTotal,
                cpeTargetTotal == 0 ? 0.0 : (double) cpeVendorProductCorrect / cpeTargetTotal);
    }

    private static String key(String productName, String version) {
        return productName + " " + version;
    }
}
