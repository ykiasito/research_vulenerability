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
 * Backlog item 299 (closed-mode golden-300 case 5, "Microsoft Visual Studio" resolving to the
 * wrong, derived {@code microsoft:visual_studio_code} product) recall re-measurement — same
 * pattern as {@link ChocolateyRemovalGolden300RecallTest} (real dev DB, {@code REAL_USER_ID}=5 has
 * no Claude key so Tier2/Tier3 never fire and this costs nothing, whole run wrapped in a rolled
 * -back transaction so nothing is ever durably written).
 *
 * <p>Unlike {@link ChocolateyRemovalGolden300RecallTest} (identified-vs-not recall only), this
 * additionally compares the resolved CPE's own vendor:product against golden-300's {@code
 * expected_cpe_vendor}/{@code expected_cpe_product} columns for every {@code IDENTIFIED_CPE} row —
 * the "identified but the wrong product" failure mode item 299 case 5 was about, which a bare
 * identified/not check can never catch.
 *
 * <p>Disabled by default, same convention as every other real-dev-DB test in this package — run
 * once by hand ({@code mvn -Dtest=Backlog299CpeRankingGolden300RecallTest test}), read the printed
 * metrics, then restore {@code @Disabled}. Never left enabled for a routine {@code mvn test} run.
 */
@SpringBootTest
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:postgresql://postgres:5432/vulncheck",
        "spring.datasource.username=vulncheck",
        "spring.datasource.password=${POSTGRES_PASSWORD}"
})
@Disabled("Re-measured 2026-09-05 (backlog item 308, VirtualBox exact-slug-vs-version-coverage fix) "
        + "against the real dev DB, both before and after that fix, to satisfy the '68 denominator "
        + "NEEDS RE-MEASUREMENT' note left by the previous (item 299 case 5) update -- CPE "
        + "vendor:product exact match is 63/68 = 0.9265 identically before and after item 308's "
        + "rankCpeCandidates change (zero regression, but also zero improvement on this suite: see "
        + "below). The 5 remaining mismatches are Metasploit Framework, Notepad++, VirtualBox, Zoom, "
        + "Kibana (Cisco IOS XE from the previous note's list is no longer one of them -- and Kibana "
        + "is newly one -- pure real-dev-DB CPE dictionary content drift since that note was written, "
        + "confirmed unrelated to item 308 since both the pre- and post-fix runs here show the exact "
        + "same 5). VirtualBox itself stays a mismatch even after item 308's fix: real dev DB data "
        + "confirms oracle:virtualbox (max cataloged major 3, 8 rows) and oracle:vm_virtualbox (max "
        + "cataloged major 71, 270 rows) exist exactly as item 308's own diagnosis described, but "
        + "oracle:vm_virtualbox never reaches rankCpeCandidates's candidate pool at all for the query "
        + "'VirtualBox' -- plausibleContainmentOnly's explainsQuery admission gate rejects it on both "
        + "the product field ('vm_virtualbox' has an unaccounted-for leading 'vm' token neither "
        + "Direction 1 nor Direction 2 credits) and the title field ('Oracle VM VirtualBox ...' does "
        + "not start with the query token 'virtualbox', so Direction 1's own leading-alignment "
        + "requirement fails) -- confirmed live via a throwaway reflection-based debug test against "
        + "this same dev DB, not by inspection alone. item 308's own senior-review design (narrowing "
        + "exactSlugMatch only for candidates that both reach and tie within the ranked pool) is "
        + "therefore verified correctly implemented and harmless, but does not by itself resolve the "
        + "real golden-300 VirtualBox row -- that would need a separate, unaddressed admission-layer "
        + "change to explainsQuery, out of this task's specified scope. Left disabled so it can never "
        + "re-fire on a routine mvn test run -- see class javadoc. UPDATE PENDING (item 345): once the "
        + "real-dev-DB re-measurement below this fix is run (needs POSTGRES_PASSWORD, not available in "
        + "an isolated engineer worktree -- escalated to the orchestrator/tester per this backlog item's "
        + "own instructions), this note and the max-cataloged-major-71 figure below should be updated "
        + "to reflect the actual post-345 golden-300 CPE accuracy.")
class Backlog299CpeRankingGolden300RecallTest {

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
    void measureCpeVendorProductAccuracyAfterDerivedSiblingRankingFix() throws Exception {
        ResearchJob job;
        try (InputStream csv = getClass().getClassLoader().getResourceAsStream("golden-300.csv")) {
            job = researchJobService.createJob(
                    REAL_USER_ID, "golden-300-backlog-299-recheck.csv", csv, ColumnMapping.identity(), false);
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
                    || expected.expectedCpeVendor() == null || expected.expectedCpeVendor().isBlank()) {
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

        System.out.println("\n=== backlog item 299 case 5 golden-300 CPE vendor:product accuracy re-measurement ===");
        System.out.println("missingExpected=" + missingExpected);
        System.out.printf("CPE vendor:product exact match: %d/%d = %.4f%n", cpeVendorProductCorrect, cpeTargetTotal,
                cpeTargetTotal == 0 ? 0.0 : (double) cpeVendorProductCorrect / cpeTargetTotal);
    }

    private static String key(String productName, String version) {
        return productName + " " + version;
    }
}
