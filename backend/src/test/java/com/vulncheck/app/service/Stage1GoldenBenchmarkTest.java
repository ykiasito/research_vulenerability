package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import com.vulncheck.app.entity.CpeDictionaryEntry;
import com.vulncheck.app.entity.IdentifiedProduct;
import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.repository.CpeDictionaryRepository;
import com.vulncheck.app.repository.IdentifiedProductRepository;
import com.vulncheck.app.service.nvd.CpeNameVariantCache;
import com.vulncheck.app.service.nvd.CpeUtils;
import com.vulncheck.app.service.registry.PackageRegistryLookup;
import com.vulncheck.app.service.registry.RegistryLookupCache;
import com.vulncheck.app.service.registry.RegistryMatch;
import com.vulncheck.app.service.registry.RegistryRoutingPolicy;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Golden regression-gate benchmark for {@link Stage1IdentificationService}, seeded from the
 * specific items adjudicated (with a stated correct answer) across accuracy validation jobs
 * 35/36/37 and the senior-review round-2/round-3 root-cause writeups. Unlike the ad-hoc 400-item
 * CSV validation rounds that produced it — which only ever compared *aggregate*
 * IDENTIFIED/UNIDENTIFIED counts between runs and twice let real regressions through undetected —
 * every case here asserts a specific per-item expected outcome, and runs as an ordinary part of
 * {@code mvn test} so it's a real gate on every future change, not a one-off script.
 *
 * <p>Each case is a row (or group of rows sharing one {@code case_id}) in {@code
 * stage1-golden-benchmark.csv}, replaying the exact real dictionary rows/registry matches involved
 * in that item's adjudication directly against {@link Stage1IdentificationService#identify}
 * (Mockito-mocked dependencies, no live DB/network — consistent with every other test in this
 * class's package) rather than a full job.
 *
 * <p>To extend this benchmark: add a new {@code case_id} group to the CSV fixture with the
 * mocked dictionary row(s)/registry match a future round found relevant, and the adjudicated
 * {@code expected_outcome} (one of {@code IDENTIFIED_WITH_CPE}, {@code IDENTIFIED_NO_CPE}, {@code
 * UNIDENTIFIED}). No new Java code is needed for the common case of "one more known-correct
 * product/outcome pair" — only add a Java-level case if the scenario needs something the CSV
 * schema can't express (e.g. an AI disambiguation call, which this benchmark deliberately never
 * exercises — see {@link #commonStubs()}).
 */
@ExtendWith(MockitoExtension.class)
class Stage1GoldenBenchmarkTest {

    private static final Long USER_ID = 42L;
    private static final String GOLDEN_CSV_RESOURCE = "stage1-golden-benchmark.csv";

    @Mock
    private CpeDictionaryRepository cpeDictionaryRepository;

    @Mock
    private IdentifiedProductRepository identifiedProductRepository;

    @Mock
    private UserApiKeyService userApiKeyService;

    @Mock
    private NvdCpeSyncService nvdCpeSyncService;

    @Mock
    private RegistryRoutingPolicy registryRoutingPolicy;

    @BeforeEach
    void commonStubs() {
        // This benchmark deliberately validates the static-only pipeline — closed-mode B2
        // (docs/spec/closed-mode-plan.md §9-2) made that the *only* pipeline: every AI call site
        // this benchmark used to have to deliberately avoid is gone outright, always taking the
        // exact fallback this benchmark already validated against.
        lenient().when(registryRoutingPolicy.route(any(), any())).thenAnswer(invocation -> invocation.getArgument(1));
        lenient().when(nvdCpeSyncService.syncKeywordSinglePage(anyString(), anyInt(), any())).thenReturn(0);
        lenient().when(identifiedProductRepository.save(any(IdentifiedProduct.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("goldenCases")
    void matchesTheAdjudicatedOutcome(GoldenCase goldenCase) {
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(goldenCase.mockEntries());

        ResearchJobItem item = new ResearchJobItem();
        item.setId(1L);
        item.setJobId(1L);
        item.setProductName(goldenCase.productName());
        item.setVendor(goldenCase.vendor());
        item.setVersion("1.0.0");
        item.setUsageText("golden benchmark");

        List<PackageRegistryLookup> lookups =
                goldenCase.registryEcosystem() == null ? List.of() : List.of(fixedRegistryLookup(goldenCase));

        // Closed-mode B2 (docs/spec/closed-mode-plan.md §9-2): both collaborators below are now
        // gutted to an unconditional AI-unavailable fallback — see their own javadoc.
        HighConfidenceVerificationService highConfidenceVerificationService = new HighConfidenceVerificationService();
        Stage1RegistryIdentification registryIdentification = new Stage1RegistryIdentification(
                lookups, registryRoutingPolicy, new RegistryLookupCache());
        Stage1AiArbitration aiArbitration = new Stage1AiArbitration();
        Stage1IdentificationService service = new Stage1IdentificationService(
                cpeDictionaryRepository, new CpeNameVariantCache(), identifiedProductRepository, userApiKeyService,
                nvdCpeSyncService, highConfidenceVerificationService, registryIdentification, aiArbitration);

        Optional<IdentifiedProduct> result = service.identify(item, USER_ID);

        switch (goldenCase.expectedOutcome()) {
            case UNIDENTIFIED -> assertThat(result).as(goldenCase.caseId()).isEmpty();
            case IDENTIFIED_NO_CPE -> {
                assertThat(result).as(goldenCase.caseId()).isPresent();
                assertThat(result.get().getEcosystem()).as(goldenCase.caseId()).isEqualTo(goldenCase.expectedEcosystem());
                assertThat(result.get().getCpe()).as(goldenCase.caseId()).isNull();
            }
            case IDENTIFIED_WITH_CPE -> {
                assertThat(result).as(goldenCase.caseId()).isPresent();
                if (goldenCase.expectedEcosystem() != null) {
                    assertThat(result.get().getEcosystem()).as(goldenCase.caseId()).isEqualTo(goldenCase.expectedEcosystem());
                }
                CpeUtils.VendorProduct vendorProduct = CpeUtils.parseVendorProduct(result.get().getCpe());
                assertThat(vendorProduct).as(goldenCase.caseId()).isNotNull();
                assertThat(vendorProduct.vendor()).as(goldenCase.caseId()).isEqualTo(goldenCase.expectedCpeVendor());
                assertThat(vendorProduct.product()).as(goldenCase.caseId()).isEqualTo(goldenCase.expectedCpeProduct());
            }
        }
    }

    private PackageRegistryLookup fixedRegistryLookup(GoldenCase goldenCase) {
        return new PackageRegistryLookup() {
            @Override
            public Optional<RegistryMatch> lookup(String name, String version) {
                return Optional.of(new RegistryMatch(
                        goldenCase.registryEcosystem(),
                        goldenCase.registryPackageName(),
                        "pkg:" + goldenCase.registryEcosystem() + "/" + goldenCase.registryPackageName(),
                        new BigDecimal("0.95"),
                        Boolean.TRUE.equals(goldenCase.registryExactVersionConfirmed())));
            }

            @Override
            public String ecosystem() {
                return goldenCase.registryEcosystem();
            }
        };
    }

    static Stream<GoldenCase> goldenCases() throws IOException {
        CSVFormat format = CSVFormat.DEFAULT.builder()
                .setHeader()
                .setSkipHeaderRecord(true)
                .setTrim(true)
                .setIgnoreSurroundingSpaces(true)
                .build();

        Map<String, List<CSVRecord>> recordsByCaseId = new LinkedHashMap<>();
        try (InputStream csv = Stage1GoldenBenchmarkTest.class.getClassLoader().getResourceAsStream(GOLDEN_CSV_RESOURCE);
                CSVParser parser = CSVParser.parse(new InputStreamReader(csv, StandardCharsets.UTF_8), format)) {
            for (CSVRecord record : parser) {
                recordsByCaseId.computeIfAbsent(record.get("case_id"), key -> new ArrayList<>()).add(record);
            }
        }

        List<GoldenCase> cases = new ArrayList<>();
        for (Map.Entry<String, List<CSVRecord>> group : recordsByCaseId.entrySet()) {
            CSVRecord first = group.getValue().get(0);
            List<CpeDictionaryEntry> mockEntries = new ArrayList<>();
            for (CSVRecord record : group.getValue()) {
                String cpeString = blankToNull(record.get("mock_cpe_string"));
                if (cpeString == null) {
                    continue;
                }
                mockEntries.add(toMockEntry(cpeString, record));
            }
            cases.add(new GoldenCase(
                    group.getKey(),
                    first.get("product_name"),
                    blankToNull(first.get("vendor")),
                    blankToNull(first.get("registry_ecosystem")),
                    blankToNull(first.get("registry_package_name")),
                    "true".equalsIgnoreCase(first.get("registry_exact_version_confirmed")),
                    mockEntries,
                    ExpectedOutcome.valueOf(first.get("expected_outcome")),
                    blankToNull(first.get("expected_ecosystem")),
                    blankToNull(first.get("expected_cpe_vendor")),
                    blankToNull(first.get("expected_cpe_product"))));
        }
        return cases.stream();
    }

    /** Derives vendor/product the same way the real ingestion pipeline does — via {@link
     *  CpeUtils#parseVendorProduct} — rather than a separate hand-maintained CSV column, so a mock
     *  row exercises the same escape-aware parsing real dictionary rows do. {@code mock_product},
     *  when present, overrides just the derived product (never vendor) with a literal value instead
     *  — round 4 addition, letting a case encode "this dictionary row's stored product column
     *  doesn't match what the CPE string itself parses to" (e.g. the pre-backfill corrupted {@code
     *  ktat} row, whose real stored product was literally {@code http\} — see the {@code
     *  V13__backfill_corrupted_cpe_vendor_product} migration and {@code http_crates}'s own case in
     *  the CSV). Blank/absent (the common case, and every pre-round-4 row) falls back to the derived
     *  value, so this is purely additive to the existing schema. */
    private static CpeDictionaryEntry toMockEntry(String cpeString, CSVRecord record) {
        CpeUtils.VendorProduct vendorProduct = CpeUtils.parseVendorProduct(cpeString);
        CpeDictionaryEntry entry = new CpeDictionaryEntry();
        entry.setCpeString(cpeString);
        entry.setVendor(vendorProduct != null ? vendorProduct.vendor() : null);
        String mockProductOverride = blankToNull(record.get("mock_product"));
        entry.setProduct(mockProductOverride != null
                ? mockProductOverride
                : (vendorProduct != null ? vendorProduct.product() : null));
        entry.setTitle(blankToNull(record.get("mock_cpe_title")));
        entry.setLastSyncedAt(OffsetDateTime.now());
        String targetSw = blankToNull(record.get("mock_target_sw"));
        if (targetSw != null) {
            entry.setTargetSwValues(new LinkedHashSet<>(List.of(targetSw.split(";"))));
        }
        return entry;
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    enum ExpectedOutcome {
        IDENTIFIED_WITH_CPE,
        IDENTIFIED_NO_CPE,
        UNIDENTIFIED
    }

    record GoldenCase(
            String caseId,
            String productName,
            String vendor,
            String registryEcosystem,
            String registryPackageName,
            Boolean registryExactVersionConfirmed,
            List<CpeDictionaryEntry> mockEntries,
            ExpectedOutcome expectedOutcome,
            String expectedEcosystem,
            String expectedCpeVendor,
            String expectedCpeProduct) {

        @Override
        public String toString() {
            return caseId;
        }
    }
}
