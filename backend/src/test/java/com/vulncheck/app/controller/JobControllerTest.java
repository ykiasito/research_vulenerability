package com.vulncheck.app.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import com.vulncheck.app.entity.IdentifiedProduct;
import com.vulncheck.app.entity.ResearchJob;
import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.entity.User;
import com.vulncheck.app.repository.IdentifiedProductRepository;
import com.vulncheck.app.repository.JobItemVulnerabilityCappedView;
import com.vulncheck.app.repository.JobItemVulnerabilityRepository;
import com.vulncheck.app.repository.ResearchJobItemRepository;
import com.vulncheck.app.repository.ResearchJobRepository;
import com.vulncheck.app.repository.UserRepository;
import com.vulncheck.app.service.CsvParsingService;
import com.vulncheck.app.service.PendingCsvUploadStore;
import com.vulncheck.app.service.ResearchJobProcessingService;
import com.vulncheck.app.service.ResearchJobService;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;

/**
 * {@link JobController#exportCsv} — a plain Mockito unit test invoking the controller method
 * directly (this codebase has no MockMvc/@WebMvcTest infrastructure elsewhere; every existing test
 * is a Mockito-based unit test, so this follows the same convention rather than introducing a new
 * one for a single endpoint).
 */
@ExtendWith(MockitoExtension.class)
class JobControllerTest {

    @Mock
    private ResearchJobService researchJobService;
    @Mock
    private ResearchJobProcessingService researchJobProcessingService;
    @Mock
    private ResearchJobRepository researchJobRepository;
    @Mock
    private ResearchJobItemRepository researchJobItemRepository;
    @Mock
    private IdentifiedProductRepository identifiedProductRepository;
    @Mock
    private JobItemVulnerabilityRepository jobItemVulnerabilityRepository;
    @Mock
    private UserRepository userRepository;
    @Mock
    private CsvParsingService csvParsingService;
    @Mock
    private PendingCsvUploadStore pendingCsvUploadStore;

    private JobController newController() {
        return new JobController(researchJobService, researchJobProcessingService, researchJobRepository,
                researchJobItemRepository, identifiedProductRepository, jobItemVulnerabilityRepository,
                userRepository, csvParsingService, pendingCsvUploadStore);
    }

    private User user(Long id, String email) {
        User user = new User();
        user.setId(id);
        user.setEmail(email);
        user.setPasswordHash("hash");
        return user;
    }

    private UserDetails userDetails(String email) {
        return org.springframework.security.core.userdetails.User
                .withUsername(email).password("x").roles("USER").build();
    }

    private ResearchJob job(Long id, Long ownerUserId) {
        ResearchJob job = new ResearchJob();
        job.setId(id);
        job.setUserId(ownerUserId);
        job.setCsvFilename("test.csv");
        job.setStatus(ResearchJob.STATUS_COMPLETED);
        return job;
    }

    private ResearchJobItem item(Long id, Long jobId, String productName, String version, String vendor, String status) {
        ResearchJobItem item = new ResearchJobItem();
        item.setId(id);
        item.setJobId(jobId);
        item.setProductName(productName);
        item.setVersion(version);
        item.setVendor(vendor);
        item.setUsageText("used somewhere");
        item.setStatus(status);
        return item;
    }

    /** Fixture builder for {@link JobItemVulnerabilityCappedView} (an interface projection, not
     *  instantiable via {@code new}) — same field order as the old {@code JobItemVulnerabilityView}
     *  record constructor this replaces, plus {@code totalCount} appended. */
    private JobItemVulnerabilityCappedView cappedView(Long jobItemId, String cveOrGhsaId, String source,
            String severity, String url, String discoveredViaTier, String citationUrl, String fixedVersion,
            String bundledComponentName, String bundledComponentVersion, String csafAdvisoryId, String csafStatus,
            String csafFixedVersion, long totalCount) {
        return new JobItemVulnerabilityCappedView() {
            @Override
            public Long getJobItemId() {
                return jobItemId;
            }

            @Override
            public String getCveOrGhsaId() {
                return cveOrGhsaId;
            }

            @Override
            public String getSource() {
                return source;
            }

            @Override
            public String getSeverity() {
                return severity;
            }

            @Override
            public String getUrl() {
                return url;
            }

            @Override
            public String getDiscoveredViaTier() {
                return discoveredViaTier;
            }

            @Override
            public String getCitationUrl() {
                return citationUrl;
            }

            @Override
            public String getFixedVersion() {
                return fixedVersion;
            }

            @Override
            public String getBundledComponentName() {
                return bundledComponentName;
            }

            @Override
            public String getBundledComponentVersion() {
                return bundledComponentVersion;
            }

            @Override
            public String getCsafAdvisoryId() {
                return csafAdvisoryId;
            }

            @Override
            public String getCsafStatus() {
                return csafStatus;
            }

            @Override
            public String getCsafFixedVersion() {
                return csafFixedVersion;
            }

            @Override
            public Long getTotalCount() {
                return totalCount;
            }
        };
    }

    @Test
    void exportCsvReturnsAllColumnsForAMixOfIdentifiedAndUnidentifiedItems() throws IOException {
        User owner = user(1L, "owner@example.com");
        ResearchJob job = job(10L, 1L);
        ResearchJobItem identifiedItem =
                item(100L, 10L, "lodash", "4.17.21", null, ResearchJobItem.STATUS_IDENTIFIED);
        ResearchJobItem unidentifiedItem =
                item(101L, 10L, "some obscure tool", "9.9.9", "Acme", ResearchJobItem.STATUS_UNIDENTIFIED);

        IdentifiedProduct identifiedProduct = new IdentifiedProduct();
        identifiedProduct.setJobItemId(100L);
        identifiedProduct.setEcosystem("npm");
        identifiedProduct.setPackageName("lodash");
        identifiedProduct.setConfidence(new BigDecimal("0.95"));

        JobItemVulnerabilityCappedView vuln1 = cappedView(
                100L, "CVE-2021-0001", "nvd", "HIGH", "https://example.com/1", "stage2", null, null, null, null, null, null, null, 2L);
        JobItemVulnerabilityCappedView vuln2 = cappedView(
                100L, "GHSA-aaaa-bbbb-cccc", "ghsa", "MEDIUM", "https://example.com/2", "stage2", null, null, null, null, null, null, null, 2L);

        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(owner));
        when(researchJobRepository.findById(10L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdOrderById(10L)).thenReturn(List.of(identifiedItem, unidentifiedItem));
        when(identifiedProductRepository.findByJobItemIdIn(List.of(100L, 101L))).thenReturn(List.of(identifiedProduct));
        when(jobItemVulnerabilityRepository.findCappedViewsByJobItemIdIn(eq(List.of(100L, 101L)), anyInt()))
                .thenReturn(List.of(vuln1, vuln2));

        ResponseEntity<byte[]> response = newController().exportCsv(userDetails("owner@example.com"), 10L);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getHeaders().getFirst("Content-Disposition"))
                .isEqualTo("attachment; filename=\"job_10_results.csv\"");

        List<CSVRecord> rows = parseCsv(response.getBody());
        assertThat(rows).hasSize(2);

        CSVRecord identifiedRow = rows.get(0);
        assertThat(identifiedRow.get("product_name")).isEqualTo("lodash");
        assertThat(identifiedRow.get("version")).isEqualTo("4.17.21");
        assertThat(identifiedRow.get("status")).isEqualTo(ResearchJobItem.STATUS_IDENTIFIED);
        assertThat(identifiedRow.get("ecosystem")).isEqualTo("npm");
        assertThat(identifiedRow.get("package_or_cpe")).isEqualTo("lodash");
        assertThat(identifiedRow.get("confidence")).isEqualTo("0.95");
        assertThat(identifiedRow.get("vulnerability_count")).isEqualTo("2");
        assertThat(identifiedRow.get("vulnerabilities")).isEqualTo("CVE-2021-0001; GHSA-aaaa-bbbb-cccc");

        CSVRecord unidentifiedRow = rows.get(1);
        assertThat(unidentifiedRow.get("product_name")).isEqualTo("some obscure tool");
        assertThat(unidentifiedRow.get("vendor")).isEqualTo("Acme");
        assertThat(unidentifiedRow.get("status")).isEqualTo(ResearchJobItem.STATUS_UNIDENTIFIED);
        assertThat(unidentifiedRow.get("ecosystem")).isEmpty();
        assertThat(unidentifiedRow.get("package_or_cpe")).isEmpty();
        assertThat(unidentifiedRow.get("vulnerability_count")).isEqualTo("0");
        assertThat(unidentifiedRow.get("vulnerabilities")).isEmpty();
    }

    @Test
    void exportCsvRejectsAJobOwnedByAnotherUser() {
        User requestingUser = user(2L, "other@example.com");
        ResearchJob job = job(10L, 1L); // owned by user 1, not the requester (user 2)

        when(userRepository.findByEmail("other@example.com")).thenReturn(Optional.of(requestingUser));
        when(researchJobRepository.findById(10L)).thenReturn(Optional.of(job));

        assertThatThrownBy(() -> newController().exportCsv(userDetails("other@example.com"), 10L))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // --- REVISE item 4 (senior review 2026-08-26): bundled findings must not be counted/listed as
    // the product's own in the CSV export -----------------------------------------------------

    @Test
    void exportCsvSeparatesBundledComponentFindingsFromTheProductsOwnVulnerabilities() throws IOException {
        User owner = user(1L, "owner@example.com");
        ResearchJob job = job(10L, 1L);
        ResearchJobItem identifiedItem =
                item(100L, 10L, "Chocolatey CLI", "4.6.0", null, ResearchJobItem.STATUS_IDENTIFIED);

        // One product finding (no bundled attribution) plus one bundled 7-Zip finding.
        JobItemVulnerabilityCappedView productVuln = cappedView(
                100L, "CVE-2021-0001", "nvd", "HIGH", "https://example.com/1", "stage2", null, null, null, null, null, null, null, 1L);
        JobItemVulnerabilityCappedView bundledVuln = cappedView(
                100L, "CVE-2026-11111", "nvd", "CRITICAL", "https://example.com/2", "bundled_component", null,
                "26.03", "7-Zip", "26.02", null, null, null, 1L);

        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(owner));
        when(researchJobRepository.findById(10L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdOrderById(10L)).thenReturn(List.of(identifiedItem));
        when(identifiedProductRepository.findByJobItemIdIn(List.of(100L))).thenReturn(List.of());
        when(jobItemVulnerabilityRepository.findCappedViewsByJobItemIdIn(eq(List.of(100L)), anyInt()))
                .thenReturn(List.of(productVuln, bundledVuln));

        ResponseEntity<byte[]> response = newController().exportCsv(userDetails("owner@example.com"), 10L);

        List<CSVRecord> rows = parseCsv(response.getBody());
        assertThat(rows).hasSize(1);
        CSVRecord row = rows.get(0);
        // The product's own count/list excludes the bundled finding entirely.
        assertThat(row.get("vulnerability_count")).isEqualTo("1");
        assertThat(row.get("vulnerabilities")).isEqualTo("CVE-2021-0001");
        // The bundled finding is surfaced separately, as a presence flag (component + version).
        assertThat(row.get("bundled_component_findings")).isEqualTo("7-Zip 26.02");
    }

    // --- closed-mode backlog item 251 REVISE item 4: the display/export cap appends a "他N件"
    // notice to the vulnerabilities cell (not to vulnerability_count, which stays the true total) --

    @Test
    void exportCsvAppendsAHiddenCountNoticeWhenTheTrueTotalExceedsWhatWasReturned() throws IOException {
        User owner = user(1L, "owner@example.com");
        ResearchJob job = job(10L, 1L);
        ResearchJobItem identifiedItem =
                item(100L, 10L, "Google Chrome", "127.0.6533.100", null, ResearchJobItem.STATUS_IDENTIFIED);

        // Simulates the repository having already capped the list server-side: only 2 rows come
        // back, but each carries the TRUE total (2739) via getTotalCount().
        JobItemVulnerabilityCappedView vuln1 = cappedView(
                100L, "CVE-2024-0001", "nvd", "CRITICAL", "u", "nvd", null, null, null, null, null, null, null, 2739L);
        JobItemVulnerabilityCappedView vuln2 = cappedView(
                100L, "CVE-2024-0002", "nvd", "CRITICAL", "u", "nvd", null, null, null, null, null, null, null, 2739L);

        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(owner));
        when(researchJobRepository.findById(10L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdOrderById(10L)).thenReturn(List.of(identifiedItem));
        when(identifiedProductRepository.findByJobItemIdIn(List.of(100L))).thenReturn(List.of());
        when(jobItemVulnerabilityRepository.findCappedViewsByJobItemIdIn(eq(List.of(100L)), anyInt()))
                .thenReturn(List.of(vuln1, vuln2));

        ResponseEntity<byte[]> response = newController().exportCsv(userDetails("owner@example.com"), 10L);

        List<CSVRecord> rows = parseCsv(response.getBody());
        CSVRecord row = rows.get(0);
        // vulnerability_count is the TRUE total, never capped.
        assertThat(row.get("vulnerability_count")).isEqualTo("2739");
        // The listed-ids cell shows what was actually returned plus how many more exist.
        assertThat(row.get("vulnerabilities")).isEqualTo("CVE-2024-0001; CVE-2024-0002; 他2737件");
    }

    // --- CSAF annotation (docs/spec/csaf-vendor-advisory-plan.md §8-2(b)) --------------------------

    @Test
    void detailPassesTheItemsOwnMaxFixedVersionThroughToTheModelWithoutRecomputingIt() {
        // closed-mode backlog item 251 REVISE item 5: JobController no longer computes this at all —
        // it's Stage2VulnerabilityResearchService's job now (see its own tests for that computation's
        // coverage). This just confirms the item itself (carrying whatever Stage2 already persisted)
        // reaches the model unchanged.
        User owner = user(1L, "owner@example.com");
        ResearchJob job = job(10L, 1L);
        ResearchJobItem identifiedItem =
                item(100L, 10L, "OpenSSL", "3.0.1", null, ResearchJobItem.STATUS_IDENTIFIED);
        identifiedItem.setMaxFixedVersion("3.0.7");

        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(owner));
        when(researchJobRepository.findById(10L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdOrderById(10L)).thenReturn(List.of(identifiedItem));
        when(identifiedProductRepository.findByJobItemIdIn(List.of(100L))).thenReturn(List.of());
        when(jobItemVulnerabilityRepository.findCappedViewsByJobItemIdIn(eq(List.of(100L)), anyInt()))
                .thenReturn(List.of());

        Model model = new ExtendedModelMap();
        newController().detail(userDetails("owner@example.com"), 10L, model);

        @SuppressWarnings("unchecked")
        List<ResearchJobItem> items = (List<ResearchJobItem>) model.getAttribute("items");
        assertThat(items).hasSize(1);
        assertThat(items.get(0).getMaxFixedVersion()).isEqualTo("3.0.7");
    }

    // --- Second REVISE round (closed-mode backlog item 251, item 1): detail.html must be able to
    // tell the user a category's findings list was capped, and by how much -- this asserts the model
    // attributes detail.html's notice reads (productCountsByItemId/bundledCountsByItemId), since this
    // test suite has no MockMvc/Thymeleaf rendering infrastructure to assert the rendered HTML
    // itself against ------------------------------------------------------------------------------

    @Test
    void detailComputesPerCategoryShownAndTrueCountsSeparatelyForProductAndBundledFindings() {
        User owner = user(1L, "owner@example.com");
        ResearchJob job = job(10L, 1L);
        ResearchJobItem identifiedItem =
                item(100L, 10L, "Google Chrome", "127.0.6533.100", null, ResearchJobItem.STATUS_IDENTIFIED);

        // 2 product findings returned (out of a true total of 2739) and 1 bundled finding returned
        // (out of a true total of 3) -- two independently-capped categories, same item.
        JobItemVulnerabilityCappedView productVuln1 = cappedView(
                100L, "CVE-2024-0001", "nvd", "CRITICAL", "u", "nvd", null, null, null, null, null, null, null, 2739L);
        JobItemVulnerabilityCappedView productVuln2 = cappedView(
                100L, "CVE-2024-0002", "nvd", "CRITICAL", "u", "nvd", null, null, null, null, null, null, null, 2739L);
        JobItemVulnerabilityCappedView bundledVuln = cappedView(
                100L, "CVE-2026-11111", "nvd", "HIGH", "u", "bundled_component", null, "26.03", "7-Zip", "26.02",
                null, null, null, 3L);

        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(owner));
        when(researchJobRepository.findById(10L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdOrderById(10L)).thenReturn(List.of(identifiedItem));
        when(identifiedProductRepository.findByJobItemIdIn(List.of(100L))).thenReturn(List.of());
        when(jobItemVulnerabilityRepository.findCappedViewsByJobItemIdIn(eq(List.of(100L)), anyInt()))
                .thenReturn(List.of(productVuln1, productVuln2, bundledVuln));

        Model model = new ExtendedModelMap();
        newController().detail(userDetails("owner@example.com"), 10L, model);

        @SuppressWarnings("unchecked")
        var productCountsByItemId = (java.util.Map<Long, JobController.CategoryCounts>) model.getAttribute("productCountsByItemId");
        @SuppressWarnings("unchecked")
        var bundledCountsByItemId = (java.util.Map<Long, JobController.CategoryCounts>) model.getAttribute("bundledCountsByItemId");

        assertThat(productCountsByItemId.get(100L)).isEqualTo(new JobController.CategoryCounts(2, 2739L));
        assertThat(bundledCountsByItemId.get(100L)).isEqualTo(new JobController.CategoryCounts(1, 3L));
    }

    @Test
    void detailOmitsCategoryCountsForAnItemWithNoFindingsAtAllInThatCategory() {
        User owner = user(1L, "owner@example.com");
        ResearchJob job = job(10L, 1L);
        ResearchJobItem identifiedItem =
                item(100L, 10L, "lodash", "4.17.21", null, ResearchJobItem.STATUS_IDENTIFIED);

        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(owner));
        when(researchJobRepository.findById(10L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdOrderById(10L)).thenReturn(List.of(identifiedItem));
        when(identifiedProductRepository.findByJobItemIdIn(List.of(100L))).thenReturn(List.of());
        when(jobItemVulnerabilityRepository.findCappedViewsByJobItemIdIn(eq(List.of(100L)), anyInt()))
                .thenReturn(List.of());

        Model model = new ExtendedModelMap();
        newController().detail(userDetails("owner@example.com"), 10L, model);

        @SuppressWarnings("unchecked")
        var productCountsByItemId = (java.util.Map<Long, JobController.CategoryCounts>) model.getAttribute("productCountsByItemId");
        @SuppressWarnings("unchecked")
        var bundledCountsByItemId = (java.util.Map<Long, JobController.CategoryCounts>) model.getAttribute("bundledCountsByItemId");

        assertThat(productCountsByItemId).doesNotContainKey(100L);
        assertThat(bundledCountsByItemId).doesNotContainKey(100L);
    }

    // --- Third REVISE round (PR#170): detail.html must never hardcode the 10/200 cap values itself
    // -- pinning these model attributes to the controller's own constants means the template's
    // notice text can never silently drift from the actual cap. ------------------------------------

    @Test
    void detailExposesTheCapConstantsAsModelAttributesMatchingTheControllersOwnValues() {
        User owner = user(1L, "owner@example.com");
        ResearchJob job = job(10L, 1L);
        ResearchJobItem identifiedItem =
                item(100L, 10L, "lodash", "4.17.21", null, ResearchJobItem.STATUS_IDENTIFIED);

        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(owner));
        when(researchJobRepository.findById(10L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdOrderById(10L)).thenReturn(List.of(identifiedItem));
        when(identifiedProductRepository.findByJobItemIdIn(List.of(100L))).thenReturn(List.of());
        when(jobItemVulnerabilityRepository.findCappedViewsByJobItemIdIn(eq(List.of(100L)), anyInt()))
                .thenReturn(List.of());

        Model model = new ExtendedModelMap();
        newController().detail(userDetails("owner@example.com"), 10L, model);

        // Package-visible (not private) specifically so this test can pin the model attribute to
        // the controller's own constant rather than a literal that could silently drift from it.
        assertThat(model.getAttribute("htmlDetailFindingCap")).isEqualTo(JobController.HTML_DETAIL_FINDING_CAP);
        assertThat(model.getAttribute("csvExportFindingCap")).isEqualTo(JobController.CSV_EXPORT_FINDING_CAP);
    }

    // --- REVISE item 10 (senior review 2026-08-27): the CSV export must reflect CSAF vendor status --

    @Test
    void exportCsvIncludesACsafVendorStatusColumn() throws IOException {
        User owner = user(1L, "owner@example.com");
        ResearchJob job = job(10L, 1L);
        ResearchJobItem identifiedItem =
                item(100L, 10L, "OpenSSL", "3.0.1", null, ResearchJobItem.STATUS_IDENTIFIED);

        JobItemVulnerabilityCappedView annotatedVuln = cappedView(
                100L, "CVE-2024-1111", "nvd", "HIGH", "https://example.com/1", "nvd", null, "3.0.7", null, null,
                "SSA-1", "known_affected", "0:3.0.7-24.el9_2", 2L);
        JobItemVulnerabilityCappedView plainVuln = cappedView(
                100L, "CVE-2024-9999", "nvd", "LOW", "https://example.com/2", "nvd", null, null, null, null,
                null, null, null, 2L);

        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(owner));
        when(researchJobRepository.findById(10L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdOrderById(10L)).thenReturn(List.of(identifiedItem));
        when(identifiedProductRepository.findByJobItemIdIn(List.of(100L))).thenReturn(List.of());
        when(jobItemVulnerabilityRepository.findCappedViewsByJobItemIdIn(eq(List.of(100L)), anyInt()))
                .thenReturn(List.of(annotatedVuln, plainVuln));

        ResponseEntity<byte[]> response = newController().exportCsv(userDetails("owner@example.com"), 10L);

        List<CSVRecord> rows = parseCsv(response.getBody());
        assertThat(rows).hasSize(1);
        CSVRecord row = rows.get(0);
        // Existing vulnerability_count/vulnerabilities semantics are unchanged by this column.
        assertThat(row.get("vulnerability_count")).isEqualTo("2");
        assertThat(row.get("csaf_vendor_status")).isEqualTo("CVE-2024-1111: known_affected (SSA-1)");
    }

    // --- Task backlog item 103 (2026-08-31): the job detail view's "checked, clean" vs. "not
    // actually checked" distinction must survive into the CSV export -----------------------------

    @Test
    void exportCsvIncludesResearchIncompleteReasonColumnWhenSet() throws IOException {
        User owner = user(1L, "owner@example.com");
        ResearchJob job = job(10L, 1L);
        ResearchJobItem itemWithReason =
                item(100L, 10L, "lodash", "4.17.21", null, ResearchJobItem.STATUS_IDENTIFIED);
        itemWithReason.setResearchIncompleteReason(ResearchJobItem.INCOMPLETE_REASON_AI_NOT_AVAILABLE);
        ResearchJobItem itemWithoutReason =
                item(101L, 10L, "express", "4.18.0", null, ResearchJobItem.STATUS_IDENTIFIED);

        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(owner));
        when(researchJobRepository.findById(10L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdOrderById(10L))
                .thenReturn(List.of(itemWithReason, itemWithoutReason));
        when(identifiedProductRepository.findByJobItemIdIn(List.of(100L, 101L))).thenReturn(List.of());
        when(jobItemVulnerabilityRepository.findCappedViewsByJobItemIdIn(eq(List.of(100L, 101L)), anyInt()))
                .thenReturn(List.of());

        ResponseEntity<byte[]> response = newController().exportCsv(userDetails("owner@example.com"), 10L);

        List<CSVRecord> rows = parseCsv(response.getBody());
        assertThat(rows).hasSize(2);
        assertThat(rows.get(0).get("research_incomplete_reason"))
                .isEqualTo(ResearchJobItem.INCOMPLETE_REASON_AI_NOT_AVAILABLE);
        // Unset (fully verified/genuine clean result) must export as an empty cell, not "null".
        assertThat(rows.get(1).get("research_incomplete_reason")).isEmpty();
    }

    private List<CSVRecord> parseCsv(byte[] body) throws IOException {
        // The export is BOM-prefixed for Excel compatibility (see JobController#BOM); strip it the
        // same way CsvParsingService does before handing the stream to CSVParser.
        String text = new String(body, StandardCharsets.UTF_8);
        String bom = Character.toString(0xFEFF);
        String withoutBom = text.startsWith(bom) ? text.substring(1) : text;
        try (CSVParser parser = CSVParser.parse(
                new InputStreamReader(new ByteArrayInputStream(withoutBom.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8),
                CSVFormat.DEFAULT.builder().setHeader().setSkipHeaderRecord(true).build())) {
            return parser.getRecords();
        }
    }
}
