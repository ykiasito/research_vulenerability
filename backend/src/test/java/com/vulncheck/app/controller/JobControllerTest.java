package com.vulncheck.app.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import com.vulncheck.app.entity.IdentifiedProduct;
import com.vulncheck.app.entity.ResearchJob;
import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.entity.User;
import com.vulncheck.app.repository.IdentifiedProductRepository;
import com.vulncheck.app.repository.JobItemVulnerabilityRepository;
import com.vulncheck.app.repository.ResearchJobItemRepository;
import com.vulncheck.app.repository.ResearchJobRepository;
import com.vulncheck.app.repository.UserRepository;
import com.vulncheck.app.service.CsvParsingService;
import com.vulncheck.app.service.JobItemVulnerabilityView;
import com.vulncheck.app.service.PendingCsvUploadStore;
import com.vulncheck.app.service.ResearchJobProcessingService;
import com.vulncheck.app.service.ResearchJobService;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
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

        JobItemVulnerabilityView vuln1 = new JobItemVulnerabilityView(
                100L, "CVE-2021-0001", "nvd", "HIGH", "https://example.com/1", "stage2", null, null, null, null, null, null, null);
        JobItemVulnerabilityView vuln2 = new JobItemVulnerabilityView(
                100L, "GHSA-aaaa-bbbb-cccc", "ghsa", "MEDIUM", "https://example.com/2", "stage2", null, null, null, null, null, null, null);

        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(owner));
        when(researchJobRepository.findById(10L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdOrderById(10L)).thenReturn(List.of(identifiedItem, unidentifiedItem));
        when(identifiedProductRepository.findByJobItemIdIn(List.of(100L, 101L))).thenReturn(List.of(identifiedProduct));
        when(jobItemVulnerabilityRepository.findViewsByJobItemIdIn(List.of(100L, 101L)))
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
        JobItemVulnerabilityView productVuln = new JobItemVulnerabilityView(
                100L, "CVE-2021-0001", "nvd", "HIGH", "https://example.com/1", "stage2", null, null, null, null, null, null, null);
        JobItemVulnerabilityView bundledVuln = new JobItemVulnerabilityView(
                100L, "CVE-2026-11111", "nvd", "CRITICAL", "https://example.com/2", "bundled_component", null,
                "26.03", "7-Zip", "26.02", null, null, null);

        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(owner));
        when(researchJobRepository.findById(10L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdOrderById(10L)).thenReturn(List.of(identifiedItem));
        when(identifiedProductRepository.findByJobItemIdIn(List.of(100L))).thenReturn(List.of());
        when(jobItemVulnerabilityRepository.findViewsByJobItemIdIn(List.of(100L)))
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

    // --- REVISE item 3 (senior review 2026-08-26): a bundled finding must never set the product-
    // level "推奨アップデート版" recommendation ---------------------------------------------------

    @Test
    void detailNeverLetsABundledFindingsFixedVersionSetTheProductLevelMaxFixedVersion() {
        User owner = user(1L, "owner@example.com");
        ResearchJob job = job(10L, 1L);
        ResearchJobItem identifiedItem =
                item(100L, 10L, "Chocolatey CLI", "4.6.0", null, ResearchJobItem.STATUS_IDENTIFIED);

        // A product finding with a low fix version, and a bundled finding with a much higher one
        // (e.g. 7-Zip 26.03) that must not win the product-level recommendation.
        JobItemVulnerabilityView productVuln = new JobItemVulnerabilityView(
                100L, "CVE-2021-0001", "nvd", "HIGH", "https://example.com/1", "stage2", null, "5.0.0", null, null, null, null, null);
        JobItemVulnerabilityView bundledVuln = new JobItemVulnerabilityView(
                100L, "CVE-2026-11111", "nvd", "CRITICAL", "https://example.com/2", "bundled_component", null,
                "26.03", "7-Zip", "26.02", null, null, null);

        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(owner));
        when(researchJobRepository.findById(10L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdOrderById(10L)).thenReturn(List.of(identifiedItem));
        when(identifiedProductRepository.findByJobItemIdIn(List.of(100L))).thenReturn(List.of());
        when(jobItemVulnerabilityRepository.findViewsByJobItemIdIn(List.of(100L)))
                .thenReturn(List.of(productVuln, bundledVuln));

        Model model = new ExtendedModelMap();
        newController().detail(userDetails("owner@example.com"), 10L, model);

        @SuppressWarnings("unchecked")
        Map<Long, String> maxFixedVersionByItemId = (Map<Long, String>) model.getAttribute("maxFixedVersionByItemId");
        assertThat(maxFixedVersionByItemId).containsEntry(100L, "5.0.0");
    }

    // --- CSAF annotation (docs/spec/csaf-vendor-advisory-plan.md §8-2(b)) --------------------------

    @Test
    void detailStillUsesAnotherSourcesFixedVersionOnARowCsafMerelyAnnotated() {
        // Path 1 of the CSAF design (an existing NVD/OSV/CVE.org row CSAF only annotates, never
        // competes for) — the row's own fixedVersion (from NVD) is untouched by the CSAF
        // annotation and must still count toward the product-level recommendation. Only a
        // CSAF-only new row (never reachable here — Stage2VulnerabilityResearchService always
        // writes NULL there) would need excluding, per JobController#highestFixedVersion's javadoc.
        User owner = user(1L, "owner@example.com");
        ResearchJob job = job(10L, 1L);
        ResearchJobItem identifiedItem =
                item(100L, 10L, "OpenSSL", "3.0.1", null, ResearchJobItem.STATUS_IDENTIFIED);

        JobItemVulnerabilityView annotatedVuln = new JobItemVulnerabilityView(
                100L, "CVE-2024-1111", "nvd", "HIGH", "https://example.com/1", "nvd", null, "3.0.7", null, null,
                "SSA-1", "known_affected", "0:3.0.7-24.el9_2");

        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(owner));
        when(researchJobRepository.findById(10L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdOrderById(10L)).thenReturn(List.of(identifiedItem));
        when(identifiedProductRepository.findByJobItemIdIn(List.of(100L))).thenReturn(List.of());
        when(jobItemVulnerabilityRepository.findViewsByJobItemIdIn(List.of(100L)))
                .thenReturn(List.of(annotatedVuln));

        Model model = new ExtendedModelMap();
        newController().detail(userDetails("owner@example.com"), 10L, model);

        @SuppressWarnings("unchecked")
        Map<Long, String> maxFixedVersionByItemId = (Map<Long, String>) model.getAttribute("maxFixedVersionByItemId");
        assertThat(maxFixedVersionByItemId).containsEntry(100L, "3.0.7");
    }

    // --- REVISE item 1 (senior review 2026-08-27): a cross-item write on the shared vulnerabilities
    // row must never leak into this item's own "推奨アップデート版" ----------------------------------

    @Test
    void detailExcludesACsafOnlyRowsFixedVersionEvenWhenACrossItemWriteLandedOnTheSharedRow() {
        // (a) this item's own NVD-sourced finding, with its own legitimate fixed version.
        // (b) a path-2 CSAF-only row for a DIFFERENT CVE — its own write to vulnerabilities.fixed_version
        // is always NULL at insert time (Stage2VulnerabilityResearchService), but simulates a later,
        // unrelated item's finding for the SAME CVE having since populated the shared vulnerabilities
        // row (VulnerabilityRepository#upsertAndGetId's COALESCE — first non-null write from ANY item
        // sticks). That value must never count toward THIS item's recommendation.
        User owner = user(1L, "owner@example.com");
        ResearchJob job = job(10L, 1L);
        ResearchJobItem identifiedItem =
                item(100L, 10L, "Siemens Device", "1.0.0", null, ResearchJobItem.STATUS_IDENTIFIED);

        JobItemVulnerabilityView nvdVuln = new JobItemVulnerabilityView(
                100L, "CVE-2024-1111", "nvd", "HIGH", "https://example.com/1", "nvd", null, "2.1.0", null, null,
                null, null, null);
        JobItemVulnerabilityView csafOnlyVuln = new JobItemVulnerabilityView(
                100L, "CVE-2024-2222", "csaf_siemens", "HIGH", "https://example.com/2", "csaf_siemens", null,
                "3.0.7", null, null, "SSA-2", "known_affected", null);

        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(owner));
        when(researchJobRepository.findById(10L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdOrderById(10L)).thenReturn(List.of(identifiedItem));
        when(identifiedProductRepository.findByJobItemIdIn(List.of(100L))).thenReturn(List.of());
        when(jobItemVulnerabilityRepository.findViewsByJobItemIdIn(List.of(100L)))
                .thenReturn(List.of(nvdVuln, csafOnlyVuln));

        Model model = new ExtendedModelMap();
        newController().detail(userDetails("owner@example.com"), 10L, model);

        @SuppressWarnings("unchecked")
        Map<Long, String> maxFixedVersionByItemId = (Map<Long, String>) model.getAttribute("maxFixedVersionByItemId");
        assertThat(maxFixedVersionByItemId).containsEntry(100L, "2.1.0");
    }

    // --- REVISE item 10 (senior review 2026-08-27): the CSV export must reflect CSAF vendor status --

    @Test
    void exportCsvIncludesACsafVendorStatusColumn() throws IOException {
        User owner = user(1L, "owner@example.com");
        ResearchJob job = job(10L, 1L);
        ResearchJobItem identifiedItem =
                item(100L, 10L, "OpenSSL", "3.0.1", null, ResearchJobItem.STATUS_IDENTIFIED);

        JobItemVulnerabilityView annotatedVuln = new JobItemVulnerabilityView(
                100L, "CVE-2024-1111", "nvd", "HIGH", "https://example.com/1", "nvd", null, "3.0.7", null, null,
                "SSA-1", "known_affected", "0:3.0.7-24.el9_2");
        JobItemVulnerabilityView plainVuln = new JobItemVulnerabilityView(
                100L, "CVE-2024-9999", "nvd", "LOW", "https://example.com/2", "nvd", null, null, null, null,
                null, null, null);

        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(owner));
        when(researchJobRepository.findById(10L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdOrderById(10L)).thenReturn(List.of(identifiedItem));
        when(identifiedProductRepository.findByJobItemIdIn(List.of(100L))).thenReturn(List.of());
        when(jobItemVulnerabilityRepository.findViewsByJobItemIdIn(List.of(100L)))
                .thenReturn(List.of(annotatedVuln, plainVuln));

        ResponseEntity<byte[]> response = newController().exportCsv(userDetails("owner@example.com"), 10L);

        List<CSVRecord> rows = parseCsv(response.getBody());
        assertThat(rows).hasSize(1);
        CSVRecord row = rows.get(0);
        // Existing vulnerability_count/vulnerabilities semantics are unchanged by this column.
        assertThat(row.get("vulnerability_count")).isEqualTo("2");
        assertThat(row.get("csaf_vendor_status")).isEqualTo("CVE-2024-1111: known_affected (SSA-1)");
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
