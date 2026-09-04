package com.vulncheck.app.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * {@link JobController#detail} rendered through the real {@code jobs/detail.html} Thymeleaf
 * template via {@code @WebMvcTest}+{@code MockMvc} (same infrastructure {@link
 * AdminControllerSecurityTest} already uses), rather than only asserting the model attributes as
 * {@link JobControllerTest} does. Closed-mode backlog item 251 (B4), senior-reviewer REVISE round
 * 4 on PR#170: three consecutive REVISE rounds on this exact template's cap-notice wording (UI
 * unreachable in round 1, factual errors in round 2, an unbalanced parenthesis plus an ambiguous
 * unit in round 3) all slipped through a green test suite precisely because nothing rendered the
 * template itself — {@link JobControllerTest} only ever checked that the right numbers reached the
 * model, never what the HTML actually said.
 */
@WebMvcTest(controllers = JobController.class)
class JobControllerDetailRenderingTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private ResearchJobService researchJobService;
    @MockBean
    private ResearchJobProcessingService researchJobProcessingService;
    @MockBean
    private ResearchJobRepository researchJobRepository;
    @MockBean
    private ResearchJobItemRepository researchJobItemRepository;
    @MockBean
    private IdentifiedProductRepository identifiedProductRepository;
    @MockBean
    private JobItemVulnerabilityRepository jobItemVulnerabilityRepository;
    @MockBean
    private UserRepository userRepository;
    @MockBean
    private CsvParsingService csvParsingService;
    @MockBean
    private PendingCsvUploadStore pendingCsvUploadStore;

    /** Same interface-projection fixture-builder shape as {@link JobControllerTest#cappedView}. */
    private JobItemVulnerabilityCappedView cappedView(Long jobItemId, String cveOrGhsaId, String severity,
            String url, String discoveredViaTier, String bundledComponentName, String bundledComponentVersion,
            long totalCount) {
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
                return "nvd";
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
                return null;
            }

            @Override
            public String getFixedVersion() {
                return null;
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
                return null;
            }

            @Override
            public String getCsafStatus() {
                return null;
            }

            @Override
            public String getCsafFixedVersion() {
                return null;
            }

            @Override
            public Long getTotalCount() {
                return totalCount;
            }
        };
    }

    /**
     * Both display categories (product findings and bundled-component findings) are capped for
     * this single item — product: 3 shown out of a true total of 2739; bundled: 2 shown (2
     * distinct components) out of a true total of 5 — so both cap notices in {@code
     * jobs/detail.html} render, and every one of this task's four wording/correctness assertions
     * can be checked against the real, rendered output in one pass.
     */
    @Test
    @WithMockUser(username = "owner@example.com")
    void detailPageRendersBothCapNoticesWithCorrectFiguresUnitsAndBalancedParentheses() throws Exception {
        User owner = new User();
        owner.setId(1L);
        owner.setEmail("owner@example.com");
        owner.setPasswordHash("hash");

        ResearchJob job = new ResearchJob();
        job.setId(10L);
        job.setUserId(1L);
        job.setCsvFilename("test.csv");
        job.setStatus(ResearchJob.STATUS_COMPLETED);

        ResearchJobItem item = new ResearchJobItem();
        item.setId(100L);
        item.setJobId(10L);
        item.setProductName("Google Chrome");
        item.setVersion("127.0.6533.100");
        item.setVendor("Google");
        item.setUsageText("used somewhere");
        item.setStatus(ResearchJobItem.STATUS_IDENTIFIED);

        // Product findings: 3 rows returned, true total 2739 -> 2736 hidden.
        JobItemVulnerabilityCappedView productVuln1 =
                cappedView(100L, "CVE-2024-0001", "CRITICAL", "https://example.com/1", "nvd", null, null, 2739L);
        JobItemVulnerabilityCappedView productVuln2 =
                cappedView(100L, "CVE-2024-0002", "CRITICAL", "https://example.com/2", "nvd", null, null, 2739L);
        JobItemVulnerabilityCappedView productVuln3 =
                cappedView(100L, "CVE-2024-0003", "HIGH", "https://example.com/3", "nvd", null, null, 2739L);
        // Bundled-component findings: 2 distinct components returned, true total 5 -> 3 hidden.
        JobItemVulnerabilityCappedView bundledVuln1 = cappedView(
                100L, "CVE-2026-11111", "CRITICAL", "https://example.com/4", "bundled_component", "7-Zip", "26.02", 5L);
        JobItemVulnerabilityCappedView bundledVuln2 = cappedView(
                100L, "CVE-2026-22222", "HIGH", "https://example.com/5", "bundled_component", "OpenSSL", "3.0.1", 5L);

        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(owner));
        when(researchJobRepository.findById(10L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdOrderById(10L)).thenReturn(List.of(item));
        when(identifiedProductRepository.findByJobItemIdIn(List.of(100L))).thenReturn(List.of());
        when(jobItemVulnerabilityRepository.findCappedViewsByJobItemIdIn(eq(List.of(100L)), anyInt()))
                .thenReturn(List.of(productVuln1, productVuln2, productVuln3, bundledVuln1, bundledVuln2));

        MvcResult result = mockMvc.perform(get("/jobs/10"))
                .andExpect(status().isOk())
                .andReturn();
        String body = result.getResponse().getContentAsString(StandardCharsets.UTF_8);

        // 1. The product notice states the true hidden count (2739 - 3 = 2736) and points to the
        //    vulnerability_count column for the true total.
        assertThat(body).contains("2736");
        assertThat(body).contains("vulnerability_count");

        // 2. No notice claims the full set is available via CSV export -- it's capped there too.
        assertThat(body).doesNotContain("全件はCSVエクスポート");

        // 3. The bundled-component notice itself (isolated from the product notice, which
        //    legitimately says "CVSS優先度順") states the ordering is by component name and never
        //    claims a severity/priority ordering it doesn't have.
        String bundledNotice = extractBundledNotice(body);
        assertThat(bundledNotice).contains("コンポーネント名順");
        assertThat(bundledNotice).doesNotContain("優先度");

        // 4. The rendered cap figures come from JobController's own constants, not literals that
        //    could silently drift from them.
        assertThat(bundledNotice).contains(String.valueOf(JobController.HTML_DETAIL_FINDING_CAP) + "件");
        assertThat(body).contains(String.valueOf(JobController.CSV_EXPORT_FINDING_CAP) + "件");

        // Regression guard for the round-3 bug itself: every full-width paren opened in the
        // bundled notice must be closed within it (round 3 shipped one unmatched trailing "）").
        assertThat(countOccurrences(bundledNotice, '（')).isEqualTo(countOccurrences(bundledNotice, '）'));
    }

    private String extractBundledNotice(String body) {
        int start = body.indexOf("同梱コンポーネントの脆弱性は");
        assertThat(start).as("bundled-component cap notice must be present in the rendered page").isNotEqualTo(-1);
        int end = body.indexOf("</div>", start);
        assertThat(end).as("bundled-component cap notice's containing <div> must close").isNotEqualTo(-1);
        return body.substring(start, end);
    }

    private long countOccurrences(String text, char target) {
        return text.chars().filter(c -> c == target).count();
    }
}
