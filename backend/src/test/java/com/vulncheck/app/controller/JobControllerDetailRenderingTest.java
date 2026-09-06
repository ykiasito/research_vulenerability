package com.vulncheck.app.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
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
import com.vulncheck.app.service.MirrorFreshnessService;
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
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
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
    // Closed-mode backlog item 382: JobController#detail now unconditionally calls
    // MirrorFreshnessService#staleMirrorWarnings() -- left unstubbed deliberately, since Mockito's
    // default answer already returns an empty List for an unstubbed List-returning method, which is
    // exactly "no mirror freshness warnings" (irrelevant to every assertion in this class).
    @MockBean
    private MirrorFreshnessService mirrorFreshnessService;

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
        when(researchJobItemRepository.findByJobIdOrderById(eq(10L), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(item)));
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

        // 5. Task-backlog item 269: the notice's own unit wording ("表示中のfinding N件、未表示の
        //    finding N件") must actually appear with the right figures attached to the right label
        //    -- 2 shown, 3 hidden (5 true total - 2 returned), not just the bare numbers checked
        //    elsewhere in this test, which wouldn't catch the labels themselves silently drifting
        //    or getting swapped.
        assertThat(bundledNotice).contains("表示中のfinding 2件、未表示のfinding 3件");

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

    // --- closed-mode backlog item 267: JobController#detail's HTML item-list pagination, rendered
    // through the real template rather than just asserted at the model-attribute level (same
    // rationale as this class's own javadoc: previous rounds' bugs in this exact template only
    // ever surfaced once something actually rendered it) ------------------------------------------

    @Test
    @WithMockUser(username = "owner@example.com")
    void detailPageTwoRendersOnlyThatPagesItemWithPreviousAndNextLinks() throws Exception {
        User owner = new User();
        owner.setId(1L);
        owner.setEmail("owner@example.com");
        owner.setPasswordHash("hash");

        ResearchJob job = new ResearchJob();
        job.setId(10L);
        job.setUserId(1L);
        job.setCsvFilename("test.csv");
        job.setStatus(ResearchJob.STATUS_COMPLETED);

        ResearchJobItem itemOnPage2 = new ResearchJobItem();
        itemOnPage2.setId(200L);
        itemOnPage2.setJobId(10L);
        itemOnPage2.setProductName("express");
        itemOnPage2.setVersion("4.18.0");
        itemOnPage2.setUsageText("used somewhere");
        itemOnPage2.setStatus(ResearchJobItem.STATUS_IDENTIFIED);

        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(owner));
        when(researchJobRepository.findById(10L)).thenReturn(Optional.of(job));
        // 120 items total at ITEMS_PAGE_SIZE=50 -> 3 pages; requesting page=1 (0-based, the middle
        // page) must show both a previous and a next link.
        when(researchJobItemRepository.findByJobIdOrderById(eq(10L), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(itemOnPage2), PageRequest.of(1, JobController.ITEMS_PAGE_SIZE), 120));
        when(identifiedProductRepository.findByJobItemIdIn(List.of(200L))).thenReturn(List.of());
        when(jobItemVulnerabilityRepository.findCappedViewsByJobItemIdIn(eq(List.of(200L)), anyInt()))
                .thenReturn(List.of());

        MvcResult result = mockMvc.perform(get("/jobs/10").param("page", "1"))
                .andExpect(status().isOk())
                .andReturn();
        String body = result.getResponse().getContentAsString(StandardCharsets.UTF_8);

        assertThat(body).contains("express");
        assertThat(body).contains("2 / 3");
        assertThat(body).contains("全120件");
        assertThat(body).contains("← 前のページ");
        assertThat(body).contains("次のページ →");
        assertThat(body).contains("page=0");
        assertThat(body).contains("page=2");
    }

    @Test
    @WithMockUser(username = "owner@example.com")
    void detailLastPageOmitsTheNextLinkAndFirstPageOmitsThePreviousLink() throws Exception {
        User owner = new User();
        owner.setId(1L);
        owner.setEmail("owner@example.com");
        owner.setPasswordHash("hash");

        ResearchJob job = new ResearchJob();
        job.setId(10L);
        job.setUserId(1L);
        job.setCsvFilename("test.csv");
        job.setStatus(ResearchJob.STATUS_COMPLETED);

        ResearchJobItem lastItem = new ResearchJobItem();
        lastItem.setId(300L);
        lastItem.setJobId(10L);
        lastItem.setProductName("tail-item");
        lastItem.setVersion("1.0.0");
        lastItem.setUsageText("used somewhere");
        lastItem.setStatus(ResearchJobItem.STATUS_IDENTIFIED);

        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(owner));
        when(researchJobRepository.findById(10L)).thenReturn(Optional.of(job));
        // 120 items, page 2 (0-based) is the last of 3 pages (20 items) -- must show a previous
        // link but no next link.
        when(researchJobItemRepository.findByJobIdOrderById(eq(10L), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(lastItem), PageRequest.of(2, JobController.ITEMS_PAGE_SIZE), 120));
        when(identifiedProductRepository.findByJobItemIdIn(List.of(300L))).thenReturn(List.of());
        when(jobItemVulnerabilityRepository.findCappedViewsByJobItemIdIn(eq(List.of(300L)), anyInt()))
                .thenReturn(List.of());

        MvcResult result = mockMvc.perform(get("/jobs/10").param("page", "2"))
                .andExpect(status().isOk())
                .andReturn();
        String body = result.getResponse().getContentAsString(StandardCharsets.UTF_8);

        assertThat(body).contains("3 / 3");
        assertThat(body).contains("← 前のページ");
        assertThat(body).doesNotContain("次のページ →");
    }

    // --- closed-mode backlog item 275: abbreviated page-number links ("1 2 3 … 20"), boundary
    // cases -- a 20-page job (1,000 items at ITEMS_PAGE_SIZE=50) is exactly the scenario that
    // motivated this feature (prev/next-only pagination needed up to 19 clicks to reach the end) --

    private ResearchJob multiPageJob() {
        ResearchJob job = new ResearchJob();
        job.setId(10L);
        job.setUserId(1L);
        job.setCsvFilename("test.csv");
        job.setStatus(ResearchJob.STATUS_COMPLETED);
        return job;
    }

    private ResearchJobItem oneItem(Long id) {
        ResearchJobItem item = new ResearchJobItem();
        item.setId(id);
        item.setJobId(10L);
        item.setProductName("item-" + id);
        item.setVersion("1.0.0");
        item.setUsageText("used somewhere");
        item.setStatus(ResearchJobItem.STATUS_IDENTIFIED);
        return item;
    }

    @Test
    @WithMockUser(username = "owner@example.com")
    void detailFirstPageOfA20PageJobShowsTheHeadAndAnEllipsisBeforeTheLastPage() throws Exception {
        User owner = new User();
        owner.setId(1L);
        owner.setEmail("owner@example.com");
        owner.setPasswordHash("hash");
        ResearchJob job = multiPageJob();
        ResearchJobItem firstItem = oneItem(400L);

        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(owner));
        when(researchJobRepository.findById(10L)).thenReturn(Optional.of(job));
        // 1,000 items at ITEMS_PAGE_SIZE=50 -> exactly 20 pages.
        when(researchJobItemRepository.findByJobIdOrderById(eq(10L), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(firstItem), PageRequest.of(0, JobController.ITEMS_PAGE_SIZE), 1000));
        when(identifiedProductRepository.findByJobItemIdIn(List.of(400L))).thenReturn(List.of());
        when(jobItemVulnerabilityRepository.findCappedViewsByJobItemIdIn(eq(List.of(400L)), anyInt()))
                .thenReturn(List.of());

        MvcResult result = mockMvc.perform(get("/jobs/10"))
                .andExpect(status().isOk())
                .andReturn();
        String body = result.getResponse().getContentAsString(StandardCharsets.UTF_8);

        // Page 1 (the current page) is not itself a link.
        assertThat(body).contains("<strong>1</strong>");
        // 2 and 3 stay spelled out, then a gap, then the always-present last page (20).
        assertThat(body).contains("…");
        assertThat(body).contains("page=19\"");
        // No link ever points back to page 1 itself.
        assertThat(body).doesNotContain("page=0\"");
    }

    @Test
    @WithMockUser(username = "owner@example.com")
    void detailLastPageOfA20PageJobShowsAnEllipsisAfterTheFirstPageThenTheTail() throws Exception {
        User owner = new User();
        owner.setId(1L);
        owner.setEmail("owner@example.com");
        owner.setPasswordHash("hash");
        ResearchJob job = multiPageJob();
        ResearchJobItem lastItem = oneItem(419L);

        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(owner));
        when(researchJobRepository.findById(10L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdOrderById(eq(10L), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(lastItem), PageRequest.of(19, JobController.ITEMS_PAGE_SIZE), 1000));
        when(identifiedProductRepository.findByJobItemIdIn(List.of(419L))).thenReturn(List.of());
        when(jobItemVulnerabilityRepository.findCappedViewsByJobItemIdIn(eq(List.of(419L)), anyInt()))
                .thenReturn(List.of());

        MvcResult result = mockMvc.perform(get("/jobs/10").param("page", "19"))
                .andExpect(status().isOk())
                .andReturn();
        String body = result.getResponse().getContentAsString(StandardCharsets.UTF_8);

        assertThat(body).contains("20 / 20");
        // Page 20 (the current page) is not itself a link; page 1 is always still a link.
        assertThat(body).contains("<strong>20</strong>");
        assertThat(body).contains("…");
        assertThat(body).contains(">1<");
        // No link ever points back to page 20 itself.
        assertThat(body).doesNotContain("page=19\"");
    }

    @Test
    @WithMockUser(username = "owner@example.com")
    void detailMiddlePageOfA20PageJobShowsAnEllipsisOnBothSidesOfTheCurrentPageWindow() throws Exception {
        User owner = new User();
        owner.setId(1L);
        owner.setEmail("owner@example.com");
        owner.setPasswordHash("hash");
        ResearchJob job = multiPageJob();
        ResearchJobItem middleItem = oneItem(410L);

        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(owner));
        when(researchJobRepository.findById(10L)).thenReturn(Optional.of(job));
        // 0-based page 9 -> 1-based page 10, dead center of a 20-page job.
        when(researchJobItemRepository.findByJobIdOrderById(eq(10L), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(middleItem), PageRequest.of(9, JobController.ITEMS_PAGE_SIZE), 1000));
        when(identifiedProductRepository.findByJobItemIdIn(List.of(410L))).thenReturn(List.of());
        when(jobItemVulnerabilityRepository.findCappedViewsByJobItemIdIn(eq(List.of(410L)), anyInt()))
                .thenReturn(List.of());

        MvcResult result = mockMvc.perform(get("/jobs/10").param("page", "9"))
                .andExpect(status().isOk())
                .andReturn();
        String body = result.getResponse().getContentAsString(StandardCharsets.UTF_8);

        assertThat(body).contains("10 / 20");
        // Current page (10) is not a link; the window (8,9,11,12) and both endpoints (1, 20) are.
        assertThat(body).contains("<strong>10</strong>");
        assertThat(body).contains("page=7\""); // page 8
        assertThat(body).contains("page=8\""); // page 9
        assertThat(body).contains("page=10\""); // page 11
        assertThat(body).contains("page=11\""); // page 12
        assertThat(body).contains(">1<"); // page 1 link text
        assertThat(body).contains("page=19\""); // page 20 link
        // Both gaps (before page 8, and after page 12) must render.
        assertThat(countOccurrences(body, '…')).isGreaterThanOrEqualTo(2);
    }
}
