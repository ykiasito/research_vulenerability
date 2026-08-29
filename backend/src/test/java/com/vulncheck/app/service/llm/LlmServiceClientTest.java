package com.vulncheck.app.service.llm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.vulncheck.app.entity.JobCostLedgerEntry;
import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.service.JobCostBudgetService;
import com.vulncheck.app.service.llm.LlmServiceModels.BundledChangelogResponse;
import com.vulncheck.app.service.llm.LlmServiceModels.BundledExtractResponse;
import com.vulncheck.app.service.llm.LlmServiceModels.CandidateDto;
import com.vulncheck.app.service.llm.LlmServiceModels.DisambiguateResponse;
import com.vulncheck.app.service.llm.LlmServiceModels.WebSearchIdentifyResponse;
import com.vulncheck.app.service.llm.LlmServiceModels.WebSearchResearchResponse;
import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

/**
 * Verifies two things every {@link LlmServiceClient} method must get right for {@link
 * JobCostBudgetService} reconciliation to reflect real spend (senior review REVISE item 8, part of
 * the 2026-08-29 cost-target correction pass): (1) it reconciles against the {@code CALL_SITE_*}
 * constant matching the endpoint it actually called, and (2) it passes the response's {@link
 * LlmServiceModels.UsageDto} token/web-search counts through to {@link JobCostBudgetService}
 * verbatim rather than re-deriving or dropping them.
 */
@ExtendWith(MockitoExtension.class)
class LlmServiceClientTest {

    private static final String BASE_URL = "http://llm-service-test";
    private static final String API_KEY = "sk-ant-test";
    private static final BigDecimal RESERVED_COST_USD = new BigDecimal("0.05");
    private static final BigDecimal ACTUAL_COST_USD = new BigDecimal("0.001234");

    @Mock
    private JobCostBudgetService jobCostBudgetService;

    private MockRestServiceServer server;
    private LlmServiceClient client;

    @BeforeEach
    void setUp() {
        // LlmServiceClient calls .uri("/v1/...") with relative paths (unlike e.g. NpmRegistryClient,
        // which embeds an absolute URL) — it relies on the RestClient's baseUrl, configured in
        // production by RestClientConfig#llmServiceRestClient from app.llm-service-url. A baseUrl
        // must be set here too so relative .uri(...) calls resolve instead of throwing.
        RestClient.Builder builder = RestClient.builder().baseUrl(BASE_URL);
        server = MockRestServiceServer.bindTo(builder).build();
        client = new LlmServiceClient(builder.build(), jobCostBudgetService);
    }

    private ResearchJobItem item() {
        ResearchJobItem item = new ResearchJobItem();
        item.setId(9L);
        item.setJobId(1L);
        item.setProductName("some-tool");
        item.setVersion("1.2.3");
        item.setUsageText("usage");
        return item;
    }

    @Test
    void disambiguatePassesCallSiteAndUsageThroughToReconcile() {
        when(jobCostBudgetService.computeActualCost(100, 50, 0)).thenReturn(ACTUAL_COST_USD);
        server.expect(requestTo(BASE_URL + "/v1/identify/disambiguate"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withSuccess(
                        "{\"matched\":true,\"selected_index\":1,\"confidence\":0.9,\"reasoning\":\"why\","
                                + "\"usage\":{\"input_tokens\":100,\"output_tokens\":50,\"web_search_requests\":0}}",
                        MediaType.APPLICATION_JSON));

        Optional<DisambiguateResponse> result = client.disambiguate(
                API_KEY, item(), List.of(new CandidateDto("npm", "some-tool", null, null, "registry")), RESERVED_COST_USD);

        assertThat(result).isPresent();
        assertThat(result.get().matched()).isTrue();
        server.verify();
        verify(jobCostBudgetService).reconcile(
                eq(1L), eq(9L), eq(JobCostLedgerEntry.CALL_SITE_TIER2),
                eq(RESERVED_COST_USD), eq(ACTUAL_COST_USD), eq(100), eq(50), eq(0));
    }

    @Test
    void webSearchIdentifyPassesCallSiteAndUsageThroughToReconcile() {
        when(jobCostBudgetService.computeActualCost(200, 80, 2)).thenReturn(ACTUAL_COST_USD);
        server.expect(requestTo(BASE_URL + "/v1/identify/web-search"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withSuccess(
                        "{\"found\":true,\"official_vendor\":\"Acme\",\"official_product_name\":\"Widget\","
                                + "\"reasoning\":\"r\",\"source_urls\":[],\"ecosystem_candidates\":[],\"platform_hint\":null,"
                                + "\"usage\":{\"input_tokens\":200,\"output_tokens\":80,\"web_search_requests\":2}}",
                        MediaType.APPLICATION_JSON));

        Optional<WebSearchIdentifyResponse> result =
                client.webSearchIdentify(API_KEY, item(), List.of("npm"), RESERVED_COST_USD);

        assertThat(result).isPresent();
        assertThat(result.get().found()).isTrue();
        server.verify();
        verify(jobCostBudgetService).reconcile(
                eq(1L), eq(9L), eq(JobCostLedgerEntry.CALL_SITE_TIER3),
                eq(RESERVED_COST_USD), eq(ACTUAL_COST_USD), eq(200), eq(80), eq(2));
    }

    @Test
    void webSearchResearchPassesCallSiteAndUsageThroughToReconcile() {
        when(jobCostBudgetService.computeActualCost(300, 120, 1)).thenReturn(ACTUAL_COST_USD);
        server.expect(requestTo(BASE_URL + "/v1/research/web-search"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withSuccess(
                        "{\"findings\":[],\"usage\":{\"input_tokens\":300,\"output_tokens\":120,\"web_search_requests\":1}}",
                        MediaType.APPLICATION_JSON));

        var findings = client.webSearchResearch(API_KEY, item(), "npm", "some-tool", RESERVED_COST_USD);

        assertThat(findings).isEmpty();
        server.verify();
        verify(jobCostBudgetService).reconcile(
                eq(1L), eq(9L), eq(JobCostLedgerEntry.CALL_SITE_STAGE4),
                eq(RESERVED_COST_USD), eq(ACTUAL_COST_USD), eq(300), eq(120), eq(1));
    }

    @Test
    void discoverBundledComponentChangelogPassesCallSiteAndUsageThroughToReconcile() {
        when(jobCostBudgetService.computeActualCost(150, 60, 1)).thenReturn(ACTUAL_COST_USD);
        server.expect(requestTo(BASE_URL + "/v1/bundled-components/discover-changelog"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withSuccess(
                        "{\"found\":true,\"changelog_text\":\"text\",\"source_urls\":[],"
                                + "\"usage\":{\"input_tokens\":150,\"output_tokens\":60,\"web_search_requests\":1}}",
                        MediaType.APPLICATION_JSON));

        Optional<BundledChangelogResponse> result =
                client.discoverBundledComponentChangelog(API_KEY, item(), RESERVED_COST_USD);

        assertThat(result).isPresent();
        assertThat(result.get().found()).isTrue();
        server.verify();
        verify(jobCostBudgetService).reconcileBundledComponent(
                eq(1L), eq(9L), eq(JobCostLedgerEntry.CALL_SITE_BUNDLED_CHANGELOG),
                eq(RESERVED_COST_USD), eq(ACTUAL_COST_USD), eq(150), eq(60), eq(1));
    }

    @Test
    void extractBundledComponentsPassesCallSiteAndUsageThroughToReconcile() {
        when(jobCostBudgetService.computeActualCost(90, 30, 0)).thenReturn(ACTUAL_COST_USD);
        server.expect(requestTo(BASE_URL + "/v1/bundled-components/extract"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withSuccess(
                        "{\"bundled_components\":[],\"usage\":{\"input_tokens\":90,\"output_tokens\":30,\"web_search_requests\":0}}",
                        MediaType.APPLICATION_JSON));

        Optional<BundledExtractResponse> result =
                client.extractBundledComponents(API_KEY, item(), "changelog text", RESERVED_COST_USD);

        assertThat(result).isPresent();
        server.verify();
        verify(jobCostBudgetService).reconcileBundledComponent(
                eq(1L), eq(9L), eq(JobCostLedgerEntry.CALL_SITE_BUNDLED_EXTRACT),
                eq(RESERVED_COST_USD), eq(ACTUAL_COST_USD), eq(90), eq(30), eq(0));
    }

    @Test
    void failedCallReconcilesWithZeroCostAndNullUsageBreakdown() {
        server.expect(requestTo(BASE_URL + "/v1/identify/disambiguate"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withServerError());

        Optional<DisambiguateResponse> result = client.disambiguate(
                API_KEY, item(), List.of(new CandidateDto("npm", "some-tool", null, null, "registry")), RESERVED_COST_USD);

        assertThat(result).isEmpty();
        server.verify();
        verify(jobCostBudgetService).reconcile(
                eq(1L), eq(9L), eq(JobCostLedgerEntry.CALL_SITE_TIER2),
                eq(RESERVED_COST_USD), eq(BigDecimal.ZERO), isNull(), isNull(), isNull());
    }
}
