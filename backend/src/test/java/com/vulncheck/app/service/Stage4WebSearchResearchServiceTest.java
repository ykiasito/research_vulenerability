package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.repository.JobItemVulnerabilityRepository;
import com.vulncheck.app.repository.VulnerabilityRepository;
import com.vulncheck.app.service.llm.LlmServiceClient;
import com.vulncheck.app.service.llm.LlmServiceModels.WebSearchVulnFindingDto;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class Stage4WebSearchResearchServiceTest {

    private static final Long USER_ID = 7L;

    @Mock
    private UserApiKeyService userApiKeyService;

    @Mock
    private LlmServiceClient llmServiceClient;

    @Mock
    private VulnerabilityRepository vulnerabilityRepository;

    @Mock
    private JobItemVulnerabilityRepository jobItemVulnerabilityRepository;

    @Mock
    private JobCostBudgetService jobCostBudgetService;

    @BeforeEach
    void allowAiSpendByDefault() {
        lenient().when(jobCostBudgetService.tryReserve(any(), any())).thenReturn(true);
    }

    private Stage4WebSearchResearchService service() {
        return new Stage4WebSearchResearchService(
                userApiKeyService, llmServiceClient, vulnerabilityRepository, jobItemVulnerabilityRepository, jobCostBudgetService);
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
    void skipsEntirelyWithoutAClaudeApiKey() {
        when(userApiKeyService.getClaudeApiKey(USER_ID)).thenReturn(Optional.empty());

        Stage4WebSearchResearchService.Stage4ResearchResult result = service().research(item(), "npm", "some-tool", USER_ID);

        assertThat(result.persistedCount()).isZero();
        assertThat(result.incompleteReason()).isEqualTo(ResearchJobItem.INCOMPLETE_REASON_AI_NOT_AVAILABLE);
        verifyNoInteractions(llmServiceClient, vulnerabilityRepository, jobItemVulnerabilityRepository);
    }

    @Test
    void skipsWhenJobCostBudgetIsExhausted() {
        when(userApiKeyService.getClaudeApiKey(USER_ID)).thenReturn(Optional.of("sk-ant-test"));
        when(jobCostBudgetService.tryReserve(any(), any())).thenReturn(false);

        Stage4WebSearchResearchService.Stage4ResearchResult result = service().research(item(), "npm", "some-tool", USER_ID);

        assertThat(result.persistedCount()).isZero();
        assertThat(result.incompleteReason()).isEqualTo(ResearchJobItem.INCOMPLETE_REASON_BUDGET_EXHAUSTED);
        verifyNoInteractions(llmServiceClient, vulnerabilityRepository, jobItemVulnerabilityRepository);
    }

    @Test
    void bareCveIdIsUsedDirectlyButFreeTextIsScopedToTheProduct() {
        when(userApiKeyService.getClaudeApiKey(USER_ID)).thenReturn(Optional.of("sk-ant-test"));
        when(llmServiceClient.webSearchResearch(eq("sk-ant-test"), any(), eq("npm"), eq("some-tool"), any()))
                .thenReturn(Optional.of(List.of(
                        new WebSearchVulnFindingDto("CVE-2024-12345", "HIGH", "desc", "https://example.com/a", null),
                        new WebSearchVulnFindingDto("Unpatched RCE in admin panel", "MEDIUM", "desc2", "https://example.com/b", null))));
        when(vulnerabilityRepository.insertIfAbsentAndGetId(anyString(), anyString(), any(), any(), any(), any())).thenReturn(500L);

        Stage4WebSearchResearchService.Stage4ResearchResult result = service().research(item(), "npm", "some-tool", USER_ID);

        assertThat(result.persistedCount()).isEqualTo(2);
        assertThat(result.incompleteReason()).isNull();
        verify(vulnerabilityRepository).insertIfAbsentAndGetId(
                eq("CVE-2024-12345"), eq("llm_web_search"), eq("HIGH"), eq("desc"), eq("https://example.com/a"), any());
        verify(vulnerabilityRepository).insertIfAbsentAndGetId(
                eq("llm:some-tool:Unpatched RCE in admin panel"), eq("llm_web_search"), eq("MEDIUM"), eq("desc2"), eq("https://example.com/b"), any());
        verify(jobItemVulnerabilityRepository, times(2)).linkIfAbsent(eq(9L), eq(500L), eq("llm_web_search"), any());
    }

    @Test
    void blankIdentifiersAreSkipped() {
        when(userApiKeyService.getClaudeApiKey(USER_ID)).thenReturn(Optional.of("sk-ant-test"));
        when(llmServiceClient.webSearchResearch(eq("sk-ant-test"), any(), any(), any(), any()))
                .thenReturn(Optional.of(List.of(new WebSearchVulnFindingDto("  ", null, "desc", "https://example.com", null))));

        Stage4WebSearchResearchService.Stage4ResearchResult result = service().research(item(), "npm", "some-tool", USER_ID);

        assertThat(result.persistedCount()).isEqualTo(1);
        assertThat(result.incompleteReason()).isNull();
        verify(vulnerabilityRepository, never()).insertIfAbsentAndGetId(anyString(), anyString(), any(), any(), any(), any());
        verify(jobItemVulnerabilityRepository, never()).linkIfAbsent(any(), any(), anyString(), any());
    }

    // --- PR #68 item 121 REVISE (senior review 2026-09-01): LlmServiceClient#webSearchResearch's
    // Optional.empty()/Optional.of(...) contract must be handled correctly, not conflated ------------

    @Test
    void marksAiCallFailedWhenTheClientReportsTheCallItselfFailed() {
        // The gap this asserts against: before this fix, LlmServiceClient#webSearchResearch swallowed
        // RestClientException/RuntimeException internally and returned an empty List either way, so
        // this service could never distinguish "LLM service call failed" from "call succeeded, found
        // nothing" -- the exact case ResearchJobProcessingService's stage4Threw flag was meant to
        // catch, but never fired for.
        when(userApiKeyService.getClaudeApiKey(USER_ID)).thenReturn(Optional.of("sk-ant-test"));
        when(llmServiceClient.webSearchResearch(eq("sk-ant-test"), any(), eq("npm"), eq("some-tool"), any()))
                .thenReturn(Optional.empty());

        Stage4WebSearchResearchService.Stage4ResearchResult result = service().research(item(), "npm", "some-tool", USER_ID);

        assertThat(result.persistedCount()).isZero();
        assertThat(result.incompleteReason()).isEqualTo(ResearchJobItem.INCOMPLETE_REASON_AI_CALL_FAILED);
        verifyNoInteractions(vulnerabilityRepository, jobItemVulnerabilityRepository);
    }

    @Test
    void aGenuinelyEmptyFindingsListIsNotTreatedAsACallFailure() {
        // Regression guard for the opposite mistake: a call that completed successfully but found
        // nothing (Optional.of(List.of())) must still be a real "checked, clean" all-clear, not get
        // reclassified as AI_CALL_FAILED.
        when(userApiKeyService.getClaudeApiKey(USER_ID)).thenReturn(Optional.of("sk-ant-test"));
        when(llmServiceClient.webSearchResearch(eq("sk-ant-test"), any(), eq("npm"), eq("some-tool"), any()))
                .thenReturn(Optional.of(List.of()));

        Stage4WebSearchResearchService.Stage4ResearchResult result = service().research(item(), "npm", "some-tool", USER_ID);

        assertThat(result.persistedCount()).isZero();
        assertThat(result.incompleteReason()).isNull();
        verifyNoInteractions(vulnerabilityRepository, jobItemVulnerabilityRepository);
    }

    // --- Task-backlog item 104: citation_url scheme allowlist ---------------------------------------

    @Test
    void dangerousCitationUrlSchemeIsDroppedToNullBeforePersisting() {
        when(userApiKeyService.getClaudeApiKey(USER_ID)).thenReturn(Optional.of("sk-ant-test"));
        when(llmServiceClient.webSearchResearch(eq("sk-ant-test"), any(), eq("npm"), eq("some-tool"), any()))
                .thenReturn(Optional.of(List.of(
                        new WebSearchVulnFindingDto("CVE-2024-77777", "HIGH", "desc", "javascript:alert(document.cookie)", null))));
        when(vulnerabilityRepository.insertIfAbsentAndGetId(anyString(), anyString(), any(), any(), any(), any())).thenReturn(600L);

        Stage4WebSearchResearchService.Stage4ResearchResult result = service().research(item(), "npm", "some-tool", USER_ID);

        assertThat(result.persistedCount()).isEqualTo(1);
        verify(vulnerabilityRepository).insertIfAbsentAndGetId(
                eq("CVE-2024-77777"), eq("llm_web_search"), eq("HIGH"), eq("desc"), eq((String) null), any());
        verify(jobItemVulnerabilityRepository).linkIfAbsent(eq(9L), eq(600L), eq("llm_web_search"), eq((String) null));
    }

    @Test
    void httpAndHttpsCitationUrlsPassThroughUnchanged() {
        when(userApiKeyService.getClaudeApiKey(USER_ID)).thenReturn(Optional.of("sk-ant-test"));
        when(llmServiceClient.webSearchResearch(eq("sk-ant-test"), any(), eq("npm"), eq("some-tool"), any()))
                .thenReturn(Optional.of(List.of(
                        new WebSearchVulnFindingDto("CVE-2024-88888", "LOW", "desc", "http://example.com/advisory", null))));
        when(vulnerabilityRepository.insertIfAbsentAndGetId(anyString(), anyString(), any(), any(), any(), any())).thenReturn(601L);

        service().research(item(), "npm", "some-tool", USER_ID);

        verify(vulnerabilityRepository).insertIfAbsentAndGetId(
                eq("CVE-2024-88888"), eq("llm_web_search"), eq("LOW"), eq("desc"), eq("http://example.com/advisory"), any());
    }

    @Test
    void usesPlatformHintScopeWhenNoEcosystemIsAvailable() {
        when(userApiKeyService.getClaudeApiKey(USER_ID)).thenReturn(Optional.of("sk-ant-test"));
        when(llmServiceClient.webSearchResearch(eq("sk-ant-test"), any(), eq("VS Code Marketplace"), eq("ms-python.python"), any()))
                .thenReturn(Optional.of(List.of(new WebSearchVulnFindingDto("CVE-2024-99999", "HIGH", "desc", "https://example.com", null))));
        when(vulnerabilityRepository.insertIfAbsentAndGetId(anyString(), anyString(), any(), any(), any(), any())).thenReturn(501L);

        Stage4WebSearchResearchService.Stage4ResearchResult result =
                service().research(item(), "VS Code Marketplace", "ms-python.python", USER_ID);

        assertThat(result.persistedCount()).isEqualTo(1);
        assertThat(result.incompleteReason()).isNull();
        verify(vulnerabilityRepository).insertIfAbsentAndGetId(
                eq("CVE-2024-99999"), eq("llm_web_search"), eq("HIGH"), eq("desc"), eq("https://example.com"), any());
        verify(jobItemVulnerabilityRepository).linkIfAbsent(eq(9L), eq(501L), eq("llm_web_search"), eq("https://example.com"));
    }
}
