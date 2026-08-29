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

        int count = service().research(item(), "npm", "some-tool", USER_ID);

        assertThat(count).isZero();
        verifyNoInteractions(llmServiceClient, vulnerabilityRepository, jobItemVulnerabilityRepository);
    }

    @Test
    void skipsWhenJobCostBudgetIsExhausted() {
        when(userApiKeyService.getClaudeApiKey(USER_ID)).thenReturn(Optional.of("sk-ant-test"));
        when(jobCostBudgetService.tryReserve(any(), any())).thenReturn(false);

        int count = service().research(item(), "npm", "some-tool", USER_ID);

        assertThat(count).isZero();
        verifyNoInteractions(llmServiceClient, vulnerabilityRepository, jobItemVulnerabilityRepository);
    }

    @Test
    void bareCveIdIsUsedDirectlyButFreeTextIsScopedToTheProduct() {
        when(userApiKeyService.getClaudeApiKey(USER_ID)).thenReturn(Optional.of("sk-ant-test"));
        when(llmServiceClient.webSearchResearch(eq("sk-ant-test"), any(), eq("npm"), eq("some-tool"), any()))
                .thenReturn(List.of(
                        new WebSearchVulnFindingDto("CVE-2024-12345", "HIGH", "desc", "https://example.com/a", null),
                        new WebSearchVulnFindingDto("Unpatched RCE in admin panel", "MEDIUM", "desc2", "https://example.com/b", null)));
        when(vulnerabilityRepository.insertIfAbsentAndGetId(anyString(), anyString(), any(), any(), any(), any())).thenReturn(500L);

        int count = service().research(item(), "npm", "some-tool", USER_ID);

        assertThat(count).isEqualTo(2);
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
                .thenReturn(List.of(new WebSearchVulnFindingDto("  ", null, "desc", "https://example.com", null)));

        int count = service().research(item(), "npm", "some-tool", USER_ID);

        assertThat(count).isEqualTo(1);
        verify(vulnerabilityRepository, never()).insertIfAbsentAndGetId(anyString(), anyString(), any(), any(), any(), any());
        verify(jobItemVulnerabilityRepository, never()).linkIfAbsent(any(), any(), anyString(), any());
    }

    @Test
    void usesPlatformHintScopeWhenNoEcosystemIsAvailable() {
        when(userApiKeyService.getClaudeApiKey(USER_ID)).thenReturn(Optional.of("sk-ant-test"));
        when(llmServiceClient.webSearchResearch(eq("sk-ant-test"), any(), eq("VS Code Marketplace"), eq("ms-python.python"), any()))
                .thenReturn(List.of(new WebSearchVulnFindingDto("CVE-2024-99999", "HIGH", "desc", "https://example.com", null)));
        when(vulnerabilityRepository.insertIfAbsentAndGetId(anyString(), anyString(), any(), any(), any(), any())).thenReturn(501L);

        int count = service().research(item(), "VS Code Marketplace", "ms-python.python", USER_ID);

        assertThat(count).isEqualTo(1);
        verify(vulnerabilityRepository).insertIfAbsentAndGetId(
                eq("CVE-2024-99999"), eq("llm_web_search"), eq("HIGH"), eq("desc"), eq("https://example.com"), any());
        verify(jobItemVulnerabilityRepository).linkIfAbsent(eq(9L), eq(501L), eq("llm_web_search"), eq("https://example.com"));
    }
}
