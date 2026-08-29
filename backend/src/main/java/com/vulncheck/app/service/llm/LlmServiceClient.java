package com.vulncheck.app.service.llm;

import com.vulncheck.app.entity.JobCostLedgerEntry;
import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.service.JobCostBudgetService;
import com.vulncheck.app.service.llm.LlmServiceModels.BundledChangelogRequest;
import com.vulncheck.app.service.llm.LlmServiceModels.BundledChangelogResponse;
import com.vulncheck.app.service.llm.LlmServiceModels.BundledExtractRequest;
import com.vulncheck.app.service.llm.LlmServiceModels.BundledExtractResponse;
import com.vulncheck.app.service.llm.LlmServiceModels.CandidateDto;
import com.vulncheck.app.service.llm.LlmServiceModels.DisambiguateRequest;
import com.vulncheck.app.service.llm.LlmServiceModels.DisambiguateResponse;
import com.vulncheck.app.service.llm.LlmServiceModels.UsageDto;
import com.vulncheck.app.service.llm.LlmServiceModels.WebSearchIdentifyRequest;
import com.vulncheck.app.service.llm.LlmServiceModels.WebSearchIdentifyResponse;
import com.vulncheck.app.service.llm.LlmServiceModels.WebSearchResearchRequest;
import com.vulncheck.app.service.llm.LlmServiceModels.WebSearchResearchResponse;
import com.vulncheck.app.service.llm.LlmServiceModels.WebSearchVulnFindingDto;
import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * Client for the Python LLM microservice (Stage1 Tier2/Tier3 identification, Stage4 vulnerability
 * research). Every call is best-effort: on any failure (network, invalid/expired user API key,
 * Claude API error) it logs and returns empty — an LLM tier being unavailable must degrade the
 * pipeline gracefully, never fail the whole job, matching every other tier in this app.
 *
 * <p>Every method also reconciles the caller's {@link JobCostBudgetService} reservation against
 * real usage once the call resolves — the reservation made before the call (a conservative
 * worst-case estimate, since actual cost isn't known until Claude responds) is replaced by the
 * real cost computed from the response's {@link UsageDto} on success, or fully refunded (actual
 * cost $0) on failure, since a failed call never produced a billable, parsed response.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class LlmServiceClient {

    private final RestClient llmServiceRestClient;
    private final JobCostBudgetService jobCostBudgetService;

    public Optional<DisambiguateResponse> disambiguate(
            String apiKey, ResearchJobItem item, List<CandidateDto> candidates, BigDecimal reservedCostUsd) {
        DisambiguateRequest request = new DisambiguateRequest(
                apiKey, item.getProductName(), item.getVersion(), item.getVendor(), item.getUsageText(), candidates);
        UsageDto usage = null;
        try {
            DisambiguateResponse response = llmServiceRestClient.post()
                    .uri("/v1/identify/disambiguate")
                    .body(request)
                    .retrieve()
                    .body(DisambiguateResponse.class);
            usage = response == null ? null : response.usage();
            return Optional.ofNullable(response);
        } catch (RestClientException e) {
            log.warn("LLM disambiguate call failed for item {}", item.getId(), e);
            return Optional.empty();
        } catch (RuntimeException e) {
            log.error("LLM disambiguate call failed unexpectedly for item {}", item.getId(), e);
            return Optional.empty();
        } finally {
            reconcile(item, JobCostLedgerEntry.CALL_SITE_TIER2, reservedCostUsd, usage);
        }
    }

    public Optional<WebSearchIdentifyResponse> webSearchIdentify(
            String apiKey, ResearchJobItem item, List<String> enabledEcosystems, BigDecimal reservedCostUsd) {
        WebSearchIdentifyRequest request = new WebSearchIdentifyRequest(
                apiKey, item.getProductName(), item.getVersion(), item.getVendor(), item.getUsageText(), enabledEcosystems);
        UsageDto usage = null;
        try {
            WebSearchIdentifyResponse response = llmServiceRestClient.post()
                    .uri("/v1/identify/web-search")
                    .body(request)
                    .retrieve()
                    .body(WebSearchIdentifyResponse.class);
            usage = response == null ? null : response.usage();
            return Optional.ofNullable(response);
        } catch (RestClientException e) {
            log.warn("LLM web-search identify call failed for item {}", item.getId(), e);
            return Optional.empty();
        } catch (RuntimeException e) {
            log.error("LLM web-search identify call failed unexpectedly for item {}", item.getId(), e);
            return Optional.empty();
        } finally {
            reconcile(item, JobCostLedgerEntry.CALL_SITE_TIER3, reservedCostUsd, usage);
        }
    }

    public List<WebSearchVulnFindingDto> webSearchResearch(
            String apiKey, ResearchJobItem item, String ecosystem, String packageName, BigDecimal reservedCostUsd) {
        WebSearchResearchRequest request = new WebSearchResearchRequest(
                apiKey, item.getProductName(), item.getVersion(), item.getVendor(), ecosystem, packageName);
        UsageDto usage = null;
        try {
            WebSearchResearchResponse response = llmServiceRestClient.post()
                    .uri("/v1/research/web-search")
                    .body(request)
                    .retrieve()
                    .body(WebSearchResearchResponse.class);
            usage = response == null ? null : response.usage();
            return response != null && response.findings() != null ? response.findings() : List.of();
        } catch (RestClientException e) {
            log.warn("LLM web-search research call failed for item {}", item.getId(), e);
            return List.of();
        } catch (RuntimeException e) {
            log.error("LLM web-search research call failed unexpectedly for item {}", item.getId(), e);
            return List.of();
        } finally {
            reconcile(item, JobCostLedgerEntry.CALL_SITE_STAGE4, reservedCostUsd, usage);
        }
    }

    /**
     * Bundled-package (formerly "Stage 3.5") detection, step 1: web_search-based changelog/
     * release-note discovery (Stage4-shaped — see the plan's §2/§3-2). Reconciles against the
     * separate {@link JobCostBudgetService#reconcileBundledComponent} ledger, not {@link
     * #reconcile}'s always-on one — this whole feature must never draw down the budget other jobs
     * rely on.
     */
    public Optional<BundledChangelogResponse> discoverBundledComponentChangelog(
            String apiKey, ResearchJobItem item, BigDecimal reservedCostUsd) {
        BundledChangelogRequest request = new BundledChangelogRequest(apiKey, item.getProductName(), item.getVersion(), item.getVendor());
        UsageDto usage = null;
        try {
            BundledChangelogResponse response = llmServiceRestClient.post()
                    .uri("/v1/bundled-components/discover-changelog")
                    .body(request)
                    .retrieve()
                    .body(BundledChangelogResponse.class);
            usage = response == null ? null : response.usage();
            return Optional.ofNullable(response);
        } catch (RestClientException e) {
            log.warn("LLM bundled-component changelog discovery call failed for item {}", item.getId(), e);
            return Optional.empty();
        } catch (RuntimeException e) {
            log.error("LLM bundled-component changelog discovery call failed unexpectedly for item {}", item.getId(), e);
            return Optional.empty();
        } finally {
            reconcileBundled(item, JobCostLedgerEntry.CALL_SITE_BUNDLED_CHANGELOG, reservedCostUsd, usage);
        }
    }

    /**
     * Bundled-package detection, step 2: text-only {@code (component, version)} extraction from
     * the changelog text step 1 found — no web_search tool attached (see the plan's §3-2), which is
     * exactly why this is a separate, cheaper call from step 1 rather than one combined request.
     */
    public Optional<BundledExtractResponse> extractBundledComponents(
            String apiKey, ResearchJobItem item, String changelogText, BigDecimal reservedCostUsd) {
        BundledExtractRequest request = new BundledExtractRequest(apiKey, item.getProductName(), item.getVersion(), changelogText);
        UsageDto usage = null;
        try {
            BundledExtractResponse response = llmServiceRestClient.post()
                    .uri("/v1/bundled-components/extract")
                    .body(request)
                    .retrieve()
                    .body(BundledExtractResponse.class);
            usage = response == null ? null : response.usage();
            return Optional.ofNullable(response);
        } catch (RestClientException e) {
            log.warn("LLM bundled-component extraction call failed for item {}", item.getId(), e);
            return Optional.empty();
        } catch (RuntimeException e) {
            log.error("LLM bundled-component extraction call failed unexpectedly for item {}", item.getId(), e);
            return Optional.empty();
        } finally {
            reconcileBundled(item, JobCostLedgerEntry.CALL_SITE_BUNDLED_EXTRACT, reservedCostUsd, usage);
        }
    }

    private void reconcile(ResearchJobItem item, String callSite, BigDecimal reservedCostUsd, UsageDto usage) {
        BigDecimal actualCostUsd = usage == null
                ? BigDecimal.ZERO
                : jobCostBudgetService.computeActualCost(usage.inputTokens(), usage.outputTokens(), usage.webSearchRequests());
        jobCostBudgetService.reconcile(
                item.getJobId(),
                item.getId(),
                callSite,
                reservedCostUsd,
                actualCostUsd,
                usage == null ? null : usage.inputTokens(),
                usage == null ? null : usage.outputTokens(),
                usage == null ? null : usage.webSearchRequests());
    }

    private void reconcileBundled(ResearchJobItem item, String callSite, BigDecimal reservedCostUsd, UsageDto usage) {
        BigDecimal actualCostUsd = usage == null
                ? BigDecimal.ZERO
                : jobCostBudgetService.computeActualCost(usage.inputTokens(), usage.outputTokens(), usage.webSearchRequests());
        jobCostBudgetService.reconcileBundledComponent(
                item.getJobId(),
                item.getId(),
                callSite,
                reservedCostUsd,
                actualCostUsd,
                usage == null ? null : usage.inputTokens(),
                usage == null ? null : usage.outputTokens(),
                usage == null ? null : usage.webSearchRequests());
    }
}
