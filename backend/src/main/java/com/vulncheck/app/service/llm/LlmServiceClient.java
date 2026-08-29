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
import com.vulncheck.app.service.llm.LlmServiceModels.VerifyHighConfidenceRequest;
import com.vulncheck.app.service.llm.LlmServiceModels.VerifyHighConfidenceResponse;
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
                apiKey,
                truncate(item.getProductName(), SHORT_FIELD_MAX_LENGTH, "productName"),
                truncate(item.getVersion(), SHORT_FIELD_MAX_LENGTH, "version"),
                truncate(item.getVendor(), SHORT_FIELD_MAX_LENGTH, "vendor"),
                truncate(item.getUsageText(), USAGE_TEXT_MAX_LENGTH, "usageText"),
                candidates);
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
                apiKey,
                truncate(item.getProductName(), SHORT_FIELD_MAX_LENGTH, "productName"),
                truncate(item.getVersion(), SHORT_FIELD_MAX_LENGTH, "version"),
                truncate(item.getVendor(), SHORT_FIELD_MAX_LENGTH, "vendor"),
                truncate(item.getUsageText(), USAGE_TEXT_MAX_LENGTH, "usageText"),
                enabledEcosystems);
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
                apiKey,
                truncate(item.getProductName(), SHORT_FIELD_MAX_LENGTH, "productName"),
                truncate(item.getVersion(), SHORT_FIELD_MAX_LENGTH, "version"),
                truncate(item.getVendor(), SHORT_FIELD_MAX_LENGTH, "vendor"),
                ecosystem, packageName);
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
     * High-confidence verification backstop ({@code HighConfidenceVerificationService}): double-checks
     * a Tier1-only, never-AI-reviewed static CPE match at (or above) the configured confidence
     * threshold. Same best-effort-degrade contract as every other method here — {@code Optional.empty()}
     * on any failure, which the caller treats as "leave the static match as-is".
     */
    public Optional<VerifyHighConfidenceResponse> verifyHighConfidence(
            String apiKey, ResearchJobItem item, String cpeVendor, String cpeProduct, BigDecimal reservedCostUsd) {
        VerifyHighConfidenceRequest request = new VerifyHighConfidenceRequest(
                apiKey,
                truncate(item.getProductName(), SHORT_FIELD_MAX_LENGTH, "productName"),
                truncate(item.getVersion(), SHORT_FIELD_MAX_LENGTH, "version"),
                truncate(item.getVendor(), SHORT_FIELD_MAX_LENGTH, "vendor"),
                truncate(item.getUsageText(), USAGE_TEXT_MAX_LENGTH, "usageText"),
                cpeVendor, cpeProduct);
        UsageDto usage = null;
        try {
            VerifyHighConfidenceResponse response = llmServiceRestClient.post()
                    .uri("/v1/identify/verify-high-confidence")
                    .body(request)
                    .retrieve()
                    .body(VerifyHighConfidenceResponse.class);
            usage = response == null ? null : response.usage();
            return Optional.ofNullable(response);
        } catch (RestClientException e) {
            log.warn("LLM high-confidence verification call failed for item {}", item.getId(), e);
            return Optional.empty();
        } catch (RuntimeException e) {
            log.error("LLM high-confidence verification call failed unexpectedly for item {}", item.getId(), e);
            return Optional.empty();
        } finally {
            reconcileVerification(item, JobCostLedgerEntry.CALL_SITE_VERIFICATION, reservedCostUsd, usage);
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
        BundledChangelogRequest request = new BundledChangelogRequest(
                apiKey,
                truncate(item.getProductName(), SHORT_FIELD_MAX_LENGTH, "productName"),
                truncate(item.getVersion(), SHORT_FIELD_MAX_LENGTH, "version"),
                truncate(item.getVendor(), SHORT_FIELD_MAX_LENGTH, "vendor"));
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
        BundledExtractRequest request = new BundledExtractRequest(
                apiKey,
                truncate(item.getProductName(), SHORT_FIELD_MAX_LENGTH, "productName"),
                truncate(item.getVersion(), SHORT_FIELD_MAX_LENGTH, "version"),
                truncate(changelogText, USAGE_TEXT_MAX_LENGTH, "changelogText"));
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

    /** Mirrors {@link #reconcile}/{@link #reconcileBundled}, against {@code
     *  HighConfidenceVerificationService}'s own separate budget ledger (REVISE item 1, senior review
     *  2026-08-29 — see {@code JobCostBudgetService#verificationCostCapPerItemUsd}'s javadoc). */
    private void reconcileVerification(ResearchJobItem item, String callSite, BigDecimal reservedCostUsd, UsageDto usage) {
        BigDecimal actualCostUsd = usage == null
                ? BigDecimal.ZERO
                : jobCostBudgetService.computeActualCost(usage.inputTokens(), usage.outputTokens(), usage.webSearchRequests());
        jobCostBudgetService.reconcileVerification(
                item.getJobId(),
                item.getId(),
                callSite,
                reservedCostUsd,
                actualCostUsd,
                usage == null ? null : usage.inputTokens(),
                usage == null ? null : usage.outputTokens(),
                usage == null ? null : usage.webSearchRequests());
    }

    // --- Prompt-field length guard (REVISE item 5, senior review 2026-08-29) ----------------------
    //
    // ResearchJobItem.usageText is a TEXT column with no length validation anywhere upstream, and
    // every method above embeds it (plus the short productName/version/vendor fields) directly into
    // a Claude prompt. JobCostBudgetService's reservations are fixed, size-independent worst-case
    // dollar estimates per call, not scaled to real token counts — so a single CSV row with a
    // deliberately huge usage_text cell could inflate one call's *real* token count (and therefore
    // real dollar cost) far past its reservation, without tripping the pre-flight budget check at
    // all. Truncating every item-derived string field here, at the one place every Claude-calling
    // method already funnels its request body through, closes that gap regardless of which endpoint
    // is called.

    private static final int USAGE_TEXT_MAX_LENGTH = 2000;
    private static final int SHORT_FIELD_MAX_LENGTH = 200;

    private String truncate(String value, int maxLength, String fieldName) {
        if (value == null || value.length() <= maxLength) {
            return value;
        }
        log.debug("Truncating field '{}' from {} to {} characters before sending to llm-service",
                fieldName, value.length(), maxLength);
        return value.substring(0, maxLength);
    }
}
