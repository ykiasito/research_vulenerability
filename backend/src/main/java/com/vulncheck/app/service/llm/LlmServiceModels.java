package com.vulncheck.app.service.llm;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * Request/response shapes for the Python LLM microservice's endpoints
 * (llm-service/main.py). Field names use {@code @JsonProperty} to match that service's
 * snake_case JSON exactly, since the rest of this app's Java fields are camelCase.
 */
public final class LlmServiceModels {

    private LlmServiceModels() {
    }

    /** Real Claude API usage for one call, as reported by the LLM microservice — used to
     *  reconcile {@link com.vulncheck.app.service.JobCostBudgetService}'s worst-case reservation
     *  down to actual spend. {@code webSearchRequests} is 0 for the disambiguate endpoint, which
     *  never attaches the web_search tool. */
    public record UsageDto(
            @JsonProperty("input_tokens") int inputTokens,
            @JsonProperty("output_tokens") int outputTokens,
            @JsonProperty("web_search_requests") int webSearchRequests) {
    }

    public record CandidateDto(
            String ecosystem,
            @JsonProperty("package_name") String packageName,
            String cpe,
            String purl,
            String source) {
    }

    public record DisambiguateRequest(
            @JsonProperty("api_key") String apiKey,
            @JsonProperty("product_name") String productName,
            String version,
            String vendor,
            @JsonProperty("usage_text") String usageText,
            List<CandidateDto> candidates) {
    }

    public record DisambiguateResponse(
            boolean matched,
            @JsonProperty("selected_index") Integer selectedIndex,
            double confidence,
            String reasoning,
            UsageDto usage) {
    }

    public record WebSearchIdentifyRequest(
            @JsonProperty("api_key") String apiKey,
            @JsonProperty("product_name") String productName,
            String version,
            String vendor,
            @JsonProperty("usage_text") String usageText,
            @JsonProperty("enabled_ecosystems") List<String> enabledEcosystems) {
    }

    /** A package-registry guess the AI is confident enough in to have the backend try directly —
     *  {@code ecosystem} must be one of the values sent in {@code enabled_ecosystems}. */
    public record EcosystemCandidateDto(
            String ecosystem,
            @JsonProperty("package_name") String packageName) {
    }

    /** A manual-verification hint for a distribution channel this app can't query directly (a
     *  marketplace, container registry, package manager, etc.) — e.g. platform="VS Code
     *  Marketplace", identifier="ms-python.python". All fields null when the AI found no such
     *  recognizable identifier. */
    public record PlatformHintDto(
            String platform,
            String identifier,
            String note) {
    }

    public record WebSearchIdentifyResponse(
            boolean found,
            @JsonProperty("official_vendor") String officialVendor,
            @JsonProperty("official_product_name") String officialProductName,
            String reasoning,
            @JsonProperty("source_urls") List<String> sourceUrls,
            @JsonProperty("ecosystem_candidates") List<EcosystemCandidateDto> ecosystemCandidates,
            @JsonProperty("platform_hint") PlatformHintDto platformHint,
            UsageDto usage) {
    }

    public record WebSearchResearchRequest(
            @JsonProperty("api_key") String apiKey,
            @JsonProperty("product_name") String productName,
            String version,
            String vendor,
            String ecosystem,
            @JsonProperty("package_name") String packageName) {
    }

    public record WebSearchVulnFindingDto(
            String identifier,
            String severity,
            String description,
            @JsonProperty("citation_url") String citationUrl,
            @JsonProperty("fixed_version") String fixedVersion) {
    }

    public record WebSearchResearchResponse(List<WebSearchVulnFindingDto> findings, UsageDto usage) {
    }

    // --- Bundled-package (formerly "Stage 3.5") detection --------------------------------------

    public record BundledChangelogRequest(
            @JsonProperty("api_key") String apiKey,
            @JsonProperty("product_name") String productName,
            String version,
            String vendor) {
    }

    /** {@code found=false} (with {@code changelogText} null) when web_search couldn't locate an
     *  official changelog/release-note page for this product+version — a real, expected outcome
     *  (see the plan's §2), not a failure. */
    public record BundledChangelogResponse(
            boolean found,
            @JsonProperty("changelog_text") String changelogText,
            @JsonProperty("source_urls") List<String> sourceUrls,
            UsageDto usage) {
    }

    public record BundledExtractRequest(
            @JsonProperty("api_key") String apiKey,
            @JsonProperty("product_name") String productName,
            String version,
            @JsonProperty("changelog_text") String changelogText) {
    }

    /** One (component, version) pair the LLM extracted from changelog text — plain facts only,
     *  never a CVE/GHSA id or a vulnerability judgment (enforced by the llm-service system prompt,
     *  not just convention — see the plan's §3-2). Backend-side validation ({@code
     *  BundledComponentResearchService}) still treats every field here as untrusted before use. */
    public record BundledComponentDto(
            @JsonProperty("component_name") String componentName,
            String version,
            String confidence) {
    }

    /** Empty {@code bundledComponents} is a valid, expected response (no bundled components
     *  mentioned in the changelog text) — never treated as a failure. */
    public record BundledExtractResponse(
            @JsonProperty("bundled_components") List<BundledComponentDto> bundledComponents,
            UsageDto usage) {
    }
}
