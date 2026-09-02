package com.vulncheck.app.service;

import com.vulncheck.app.entity.CpeDictionaryEntry;
import com.vulncheck.app.entity.EcosystemRegistry;
import com.vulncheck.app.entity.IdentifiedProduct;
import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.repository.EcosystemRegistryRepository;
import com.vulncheck.app.repository.ResearchJobItemRepository;
import com.vulncheck.app.service.llm.LlmServiceClient;
import com.vulncheck.app.service.llm.LlmServiceModels.CandidateDto;
import com.vulncheck.app.service.llm.LlmServiceModels.DisambiguateResponse;
import com.vulncheck.app.service.llm.LlmServiceModels.PlatformHintDto;
import com.vulncheck.app.service.llm.LlmServiceModels.WebSearchIdentifyResponse;
import com.vulncheck.app.service.registry.RegistryMatch;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Closed-mode backlog item 166 / {@code docs/spec/closed-mode-plan.md} §3-3 (A3): every place
 * {@link Stage1IdentificationService} used to call out to the Claude LLM microservice — Tier2 CPE/
 * registry disambiguation and Tier3 web-search identification — pulled into its own class for the
 * same reason as {@link Stage1RegistryIdentification}: this whole file (plus {@link
 * LlmServiceClient}, the Python {@code llm-service}, and everything else in the "AI経路" deletion
 * list — see the plan doc's §3-8) is deleted outright in the future closed-processing-mode branch.
 *
 * <p>{@link #tryTier3} is the one method here that can't simply call back into {@link
 * Stage1IdentificationService} for the CPE-dictionary re-query and the final registry/CPE merge it
 * needs after resolving a name via web search — {@code Stage1IdentificationService} is the class
 * that constructs (and therefore, under Spring's constructor injection, must not depend on) this
 * one, so a direct back-reference would be a circular bean dependency. Instead {@code identify()}
 * passes in the two collaborator methods it already has ({@code fuzzyMatchCpe}/{@code
 * resolveCandidates}) as method references satisfying {@link CpeCandidateLookup}/{@link
 * IdentificationMerger} — ordinary Java method values, not Spring beans, so there is nothing here
 * for the container to resolve circularly. This keeps {@code tryTier3}'s full orchestration in one
 * place (matching the backlog's own extraction list) while leaving {@link
 * Stage1IdentificationService} a one-directional dependency on this class, not a mutual one.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class Stage1AiArbitration {

    private final UserApiKeyService userApiKeyService;
    private final JobCostBudgetService jobCostBudgetService;
    private final LlmServiceClient llmServiceClient;
    private final EcosystemRegistryRepository ecosystemRegistryRepository;
    private final ResearchJobItemRepository researchJobItemRepository;
    private final Stage1RegistryIdentification registryIdentification;

    /** {@code fuzzyMatchCpe}, handed to {@link #tryTier3} as a method reference so it can re-run the
     *  CPE dictionary lookup against Tier3's AI-resolved product name without this class needing a
     *  circular constructor dependency on {@link Stage1IdentificationService} itself — see this
     *  class's own javadoc. */
    @FunctionalInterface
    public interface CpeCandidateLookup {
        Stage1IdentificationService.CpeCandidateResult fuzzyMatchCpe(String vendor, String productName, Long userId,
                Optional<String> registryEcosystem, Optional<String> registryPackageName, String itemVersion);
    }

    /** {@code resolveCandidates}, handed to {@link #tryTier3} the same way as {@link
     *  CpeCandidateLookup} and for the same reason. */
    @FunctionalInterface
    public interface IdentificationMerger {
        Optional<IdentifiedProduct> resolveCandidates(ResearchJobItem item, Long userId,
                Stage1RegistryIdentification.RegistryResolution registryResolution,
                Stage1IdentificationService.CpeCandidateResult cpeCandidateResult,
                String methodIfNoDisambiguationNeeded, String vendorForCpeRescue, String productNameForCpeRescue);
    }

    /**
     * Tier3: Tier1 found absolutely nothing (common for marketplace/store listing names that
     * differ from the vendor's real product name). Asks the LLM (with web_search) to resolve the
     * real vendor/product name, then re-runs Tier1 against that resolved name.
     *
     * <p>The LLM is also given the enabled ecosystem list ({@link #ecosystemRegistryRepository})
     * and may propose {@code ecosystem_candidates} — a guessed exact registry package name per
     * ecosystem. This is the one place Tier3 is allowed to name a specific package directly
     * (rather than only a human-readable name fed back into fuzzy lookup): Tier1 already found
     * literally nothing, so there is no backend-provided candidate list to select from, and a
     * generic "resolved name" re-query fails whenever the marketplace/official name doesn't
     * happen to equal the registry's exact slug (e.g. "AWS CLI" vs the real PyPI name "awscli").
     * Each guess is still verified against the real registry before being trusted — never
     * persisted on the LLM's say-so alone.
     */
    public Optional<IdentifiedProduct> tryTier3(ResearchJobItem item, Long userId,
            CpeCandidateLookup cpeCandidateLookup, IdentificationMerger identificationMerger) {
        Optional<String> apiKey = userApiKeyService.getClaudeApiKey(userId);
        if (apiKey.isEmpty()) {
            return Optional.empty();
        }
        if (!jobCostBudgetService.tryReserve(item.getJobId(), JobCostBudgetService.TIER3_WEB_SEARCH_IDENTIFY_COST_USD)) {
            log.info("Tier3 skipped for item {}: job cost budget exhausted", item.getId());
            return Optional.empty();
        }

        List<String> enabledEcosystems = ecosystemRegistryRepository.findByEnabledTrue().stream()
                .map(EcosystemRegistry::getEcosystem)
                .toList();

        Optional<WebSearchIdentifyResponse> resolved = llmServiceClient.webSearchIdentify(
                apiKey.get(), item, enabledEcosystems, JobCostBudgetService.TIER3_WEB_SEARCH_IDENTIFY_COST_USD);
        if (resolved.isEmpty()) {
            return Optional.empty();
        }
        if (!resolved.get().found()) {
            applyUnresolvableReasonIfPresent(item, resolved.get().reasoning());
            return Optional.empty();
        }

        String resolvedProductName = resolved.get().officialProductName();
        String resolvedVendor = resolved.get().officialVendor();
        if (resolvedProductName == null || resolvedProductName.isBlank()) {
            return Optional.empty();
        }

        Stage1RegistryIdentification.RegistryResolution requeryRegistry =
                registryIdentification.resolveRegistryMatch(item, userId, resolvedProductName, item.getVersion());
        if (requeryRegistry.match().isEmpty()) {
            requeryRegistry = new Stage1RegistryIdentification.RegistryResolution(
                    registryIdentification.bestEcosystemCandidateMatch(item.getId(), resolved.get().ecosystemCandidates(), item.getVersion()),
                    false, null);
        }
        Stage1IdentificationService.CpeCandidateResult requeryCpe = cpeCandidateLookup.fuzzyMatchCpe(
                resolvedVendor, resolvedProductName, userId,
                requeryRegistry.match().map(RegistryMatch::ecosystem),
                requeryRegistry.match().map(RegistryMatch::packageName), item.getVersion());

        if (requeryRegistry.match().isEmpty() && requeryCpe.candidates().isEmpty()) {
            // Tier3 learned the real name, but re-querying Tier1 with it still found nothing
            // structural (no ecosystem/cpe) to persist — a known v1 gap, logged for visibility.
            log.info("Tier3 resolved item {} to '{}' (vendor: {}), but Tier1 re-query still found nothing",
                    item.getId(), resolvedProductName, resolvedVendor);
            applyPlatformHintIfPresent(item, resolved.get().platformHint());
            return Optional.empty();
        }

        return identificationMerger.resolveCandidates(item, userId, requeryRegistry, requeryCpe,
                IdentifiedProduct.METHOD_LLM_WEB_SEARCH, resolvedVendor, resolvedProductName);
    }

    /**
     * Item stays UNIDENTIFIED, but if the AI recognized this as belonging to a distribution
     * channel this app can't query directly (a marketplace/registry with no adapter here — VS
     * Code Marketplace, Chrome Web Store, Docker Hub, a Linux distro's own package manager, etc.)
     * and found a concrete identifier there, save it as a manual-verification hint rather than
     * silently dropping information the AI already went and found. Generalizes past the VS Code
     * case: {@code platform}/{@code note} are free text the AI fills in for whatever channel is
     * actually relevant, not a fixed enum.
     */
    private void applyPlatformHintIfPresent(ResearchJobItem item, PlatformHintDto hint) {
        if (hint == null || hint.identifier() == null || hint.identifier().isBlank()) {
            return;
        }
        String platform = hint.platform() != null && !hint.platform().isBlank() ? hint.platform() : "不明なプラットフォーム";
        String note = hint.note() != null && !hint.note().isBlank() ? " — " + hint.note() : "";
        item.setIdentificationHint(platform + ": " + hint.identifier() + note);
        item.setHintPlatform(platform);
        item.setHintIdentifier(hint.identifier());
        researchJobItemRepository.save(item);
        log.info("Item {} left UNIDENTIFIED but got a manual hint: platform={} identifier={}",
                item.getId(), hint.platform(), hint.identifier());
    }

    /**
     * Item stays UNIDENTIFIED, but when Tier3's web search concluded there's nothing to find at
     * all (firmware with no public registry, a commercial/proprietary product with no public
     * source, an internal-only tool, a plain typo with no real matching software, etc.), surface
     * *why* rather than just leaving a bare UNIDENTIFIED with no explanation — the reasoning was
     * already computed and previously discarded here. Not a manual-verification hint (there's no
     * identifier to look up), so this deliberately does not touch hintPlatform/hintIdentifier —
     * Stage4's hint-based research stays gated on hintIdentifier being present and won't fire on
     * a reasoning-only explanation.
     */
    private void applyUnresolvableReasonIfPresent(ResearchJobItem item, String reasoning) {
        if (reasoning == null || reasoning.isBlank()) {
            return;
        }
        item.setIdentificationHint("特定不可（AI判定）: " + reasoning);
        researchJobItemRepository.save(item);
        log.info("Item {} left UNIDENTIFIED — AI reported why: {}", item.getId(), reasoning);
    }

    /**
     * Reuses the Tier2 disambiguate endpoint with a single registry-match candidate — same
     * anti-hallucination shape (the LLM only ever selects/rejects a backend-provided candidate,
     * never invents a new package) as CPE disambiguation, just applied to a weak registry hit
     * instead. Returns empty when no verdict is available at all (no Claude key, or the call
     * itself failed) — callers treat that as "degrade to the pre-existing best-effort trust",
     * distinct from an actual {@code matched=false} rejection.
     */
    public Optional<DisambiguateResponse> verifyWeakRegistryMatchWithAi(ResearchJobItem item, Long userId, RegistryMatch match) {
        Optional<String> apiKey = userApiKeyService.getClaudeApiKey(userId);
        if (apiKey.isEmpty()) {
            return Optional.empty();
        }
        if (!jobCostBudgetService.tryReserve(item.getJobId(), JobCostBudgetService.TIER2_DISAMBIGUATE_COST_USD)) {
            log.info("Weak registry match AI verification skipped for item {}: job cost budget exhausted", item.getId());
            return Optional.empty();
        }
        CandidateDto candidate = new CandidateDto(match.ecosystem(), match.packageName(), null, match.purl(), "registry");
        return llmServiceClient.disambiguate(
                apiKey.get(), item, List.of(candidate), JobCostBudgetService.TIER2_DISAMBIGUATE_COST_USD);
    }

    /**
     * Reuses the Tier2 disambiguate endpoint with a single name-variant-derived CPE candidate — same
     * anti-hallucination shape as {@link #verifyWeakRegistryMatchWithAi}, applied to a CPE match
     * instead of a registry one. Callers must NOT degrade to trusting the match when this returns
     * empty (see {@code Stage1IdentificationService#resolveSingleCpeCandidate}'s javadoc for why)
     * — that's the one place this intentionally differs from the registry-match verification it's
     * modeled on.
     *
     * <p>Takes {@link MaskedCpeString} rather than a plain {@code String} (closed-mode backlog items
     * 169/170, senior review 2026-09-01) so "the CPE shown to the LLM is always version-masked" is
     * enforced by the type system instead of caller discipline.
     */
    public Optional<DisambiguateResponse> verifyVariantDerivedCpeMatchWithAi(
            ResearchJobItem item, Long userId, CpeDictionaryEntry candidate, MaskedCpeString maskedCpe) {
        Optional<String> apiKey = userApiKeyService.getClaudeApiKey(userId);
        if (apiKey.isEmpty()) {
            return Optional.empty();
        }
        if (!jobCostBudgetService.tryReserve(item.getJobId(), JobCostBudgetService.TIER2_DISAMBIGUATE_COST_USD)) {
            log.info("Variant-derived CPE candidate AI verification skipped for item {}: job cost budget exhausted", item.getId());
            return Optional.empty();
        }
        CandidateDto candidateDto = new CandidateDto(
                null, candidate.getProduct(), maskedCpe.value(), null, "cpe_dictionary_name_variant");
        return llmServiceClient.disambiguate(
                apiKey.get(), item, List.of(candidateDto), JobCostBudgetService.TIER2_DISAMBIGUATE_COST_USD);
    }

    /**
     * The "ask AI" half of {@code Stage1IdentificationService#resolveCandidates}'s multi-candidate
     * CPE Tier2 disambiguation block — same apiKey-presence + job-budget short-circuit as every
     * other AI call site here, so a caller can simply treat an empty result as "no AI verdict
     * available" without needing to know *why* (no key, no budget, or the LLM call itself failing
     * are all folded into the same empty return, matching this method's pre-extraction inline
     * behavior).
     *
     * <p>Takes {@link CpeDisambiguationCandidate} (which itself wraps a {@link MaskedCpeString})
     * rather than a raw {@code List<CandidateDto>} (closed-mode backlog items 169/170, senior review
     * 2026-09-01) — a plain {@code CandidateDto} carries an unconstrained {@code String cpe} field
     * a caller could pass unmasked, whereas building the {@code CandidateDto}s here from a
     * {@code MaskedCpeString}-backed type keeps "the LLM only ever sees masked CPEs" a guarantee
     * of this method's own signature instead of caller discipline.
     */
    public Optional<DisambiguateResponse> disambiguateCpeCandidates(
            ResearchJobItem item, Long userId, List<CpeDisambiguationCandidate> candidates) {
        Optional<String> apiKey = userApiKeyService.getClaudeApiKey(userId);
        if (apiKey.isEmpty()) {
            return Optional.empty();
        }
        if (!jobCostBudgetService.tryReserve(item.getJobId(), JobCostBudgetService.TIER2_DISAMBIGUATE_COST_USD)) {
            return Optional.empty();
        }
        List<CandidateDto> candidateDtos = candidates.stream()
                .map(c -> new CandidateDto(null, c.product(), c.cpe().value(), null, "cpe_dictionary"))
                .toList();
        return llmServiceClient.disambiguate(apiKey.get(), item, candidateDtos, JobCostBudgetService.TIER2_DISAMBIGUATE_COST_USD);
    }

    /**
     * One candidate for {@link #disambiguateCpeCandidates}: a CPE-dictionary product name paired
     * with its version-masked CPE string. Every real caller today (see {@link
     * Stage1IdentificationService#resolveCandidates}) fills in exactly this — dictionary-derived
     * {@code ecosystem=null}/{@code purl=null}/{@code source="cpe_dictionary"} — so bundling those
     * fixed fields here rather than exposing full {@link CandidateDto} construction to callers is
     * both simpler and (per this class's own note above) forces the CPE through {@link
     * MaskedCpeString}.
     */
    public record CpeDisambiguationCandidate(String product, MaskedCpeString cpe) {
    }
}
