package com.vulncheck.app.service;

import com.vulncheck.app.entity.CpeDictionaryEntry;
import com.vulncheck.app.entity.IdentifiedProduct;
import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.service.registry.RegistryMatch;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * Closed-mode B2 (docs/spec/closed-mode-plan.md §9-2): every AI call site this class used to hold
 * (Tier2 CPE/registry disambiguation via the Python {@code llm-service}, Tier3 web-search
 * identification) is gone along with {@code LlmServiceClient}/{@code LlmServiceModels} themselves —
 * closed mode never has a Claude API key to call with, so every method here now unconditionally
 * returns the exact same fallback {@link Stage1IdentificationService}/{@link
 * Stage1RegistryIdentification} already used whenever no key was configured (see each method's own
 * javadoc below for what that fallback means at each call site). {@link DisambiguateResponse} is
 * kept as a minimal local record shape (trimmed of the {@code usage}/cost fields that only ever
 * mattered for real Claude billing) purely so its callers' existing multi-branch decision trees
 * keep compiling and behaving exactly as they already did on their own "no AI verdict available"
 * path — not because this class calls anything with it anymore. {@code CandidateDto} (the old
 * {@code LlmServiceModels.CandidateDto} stand-in this class used to carry) was dropped once the
 * mainline (non-closed-mode) branch's own type-safety refactor (closed-mode backlog items 169/170)
 * moved every real caller over to {@link CpeDisambiguationCandidate}/{@link MaskedCpeString} — see
 * that record's own javadoc.
 */
@Component
public class Stage1AiArbitration {

    /** Trimmed local stand-in for the deleted {@code LlmServiceModels.DisambiguateResponse} — never
     *  actually instantiated by this class anymore (every method returns {@link Optional#empty()}),
     *  kept only as the return type's generic parameter so callers' existing {@code Optional}-based
     *  branching still compiles unchanged. */
    public record DisambiguateResponse(
            boolean matched,
            Integer selectedIndex,
            double confidence,
            String reasoning) {
    }

    /** {@code fuzzyMatchCpe} — no longer invoked by this class (Tier3 never fires), kept only as a
     *  parameter type on {@link #tryTier3} so {@link Stage1IdentificationService} doesn't need its
     *  own call site touched. */
    @FunctionalInterface
    public interface CpeCandidateLookup {
        Stage1IdentificationService.CpeCandidateResult fuzzyMatchCpe(String vendor, String productName, Long userId,
                Optional<String> registryEcosystem, Optional<String> registryPackageName, String itemVersion,
                String installUrl);
    }

    /** {@code resolveCandidates} — see {@link CpeCandidateLookup}'s own javadoc for why this is kept
     *  as an unused parameter type rather than dropped from {@link #tryTier3}'s signature. */
    @FunctionalInterface
    public interface IdentificationMerger {
        Optional<IdentifiedProduct> resolveCandidates(ResearchJobItem item, Long userId,
                Stage1RegistryIdentification.RegistryResolution registryResolution,
                Stage1IdentificationService.CpeCandidateResult cpeCandidateResult,
                String methodIfNoDisambiguationNeeded, String vendorForCpeRescue, String productNameForCpeRescue);
    }

    /**
     * Tier3 (web-search name resolution) has no non-AI form at all — closed mode always takes the
     * exact fallback {@link Stage1IdentificationService#identify} already took whenever no Claude key
     * was configured: leave the item UNIDENTIFIED (no marketplace-name resolution, no manual hint).
     */
    public Optional<IdentifiedProduct> tryTier3(ResearchJobItem item, Long userId,
            CpeCandidateLookup cpeCandidateLookup, IdentificationMerger identificationMerger) {
        return Optional.empty();
    }

    /**
     * Same fallback {@link Stage1IdentificationService#resolveCandidates} already used for "no AI
     * verdict available" on a weak registry match — that method's own static rule (reject an
     * unconfirmed match with a non-blank item vendor, otherwise trust it) takes over unconditionally.
     */
    public Optional<DisambiguateResponse> verifyWeakRegistryMatchWithAi(ResearchJobItem item, Long userId, RegistryMatch match) {
        return Optional.empty();
    }

    /**
     * Same fallback {@link Stage1IdentificationService#resolveSingleCpeCandidate} already used for
     * "no AI verdict available" on a name-variant-derived CPE candidate — that candidate is dropped
     * rather than trusted unconditionally now (see that method's own javadoc for why this is the
     * intentionally asymmetric case, unlike the registry-match fallback above).
     *
     * <p>Takes {@link MaskedCpeString} rather than a plain {@code String} (closed-mode backlog items
     * 169/170, senior review 2026-09-01) so "the CPE shown to the LLM is always version-masked" is
     * enforced by the type system instead of caller discipline — kept even though this class never
     * actually sends anything to an LLM anymore, so the signature stays aligned with the mainline
     * (non-closed-mode) branch this class was forked from.
     */
    public Optional<DisambiguateResponse> verifyVariantDerivedCpeMatchWithAi(
            ResearchJobItem item, Long userId, CpeDictionaryEntry candidate, MaskedCpeString maskedCpe) {
        return Optional.empty();
    }

    /**
     * Same fallback {@link Stage1IdentificationService#resolveCandidates} already used for "no AI
     * verdict available" among several CPE candidates — that method's own
     * degrade-to-first-candidate-unless-relaxed-containment-derived rule takes over unconditionally.
     *
     * <p>Takes {@link CpeDisambiguationCandidate} (which itself wraps a {@link MaskedCpeString})
     * rather than a raw {@code List<LlmServiceModels.CandidateDto>} (closed-mode backlog items
     * 169/170, senior review 2026-09-01), same rationale as {@link #verifyVariantDerivedCpeMatchWithAi}
     * above.
     */
    public Optional<DisambiguateResponse> disambiguateCpeCandidates(
            ResearchJobItem item, Long userId, List<CpeDisambiguationCandidate> candidates) {
        return Optional.empty();
    }

    /**
     * One candidate for {@link #disambiguateCpeCandidates}: a CPE-dictionary product name paired
     * with its version-masked CPE string. Every real caller today (see {@link
     * Stage1IdentificationService#resolveCandidates}) fills in exactly this — dictionary-derived
     * {@code ecosystem=null}/{@code purl=null}/{@code source="cpe_dictionary"} — so bundling those
     * fixed fields here rather than exposing full {@code LlmServiceModels.CandidateDto} construction
     * to callers is both simpler and (per this class's own note above) forces the CPE through
     * {@link MaskedCpeString}.
     */
    public record CpeDisambiguationCandidate(String product, MaskedCpeString cpe) {
    }
}
