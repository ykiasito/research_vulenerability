package com.vulncheck.app.service;

import com.vulncheck.app.entity.IdentifiedProduct;
import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.repository.IdentifiedProductRepository;
import com.vulncheck.app.service.llm.LlmServiceClient;
import com.vulncheck.app.service.llm.LlmServiceModels.AmbiguousCandidateDto;
import com.vulncheck.app.service.llm.LlmServiceModels.VerifyHighConfidenceResponse;
import com.vulncheck.app.service.nvd.CpeUtils;
import com.vulncheck.app.service.nvd.CpeUtils.VendorProduct;
import java.math.BigDecimal;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Backstop AI+web_search verification for the known-limitations "confidence lending" gap: a Stage1
 * item can reach {@code IDENTIFIED} status with a high (typically 0.95) confidence CPE match purely
 * via Tier1 static logic (a version-confirmed registry hit whose confidence gets attached to a
 * separately, non-AI-derived CPE — see {@link Stage1IdentificationService#resolveCandidates}'s own
 * "cheap half of the confidence-lending fix" comment) without that CPE's vendor/product ever having
 * been reviewed by Tier2/Tier3's AI disambiguation. Golden-300 benchmarking found real wrong CPEs
 * clustered almost entirely in exactly this population (vendor/generation mixups that static
 * containment logic alone didn't catch).
 *
 * <p>Off by default ({@link #enabled}) — every threshold/behavior below is deliberately
 * configurable (see each {@code @Value} field) rather than hardcoded, per the task this was built
 * for. Degrades exactly like every other AI tier in this app on any unavailability (feature
 * disabled, item not eligible, no Claude key, job cost budget exhausted, or the call itself
 * failing): the static match is left completely untouched, never blocked or failed.
 *
 * <p>Three distinct outcomes, not two — see {@link IdentifiedProduct#VERIFICATION_CONFIRMED}/
 * {@link IdentifiedProduct#VERIFICATION_INCORRECT}/{@link IdentifiedProduct#VERIFICATION_AMBIGUOUS}:
 * a genuinely ambiguous match (e.g. "Zoom" alone can't tell a Windows build from a Mac build) is
 * <em>not</em> the same as a wrong one — the existing candidate may well be correct, there's just
 * more than one real candidate it could legitimately be — so it is flagged for human review rather
 * than downgraded like an actually-incorrect match.
 *
 * <p>REVISE item 7 (senior review 2026-08-29, PR #1) — throughput note: {@link #verifyIfEligible}
 * runs synchronously on the item-processing thread (see {@code itemProcessingExecutor}, capped at 8
 * parallel items), the same as every other Stage1 AI tier call. Enabling this feature therefore adds
 * one more synchronous Claude round-trip to every eligible item's processing time, on top of
 * Tier2/Tier3/Stage4 — for a 1,000-item job with a meaningful fraction of high-confidence static
 * matches, this can plausibly add on the order of 7-8 minutes of wall-clock throughput compared to
 * running with the feature off.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class HighConfidenceVerificationService {

    private final UserApiKeyService userApiKeyService;
    private final LlmServiceClient llmServiceClient;
    private final JobCostBudgetService jobCostBudgetService;
    private final IdentifiedProductRepository identifiedProductRepository;

    @Value("${app.high-confidence-verification.enabled:false}")
    private boolean enabled;

    /** Only a {@link IdentifiedProduct#METHOD_STATIC} match (never touched by Tier2/Tier3 AI
     *  disambiguation) at or above this confidence is eligible — an item that already went through
     *  an AI tier has already had its CPE reviewed once, so re-checking it here would be a
     *  redundant double-charge for the same question. */
    @Value("${app.high-confidence-verification.confidence-threshold:0.95}")
    private double confidenceThreshold;

    /** Multiplier applied to an INCORRECT verdict's confidence — e.g. 0.5 halves it. Deliberately
     *  not 0 (that would be "全部疑う", an extreme fixed behavior) and not 1 (a no-op, "全部信用"). */
    @Value("${app.high-confidence-verification.downgrade-factor:0.5}")
    private double downgradeFactor;

    /**
     * Runs the verification check if (and only if) {@code product} is eligible, persisting whatever
     * outcome results directly onto it (or deleting it, for a full demotion with no registry
     * fallback — see {@link #applyIncorrectVerdict}). Callers must treat the return value as the
     * item's final Stage1 result: {@link Optional#empty()} means the item should end up
     * {@code UNIDENTIFIED}, exactly like every other Stage1 rejection path.
     *
     * @param product the already-persisted static match to verify; never null
     */
    public Optional<IdentifiedProduct> verifyIfEligible(ResearchJobItem item, IdentifiedProduct product, Long userId) {
        if (!enabled || !isEligible(product)) {
            return Optional.of(product);
        }
        Optional<String> apiKey = userApiKeyService.getClaudeApiKey(userId);
        if (apiKey.isEmpty()) {
            return Optional.of(product);
        }

        // REVISE item 2 (senior review 2026-08-29, PR #1): parsed BEFORE the budget reservation
        // below. A malformed cpe is detected here for free (isEligible already required a non-blank
        // cpe, so this should never actually happen) -- if it were checked only after
        // tryReserveVerification, this early return would leak the reservation, since it never
        // reaches a call to reconcileVerification to release it.
        VendorProduct vendorProduct = CpeUtils.parseVendorProduct(product.getCpe());
        if (vendorProduct == null) {
            log.warn("High-confidence verification skipped for item {}: could not parse vendor/product from cpe {}",
                    item.getId(), product.getCpe());
            return Optional.of(product);
        }

        if (!jobCostBudgetService.tryReserveVerification(item.getJobId(), JobCostBudgetService.HIGH_CONFIDENCE_VERIFICATION_COST_USD)) {
            log.info("High-confidence verification skipped for item {}: job cost budget exhausted", item.getId());
            return Optional.of(product);
        }

        Optional<VerifyHighConfidenceResponse> result = llmServiceClient.verifyHighConfidence(
                apiKey.get(), item, vendorProduct.vendor(), vendorProduct.product(),
                JobCostBudgetService.HIGH_CONFIDENCE_VERIFICATION_COST_USD);
        if (result.isEmpty()) {
            // Call itself failed (network/auth/etc) — degrade to trusting the static match, same as
            // every other AI tier's failure handling in this app.
            return Optional.of(product);
        }
        return applyVerdict(item, product, result.get());
    }

    /** A match is only eligible if it's purely static (no AI has ever reviewed this CPE yet) and
     *  actually has a CPE to verify — a registry-only match (no cpe) has nothing this endpoint
     *  checks, since it isn't a vendor/product CPE claim at all. */
    private boolean isEligible(IdentifiedProduct product) {
        return IdentifiedProduct.METHOD_STATIC.equals(product.getMethod())
                && product.getCpe() != null
                && !product.getCpe().isBlank()
                && product.getConfidence() != null
                && product.getConfidence().compareTo(BigDecimal.valueOf(confidenceThreshold)) >= 0;
    }

    private Optional<IdentifiedProduct> applyVerdict(ResearchJobItem item, IdentifiedProduct product, VerifyHighConfidenceResponse verdict) {
        String outcome = verdict.outcome() == null ? "" : verdict.outcome().toLowerCase(java.util.Locale.ROOT);
        return switch (outcome) {
            case "correct" -> {
                product.setVerificationStatus(IdentifiedProduct.VERIFICATION_CONFIRMED);
                product.setVerificationNote(verdict.reasoning());
                log.info("High-confidence verification CONFIRMED item {} ({}:{})",
                        item.getId(), product.getEcosystem(), product.getCpe());
                yield Optional.of(identifiedProductRepository.save(product));
            }
            case "ambiguous" -> {
                product.setVerificationStatus(IdentifiedProduct.VERIFICATION_AMBIGUOUS);
                product.setVerificationNote(describeAmbiguousCandidates(verdict));
                log.info("High-confidence verification AMBIGUOUS for item {} — needs human selection: {}",
                        item.getId(), product.getVerificationNote());
                // Confidence and CPE are deliberately left untouched: an ambiguous match is not
                // known to be wrong, just not confirmed as the *specific* one meant (see this
                // class's javadoc) — downgrading it the way an INCORRECT verdict does would
                // conflate two genuinely different situations.
                yield Optional.of(identifiedProductRepository.save(product));
            }
            case "incorrect" -> applyIncorrectVerdict(item, product, verdict);
            default -> {
                log.warn("High-confidence verification returned an unrecognized outcome '{}' for item {} — leaving match untouched",
                        verdict.outcome(), item.getId());
                yield Optional.of(product);
            }
        };
    }

    /**
     * INCORRECT always drops the CPE (it's the thing verification found implausible) and downgrades
     * confidence by {@link #downgradeFactor}. If there's no surviving registry-based signal
     * (ecosystem/packageName), the match is demoted fully — deleted, item ends up UNIDENTIFIED —
     * rather than left showing a low-but-nonzero confidence for a product with genuinely nothing
     * else backing it. When a registry match does survive, it's kept (verification only ever
     * evaluated the CPE claim, not the registry hit) with the discounted confidence, so the item
     * stays IDENTIFIED via that independent signal.
     *
     * <p>REVISE item 4 (senior review 2026-08-29, PR #1): demotion no longer depends on the
     * downgraded confidence crossing a configurable floor. It used to only demote when {@code
     * downgraded < demotionFloor (default 0.5)} AND {@code !hasRegistryFallback} — but with an
     * operator-raised {@code downgrade-factor} (e.g. 0.8), a 0.95-confidence match downgrades to
     * 0.76, which never falls below the 0.5 floor, so a match with neither a CPE nor a registry
     * fallback (nothing left to look up vulnerabilities against) would stay IDENTIFIED regardless —
     * exactly the "IDENTIFIED with no vulnerability-lookup path" bug this whole PR's Chocolatey fix
     * closed, reopened through a different door. Once the CPE is dropped, the absence of a registry
     * fallback alone is sufficient reason to demote, independent of how much the confidence number
     * happens to be discounted by.
     */
    private Optional<IdentifiedProduct> applyIncorrectVerdict(ResearchJobItem item, IdentifiedProduct product, VerifyHighConfidenceResponse verdict) {
        BigDecimal downgraded = product.getConfidence().multiply(BigDecimal.valueOf(downgradeFactor));
        boolean hasRegistryFallback = product.getEcosystem() != null && !product.getEcosystem().isBlank();

        if (!hasRegistryFallback) {
            log.info("High-confidence verification INCORRECT for item {} — demoting to UNIDENTIFIED "
                            + "(no registry fallback, downgraded confidence {}): {}",
                    item.getId(), downgraded, verdict.reasoning());
            identifiedProductRepository.delete(product);
            return Optional.empty();
        }

        product.setCpe(null);
        product.setConfidence(downgraded);
        product.setVerificationStatus(IdentifiedProduct.VERIFICATION_INCORRECT);
        product.setVerificationNote(describeIncorrectVerdict(verdict));
        log.info("High-confidence verification INCORRECT for item {} — CPE dropped, confidence downgraded to {}: {}",
                item.getId(), downgraded, verdict.reasoning());
        return Optional.of(identifiedProductRepository.save(product));
    }

    private String describeIncorrectVerdict(VerifyHighConfidenceResponse verdict) {
        // REVISE item 3 (senior review 2026-08-29, round 1): verdict.reasoning() is an ordinary
        // nullable field on the wire, same as ambiguousCandidates below -- normalize null to "" here
        // rather than either NPE'ing (StringBuilder constructor) or writing the literal string
        // "null（AIの推測: ...）" into verification_note.
        String reasoning = verdict.reasoning() == null ? "" : verdict.reasoning();
        // REVISE item 1 (senior review 2026-08-29, PR #1): alternativeVendor and
        // alternativeProduct are independently nullable -- concatenating either one directly would
        // write the literal string "null" into verification_note (e.g. "null:acrobat_reader") when
        // only one of the two is present. Join only the non-null parts instead.
        String hint = joinNonNull(verdict.alternativeVendor(), verdict.alternativeProduct());
        if (hint.isEmpty()) {
            return reasoning;
        }
        return reasoning + "（AIの推測: " + hint + "）";
    }

    private String describeAmbiguousCandidates(VerifyHighConfidenceResponse verdict) {
        StringBuilder sb = new StringBuilder(verdict.reasoning() == null ? "" : verdict.reasoning());
        // REVISE item 6 (senior review 2026-08-29, round 1): the llm-service response schema
        // doesn't guarantee ambiguousCandidates is present for an "ambiguous" outcome (it's an
        // ordinary nullable JSON field, not enforced non-null by anything on the wire) — an enhanced
        // for loop over a null list throws NPE, which would otherwise crash this AI-tier call site
        // instead of degrading gracefully like every other one in this app.
        if (verdict.ambiguousCandidates() == null || verdict.ambiguousCandidates().isEmpty()) {
            return sb.toString();
        }
        for (AmbiguousCandidateDto candidate : verdict.ambiguousCandidates()) {
            // REVISE item 1 (senior review 2026-08-29, PR #1): same independent-nullability
            // issue as describeIncorrectVerdict above applies to candidate.vendor()/product().
            String candidateLabel = joinNonNull(candidate.vendor(), candidate.product());
            // Both vendor and product are pydantic-required (non-null) on the wire, but "" is a
            // distinct, allowed value from null -- if both come back "", candidateLabel is "" too
            // and there's nothing meaningful to append. Skip the whole candidate (including the
            // " / " separator) rather than leaving a content-free " / " in verification_note.
            if (candidateLabel.isEmpty()) {
                continue;
            }
            sb.append(" / ").append(candidateLabel);
            if (candidate.note() != null && !candidate.note().isBlank()) {
                sb.append(" (").append(candidate.note()).append(')');
            }
        }
        return sb.toString();
    }

    /** Joins two independently-nullable strings with {@code ":"}, omitting whichever side is null
     *  or blank rather than rendering it as the literal text {@code "null"} or leaving a stray
     *  {@code ":"} when the llm-service sends {@code ""} instead of {@code null}. */
    private static String joinNonNull(String first, String second) {
        boolean hasFirst = first != null && !first.isBlank();
        boolean hasSecond = second != null && !second.isBlank();
        if (!hasFirst) {
            return hasSecond ? second : "";
        }
        return hasSecond ? first + ":" + second : first;
    }
}
