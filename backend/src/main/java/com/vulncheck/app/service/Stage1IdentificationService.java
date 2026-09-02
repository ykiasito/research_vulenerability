package com.vulncheck.app.service;

import com.vulncheck.app.entity.CpeDictionaryEntry;
import com.vulncheck.app.entity.IdentifiedProduct;
import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.repository.CpeDictionaryRepository;
import com.vulncheck.app.repository.IdentifiedProductRepository;
import com.vulncheck.app.service.Stage1AiArbitration.DisambiguateResponse;
import com.vulncheck.app.service.nvd.CpeNameVariantCache;
import com.vulncheck.app.service.nvd.CpeUtils;
import com.vulncheck.app.service.nvd.NameVariantGenerator;
import com.vulncheck.app.service.registry.RegistryMatch;
import com.vulncheck.app.service.registry.RegistryRoutingPolicy;
import java.math.BigDecimal;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Stage1 product identification — Tier1 (static registries + CPE Dictionary), Tier2 (LLM
 * disambiguation among an ambiguous CPE candidate set), and Tier3 (LLM+web_search when Tier1
 * found nothing at all, e.g. marketplace name variance).
 *
 * <p>Tier1's CPE matching is not limited to whatever an admin has pre-synced into the local
 * dictionary: {@link #fuzzyMatchCpe} falls back to a live, single-page NVD CPE API call (via
 * {@link NvdCpeSyncService#syncKeywordSinglePage}) whenever the local mirror has zero candidates,
 * so a product nobody has synced a keyword for yet can still be resolved — the whole point of a
 * research tool is handling products that aren't already known locally.
 *
 * <p>Tier2/3 both go through {@link UserApiKeyService} for the job owner's own Claude key —
 * if it's not configured, both tiers are silently skipped and this degrades to Tier1-only
 * behavior (same as before Tier2/3 existed), never blocking or failing the item.
 *
 * <p>Closed-mode backlog item 166 / {@code docs/spec/closed-mode-plan.md} §3-3 (A3): the Tier1
 * external-registry fan-out and every Tier2/3 LLM call site used to be interleaved line-by-line
 * inside this class's own {@code identify}/{@code resolveCandidates}/{@code resolveRegistryMatch}.
 * Those two seams are now {@link Stage1RegistryIdentification} and {@link Stage1AiArbitration} —
 * this class keeps only the CPE dictionary path ({@link #localCpeLookup}/{@link #fuzzyMatchCpe}/
 * {@link #rankCpeCandidates}/{@link #findByNameVariants}/{@link #expandLeadingInitialism} etc.)
 * plus the orchestration ({@code identify}/{@code resolveCandidates}) that merges all three
 * signals together — see those two classes' own javadoc for why the orchestration itself, rather
 * than being fully absorbed into either seam, stays here.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class Stage1IdentificationService {

    /**
     * Two separate thresholds, not one: {@code product} holds the CPE's normalized single-word
     * product slug (e.g. "gson", "nuget") and pg_trgm gives every real match near-1.0 similarity
     * there — but {@code title} is a full human-readable string ("Microsoft NuGet 4.3.1") whose
     * similarity to another short query inflates just from sharing a vendor word, independent of
     * the actual product. Confirmed live: with a sparse dictionary (only a handful of keywords ever
     * synced), "Microsoft Edge" and "Microsoft Teams" both scored ~0.35-0.4 title-similarity against
     * "Microsoft NuGet ..." entries and were accepted as matches under a single 0.3 threshold —
     * "Google Chrome" likewise matched "Google Gson ..." at 0.35. Requiring a much higher bar for a
     * title-only hit (no product-slug corroboration) closes this off without narrowing product-slug
     * matching, which was never the source of the false positives.
     */
    private static final double CPE_PRODUCT_SIMILARITY_THRESHOLD = 0.3;
    private static final double CPE_TITLE_SIMILARITY_THRESHOLD = 0.6;
    private static final int CPE_CANDIDATE_LIMIT = 3;
    /**
     * The dictionary search pulls a much wider pool than the {@value #CPE_CANDIDATE_LIMIT}
     * candidates ultimately handed to Tier2, because the raw pg_trgm ordering is a poor final
     * ranking on its own: the same product occupies one row per catalogued version (measured
     * against the real NVD dictionary: 72.7% of its 1.8M rows are version duplicates — TeamViewer
     * alone has dozens), so a narrow window is easily filled by near-duplicates or by unrelated
     * products that merely score well on generic shared words. Pulling a wide pool first, then
     * de-duplicating per vendor:product and re-ranking by vendor affinity, is what makes the final
     * three actually mean "the three best distinct products".
     */
    private static final int CPE_CANDIDATE_POOL = 40;
    private static final int LIVE_NVD_LOOKUP_RESULTS_PER_PAGE = 20;
    private static final int MAX_LIVE_NVD_QUERY_ATTEMPTS = 3;
    private static final BigDecimal CPE_MATCH_CONFIDENCE = new BigDecimal("0.6");
    /**
     * Hard cap on how many *extra* local-dictionary queries {@link #findByNameVariants} may issue
     * per item, on top of the one literal query {@link #localCpeLookup} always runs first — this is
     * the "candidate fan-out" the design explicitly requires a named limit for. Only ever spent at
     * all when the literal search already found nothing, and stops at the first variant that finds
     * something, so the common case (literal search already succeeds) pays none of this.
     */
    private static final int MAX_NAME_VARIANT_QUERIES_PER_ITEM = 3;
    /**
     * Hard cap on the initialism-expansion anchor search ({@link #expandLeadingInitialism}), a
     * left-anchored regex search against the {@code product} column (see {@link
     * com.vulncheck.app.repository.CpeDictionaryRepositoryCustom#findByLeadingInitialismMatch} for
     * why this can still use the existing trigram index despite not being a plain similarity
     * search). As of 2026-08-25 the regex itself does the real filtering at the SQL level (a
     * candidate's leading per-word initials must spell the abbreviation, immediately followed by
     * the anchor) rather than a broad ILIKE pre-filter — this limit is now generous headroom above
     * the handful of genuine matches a real abbreviation+anchor pair has, not a correctness-critical
     * window a real match has to fit inside.
     */
    private static final int NAME_VARIANT_ANCHOR_SEARCH_LIMIT = 500;
    /** An initialism this short (1 char) or this long (7+) isn't a plausible abbreviation of
     *  several other words — either too little signal either way, or simply a real first word. */
    private static final int MIN_INITIALISM_LENGTH = 2;
    private static final int MAX_INITIALISM_LENGTH = 6;
    /**
     * Below this many characters, the anchor phrase in {@link #expandLeadingInitialism} has no
     * trigram pg_trgm's GIN index can extract from the generated regex at all — measured live
     * 2026-08-25 via {@code EXPLAIN ANALYZE} against the real 1.8M-row dictionary: a 1-2 character
     * anchor still nominally "uses" the index but degrades into a 230ms-1.4s bitmap scan that has
     * to recheck tens of thousands of rows, run synchronously on the calling thread — a real
     * throughput risk. A 3+ character anchor stayed at ~13ms in the same test.
     */
    private static final int MIN_ANCHOR_LENGTH_FOR_INITIALISM_EXPANSION = 3;
    /**
     * Backlog item 36 (senior review 2026-08-30): the multiplier {@link #versionCoverageIsPlausible}
     * uses to decide whether an item's version is implausibly far beyond a candidate's catalogued
     * history, rather than demoting on {@code itemMajor > maxCatalogedMajor} alone. Measured against
     * golden-300: all 9 correct candidates whose catalogue trails the item's major version stay
     * within a ratio of 1.60, while the genuinely wrong candidates this tie-break exists to demote
     * (Audacity ratio 3.0, {@code puppet:cisco_ios} ratio 17) sit far beyond 2.
     */
    private static final int VERSION_COVERAGE_IMPLAUSIBILITY_RATIO = 2;
    /**
     * Ecosystem -&gt; CPE {@code target_sw} value (REVISE item 5, senior review 2026-08-26 / job 36
     * root-cause): the platform-scoping word NVD uses in a CPE's {@code target_sw} segment for a
     * package originating from that ecosystem's own runtime, when a real CPE happens to be scoped
     * that way (e.g. a Java library's Maven-published NVD CPE occasionally carries
     * {@code target_sw=maven}, a Jenkins plugin carries {@code target_sw=jenkins}). Deliberately
     * omits {@code hex} and {@code maven} — hex packages (e.g. Elixir's "tesla") and Maven
     * coordinates don't map to one canonical {@code target_sw} word the way the other eight do, so
     * both are left with no mapping and therefore no target_sw signal at all (see {@link
     * #mapEcosystemToTargetSw}) rather than guessing one and risking a wrong gate/preference.
     */
    private static final java.util.Map<String, String> ECOSYSTEM_TO_TARGET_SW = java.util.Map.of(
            "npm", "node.js",
            "pypi", "python",
            "rubygems", "ruby",
            "crates.io", "rust",
            "go", "go",
            "packagist", "php",
            "pub", "dart",
            "nuget", ".net");

    /**
     * REVISE item 2 (senior review, job 37 root-cause): {@code target_sw} values that scope a CPE to
     * an operating system/CPU architecture rather than to being a *component of some other software
     * platform* — the actual thing {@link #passesTargetSwGate} exists to reject. {@code
     * target_sw=macos} on Sophos Home's real NVD entry means "the macOS build of Sophos Home", not
     * "a plugin for macOS the way target_sw=jenkins means a Jenkins plugin" — treating every non-
     * wildcard target_sw value as equally disqualifying wrongly rejected that entry (senior review,
     * job 36/37: Sophos Home went from a correct match to a lost one). Treated exactly like {@code *}/
     * {@code -}: always passes the gate, never a hard requirement either.
     */
    private static final java.util.Set<String> NON_SCOPING_TARGET_SW_VALUES = java.util.Set.of(
            "windows", "macos", "mac_os", "linux", "unix",
            "android", "iphone_os", "ios", "ipados", "x86", "x64");

    /**
     * REVISE item 3 (senior review, job 37 root-cause): no registry ecosystem this project ever
     * routes to is "jenkins" — a CPE scoped {@code target_sw=jenkins} is always a Jenkins plugin,
     * never a standalone ecosystem package, so it must be rejected unconditionally, including through
     * the {@code hex}/{@code maven} fallback path ({@link #passesTargetSwGate}'s {@code
     * orElse(true)} default-allow for those two unmapped ecosystems) which would otherwise let it
     * through. Fixes {@code junit:junit} (Maven) wrongly resolving to {@code jenkins:junit}
     * (NVD's real "JUnit plugin for Jenkins" entry) instead of correctly falling through to no-CPE.
     */
    private static final String JENKINS_TARGET_SW = "jenkins";

    private final CpeDictionaryRepository cpeDictionaryRepository;
    private final CpeNameVariantCache cpeNameVariantCache;
    private final IdentifiedProductRepository identifiedProductRepository;
    // Only ever consulted here for getNvdApiKey (the live NVD CPE keyword-search fallback in
    // liveNvdCpeLookupWithFallback) — closed-mode B2 removed the Claude key lookup entirely (see
    // UserApiKeyService's own javadoc), so this field is now NVD-only.
    private final UserApiKeyService userApiKeyService;
    private final NvdCpeSyncService nvdCpeSyncService;
    // Closed-mode B2 (docs/spec/closed-mode-plan.md §9-2): no longer does anything but hand the
    // match back unchanged — see its own javadoc. Left wired in rather than removed outright, since
    // closed-mode backlog item 166 already flagged this class's own registry/AI seams for full
    // deletion in a later phase.
    private final HighConfidenceVerificationService highConfidenceVerificationService;
    // The two seams closed-mode backlog item 166 extracted — see this class's own javadoc. Closed-mode
    // B2 (docs/spec/closed-mode-plan.md §9-2) already gutted both of their AI call sites down to a
    // fixed fallback; deleting these two fields plus the handful of call sites below is left for the
    // later phase that removes this class's registry/AI paths outright.
    private final Stage1RegistryIdentification registryIdentification;
    private final Stage1AiArbitration aiArbitration;

    /**
     * Attempts identification for a single job item and persists the result.
     *
     * @param userId the job's owner, whose own Claude key (if any) is used for Tier2/3
     * @return the saved {@link IdentifiedProduct}, or empty if nothing could be identified
     */
    public Optional<IdentifiedProduct> identify(ResearchJobItem item, Long userId) {
        // Closed-mode backlog item 193 (B3, docs/spec/closed-mode-plan.md §7 P1): the local CPE
        // dictionary check used to be kicked off onto registryLookupExecutor to run concurrently
        // with the external registry fan-out below, since that fan-out was, before B3, up to 10
        // independent several-second network round trips (up to Maven Central's 20s circuit-breaker
        // worst case) — worth overlapping with the usually-much-faster local dictionary lookup
        // rather than paying both costs strictly sequentially. Every registry lookup is now a local
        // registry_package_mirror DB read (see Stage1RegistryIdentification's own javadoc), so
        // there's no longer a slow network wait to hide the local lookup behind — this simply calls
        // it directly on the calling thread. Both signals are still always gathered, same coverage
        // as before.
        LocalCpeMatches localCpeMatches = localCpeLookup(item.getVendor(), item.getProductName(), item.getVersion());

        Stage1RegistryIdentification.RegistryResolution registryResolution =
                registryIdentification.resolveRegistryMatch(item, userId, item.getProductName(), item.getVersion());
        // A registry match already gives Stage2 vulnerability coverage via OSV/GHSA, so a missing
        // local CPE cache entry isn't worth a ~6.5s (or ~0.7s with an NVD key) live NVD round trip
        // here — NVD-via-CPE is a supplementary Stage2 source in that case, not the only signal.
        // Coverage still wins when nothing else has already confirmed this product is real.
        Optional<String> registryEcosystem = registryResolution.match().map(RegistryMatch::ecosystem);
        Optional<String> registryPackageName = registryResolution.match().map(RegistryMatch::packageName);
        CpeCandidateResult cpeCandidateResult = resolveCpeCandidates(item.getVendor(), item.getProductName(), userId,
                registryEcosystem, registryPackageName, localCpeMatches, item.getVersion());

        Optional<IdentifiedProduct> result = (registryResolution.match().isEmpty() && cpeCandidateResult.candidates().isEmpty())
                ? aiArbitration.tryTier3(item, userId, this::fuzzyMatchCpe, this::resolveCandidates)
                : resolveCandidates(item, userId, registryResolution, cpeCandidateResult, IdentifiedProduct.METHOD_STATIC,
                        item.getVendor(), item.getProductName());

        // High-confidence verification backstop: only ever reconsiders a match that resolveCandidates
        // just produced purely via static logic (no Tier2/Tier3 AI review) at high confidence — see
        // HighConfidenceVerificationService's own javadoc for why this exists and its off-by-default
        // feature flag. A no-op (returns result unchanged) for every other outcome shape.
        result = result.flatMap(product -> highConfidenceVerificationService.verifyIfEligible(item, product, userId));

        log.info("Stage1 identify item {} ('{}' v{}): registryMatch={}, cpeCandidates={}, result={}",
                item.getId(), item.getProductName(), item.getVersion(),
                registryResolution.match().map(RegistryMatch::packageName).orElse(null),
                cpeCandidateResult.candidates().size(),
                result.map(this::describe).orElse("UNIDENTIFIED"));

        return result;
    }

    private String describe(IdentifiedProduct product) {
        return product.getMethod() + " ecosystem=" + product.getEcosystem()
                + " package=" + product.getPackageName() + " cpe=" + product.getCpe();
    }

    /**
     * Merges a registry match and CPE candidate(s) into one {@link IdentifiedProduct}. The common
     * case — at most one CPE candidate — needs no LLM call: it's simply merged with the registry
     * match, exactly as Tier1 always did. Tier2 only fires when the CPE fuzzy search itself
     * returned more than one plausible candidate (genuine ambiguity worth spending a call on).
     *
     * <p>Handed to {@link Stage1AiArbitration#tryTier3} as a method reference (see that class's own
     * javadoc for why) — visible here as a package-private-callable {@code private} method is fine,
     * since a method reference to it is only ever taken from within this same class.
     */
    private Optional<IdentifiedProduct> resolveCandidates(
            ResearchJobItem item,
            Long userId,
            Stage1RegistryIdentification.RegistryResolution registryResolution,
            CpeCandidateResult cpeCandidateResult,
            String methodIfNoDisambiguationNeeded,
            String vendorForCpeRescue,
            String productNameForCpeRescue) {

        List<CpeDictionaryEntry> cpeCandidates = cpeCandidateResult.candidates();
        boolean cpeCandidatesAreVariantDerived = cpeCandidateResult.variantDerived();
        boolean cpeCandidatesAreRelaxedContainmentDerived = cpeCandidateResult.relaxedContainmentDerived();
        Optional<RegistryMatch> registryMatch = registryResolution.match();
        CpeDictionaryEntry chosenCpe = null;
        String method = methodIfNoDisambiguationNeeded;
        BigDecimal disambiguationConfidence = null;
        // Measurement-only provenance for IdentifiedProduct#cpeCandidateCount/cpeCandidateVariantDerived
        // (docs/spec/task-backlog.md item 16) — tracked alongside chosenCpe through every path that can
        // set it, reset to null wherever chosenCpe is reset to null, and never read by any confidence
        // branch below.
        Integer cpeCandidateCount = null;
        Boolean cpeCandidateVariantDerived = null;

        if (cpeCandidates.size() > 1) {
            cpeCandidateCount = cpeCandidates.size();
            cpeCandidateVariantDerived = cpeCandidatesAreVariantDerived;
            // Building candidateDtos and calling aiArbitration unconditionally (rather than only
            // when an apiKey/budget check already passed) is behaviorally identical to the
            // pre-extraction inline check: candidateDtos construction is pure/side-effect-free, and
            // Stage1AiArbitration#disambiguateCpeCandidates internally applies the exact same
            // apiKey-presence + job-budget short-circuit before ever calling the LLM, returning
            // empty for either failure reason — which this method already treats identically to an
            // LLM call that itself came back empty (both degrade to the same fallback below).
            List<Stage1AiArbitration.CpeDisambiguationCandidate> disambiguationCandidates = cpeCandidates.stream()
                    .map(entry -> new Stage1AiArbitration.CpeDisambiguationCandidate(
                            entry.getProduct(), MaskedCpeString.ofRawCpeString(entry.getCpeString())))
                    .toList();
            Optional<DisambiguateResponse> result = aiArbitration.disambiguateCpeCandidates(item, userId, disambiguationCandidates);

            if (result.isEmpty()) {
                // No AI verdict available at all (no key, exhausted budget, or the LLM call itself
                // failed) — degrade to the pre-Tier2 best-effort behavior.
                chosenCpe = degradeToFirstCpeCandidateUnlessRelaxedContainmentDerived(
                        item, cpeCandidates, cpeCandidatesAreRelaxedContainmentDerived);
            } else if (!result.get().matched()) {
                chosenCpe = null;
                cpeCandidateCount = null;
                cpeCandidateVariantDerived = null;
                method = IdentifiedProduct.METHOD_LLM_DISAMBIGUATE;
            } else if (result.get().selectedIndex() != null
                    && result.get().selectedIndex() >= 0
                    && result.get().selectedIndex() < cpeCandidates.size()) {
                chosenCpe = cpeCandidates.get(result.get().selectedIndex());
                method = IdentifiedProduct.METHOD_LLM_DISAMBIGUATE;
                disambiguationConfidence = BigDecimal.valueOf(result.get().confidence());
            } else {
                log.warn("LLM disambiguate returned an invalid selection for item {}: {}", item.getId(), result.get());
                chosenCpe = degradeToFirstCpeCandidateUnlessRelaxedContainmentDerived(
                        item, cpeCandidates, cpeCandidatesAreRelaxedContainmentDerived);
            }
            if (chosenCpe == null) {
                cpeCandidateCount = null;
                cpeCandidateVariantDerived = null;
            }
        } else if (cpeCandidates.size() == 1) {
            Optional<ChosenCpe> chosen = resolveSingleCpeCandidate(item, userId, cpeCandidates.get(0), cpeCandidatesAreVariantDerived);
            if (chosen.isPresent()) {
                chosenCpe = chosen.get().entry();
                cpeCandidateCount = 1;
                cpeCandidateVariantDerived = cpeCandidatesAreVariantDerived;
                if (chosen.get().aiConfidence() != null) {
                    disambiguationConfidence = chosen.get().aiConfidence();
                    method = IdentifiedProduct.METHOD_LLM_DISAMBIGUATE;
                }
            }
        }

        // A registry match is only as trustworthy as its corroboration. Two mitigations, cheapest
        // first:
        //   1. If a CPE match already corroborates a *specific* different product, trust that
        //      over an unconfirmed registry hit outright — no LLM call needed (see
        //      trustRegistryMatch below).
        //   2. Otherwise (no CPE to cross-check against), ask the LLM to judge the single
        //      candidate against the item's usage_text — same anti-hallucination shape as Tier2's
        //      CPE disambiguation (index-select only, never invents a new package). This fires for
        //      an *unconfirmed* match (generic short/common product names collide with unrelated
        //      same-named packages surprisingly often — observed live across npm/PyPI/NuGet:
        //      "gson"/"gin"/"PuTTY"/"Slack"/"Zoom" etc.) but also for a *confirmed* one, because
        //      "the version number happens to match" is not proof of product identity either —
        //      observed live: PyPI's "redis" (a Python client library) coincidentally ships a
        //      release numbered the same as the Redis *server* version in the CSV row, which would
        //      otherwise be accepted as version-confirmed/high-confidence with nothing to catch
        //      it. No Claude key configured (or job cost budget exhausted) degrades to the
        //      pre-existing best-effort behavior (trust the match) — this residual gap is real but
        //      unavoidable without either AI or a corroborating CPE.
        BigDecimal registryDisambiguationConfidence = null;
        if (registryMatch.isPresent() && chosenCpe == null && registryResolution.aiVerified()) {
            // Already arbitrated among multiple same-named registry candidates in
            // resolveRegistryMatch (same AI-arbitration pattern as CPE Tier2, just applied across
            // registries) — re-running the single-candidate weak-match check below would be a
            // redundant second AI call for a question already answered.
            registryDisambiguationConfidence = registryResolution.aiConfidence();
            log.info("Registry match for item {} (ecosystem={} package={}) already AI-arbitrated among "
                    + "multiple registry candidates — skipping the single-candidate weak-match check",
                    item.getId(), registryMatch.get().ecosystem(), registryMatch.get().packageName());
        } else if (registryMatch.isPresent() && chosenCpe == null) {
            RegistryMatch weakMatch = registryMatch.get();
            Optional<DisambiguateResponse> verdict = aiArbitration.verifyWeakRegistryMatchWithAi(item, userId, weakMatch);
            if (verdict.isEmpty()) {
                // REVISE item 3 (senior review 2026-08-26, job 38): no Claude key configured (or the
                // LLM call itself failed), so the AI-verdict path below never ran — but that doesn't
                // mean there's nothing to go on. Measured against real job data: of 19 items with an
                // unconfirmed registry match and no corroborating CPE, the ones with a non-blank item
                // *vendor* field are 14/14 WRONG (genuine same-named-but-different products, e.g.
                // "Slack" the desktop app matching crates.io's unrelated `slack` Rust crate), while
                // the ones with a blank/null vendor are 5/5 correct. A clean, measured split, so this
                // fires as a calibrated static rule — not a guess — rather than defaulting to "trust
                // it" the way this branch used to unconditionally. Only ever reachable here, i.e. only
                // when no AI verdict exists at all; an actual AI verdict (matched or not, the two
                // branches below) always takes precedence over this static rule.
                boolean itemHasVendor = item.getVendor() != null && !item.getVendor().isBlank();
                if (!weakMatch.exactVersionConfirmed() && itemHasVendor) {
                    log.info("Statically rejecting weak registry match for item {} (ecosystem={} package={}) — "
                            + "no AI verification available, version is unconfirmed, and item vendor '{}' is "
                            + "present (REVISE item 3: measured 14/14 wrong with a non-blank vendor vs 5/5 "
                            + "correct with a blank one)", item.getId(), weakMatch.ecosystem(),
                            weakMatch.packageName(), item.getVendor());
                    registryMatch = Optional.empty();
                    RescuedCpe rescued = rescueCpeAfterRegistryMatchRejected(
                            item, userId, vendorForCpeRescue, productNameForCpeRescue);
                    if (rescued != null) {
                        chosenCpe = rescued.entry();
                        cpeCandidateCount = rescued.candidateCount();
                        cpeCandidateVariantDerived = rescued.variantDerived();
                        log.info("Live CPE lookup after statically-rejected weak registry match found a "
                                + "fallback candidate for item {}: {}", item.getId(), chosenCpe.getCpeString());
                    }
                } else {
                    // No AI available, and either the version already came back confirmed or the
                    // item has no vendor field to weigh against it (the 5/5-correct case above) —
                    // degrade to trusting the weak match, same as before this fix.
                    log.info("No AI verification available for weak registry match on item {} (ecosystem={} package={}) "
                            + "— using it as a best-effort fallback", item.getId(), weakMatch.ecosystem(), weakMatch.packageName());
                }
            } else if (!verdict.get().matched()) {
                log.info("AI rejected weak registry match for item {} (ecosystem={} package={}) as implausible "
                        + "given the usage text — likely an unrelated same-named package",
                        item.getId(), weakMatch.ecosystem(), weakMatch.packageName());
                registryMatch = Optional.empty();
                RescuedCpe rescued = rescueCpeAfterRegistryMatchRejected(
                        item, userId, vendorForCpeRescue, productNameForCpeRescue);
                if (rescued != null) {
                    chosenCpe = rescued.entry();
                    cpeCandidateCount = rescued.candidateCount();
                    cpeCandidateVariantDerived = rescued.variantDerived();
                    log.info("Live CPE lookup after AI-rejected registry match found a fallback candidate "
                            + "for item {}: {}", item.getId(), chosenCpe.getCpeString());
                }
            } else {
                log.info("AI confirmed weak registry match for item {} (ecosystem={} package={})",
                        item.getId(), weakMatch.ecosystem(), weakMatch.packageName());
                registryDisambiguationConfidence = BigDecimal.valueOf(verdict.get().confidence());
            }
        }

        // Round-5 fix (senior review 2026-08-26): captured once, BEFORE any mutation of chosenCpe
        // below — recomputing this after nulling chosenCpe would flip it back to true (chosenCpe ==
        // null is itself one of the conditions that makes a match trustable), silently re-admitting
        // the very registry match this fix rejects, in a different shape.
        boolean trustRegistryMatch = registryMatch.isPresent()
                && (registryMatch.get().exactVersionConfirmed() || chosenCpe == null);
        if (registryMatch.isPresent() && !trustRegistryMatch) {
            log.info("Distrusting unconfirmed-version registry match for item {} (ecosystem={} package={}) — "
                    + "a CPE match already identifies this product, likely an unrelated same-named package",
                    item.getId(), registryMatch.get().ecosystem(), registryMatch.get().packageName());
            // Round-5 fix: the CPE that got this far may only have passed passesTargetSwGate BECAUSE
            // of this registry match's own ecosystem context (e.g. crates.io "slack" admitting
            // slack_morphism_project:slack_morphism, target_sw=rust) — now that the registry match
            // itself is being discarded as untrustworthy, that ecosystem context goes with it, so the
            // CPE must be re-checked against a bare no-registry-context gate before it's allowed to
            // survive on its own.
            if (chosenCpe != null && !passesTargetSwGate(chosenCpe, TargetSwContext.from(Optional.empty(), ""))) {
                log.info("Dropping CPE {} for item {} — it only passed the target_sw gate via the "
                        + "now-distrusted registry match's ecosystem context, so it cannot stand on its own",
                        chosenCpe.getCpeString(), item.getId());
                CpeDictionaryEntry discardedCpe = chosenCpe;
                chosenCpe = null;
                cpeCandidateCount = null;
                cpeCandidateVariantDerived = null;
                // Backlog item 176 (job 203 root-cause): discardedCpe only ever won the earlier
                // ranking because of the now-distrusted registry match's own ecosystem context — but
                // the OTHER candidates in the same cpeCandidates pool never depended on that context to
                // get into the pool in the first place (they're already-ranked, containment-passing
                // hits). Re-checking them against the same bare gate and taking the best surviving one
                // (list order = the existing rank, same "first in list" selection {@link
                // #degradeToFirstCpeCandidateUnlessRelaxedContainmentDerived} already uses elsewhere)
                // catches the case where a genuinely correct candidate (e.g. openssl:openssl) was
                // sitting right there the whole time, instead of silently going UNIDENTIFIED.
                chosenCpe = selectFallbackCpeCandidateAfterRegistryDistrust(discardedCpe, cpeCandidates);
                if (chosenCpe != null) {
                    log.info("Falling back to remaining CPE candidate {} for item {} after discarding {} — "
                            + "it independently passes the bare target_sw gate",
                            chosenCpe.getCpeString(), item.getId(), discardedCpe.getCpeString());
                    cpeCandidateCount = cpeCandidates.size();
                    cpeCandidateVariantDerived = cpeCandidatesAreVariantDerived;
                }
            }
        }

        if (!trustRegistryMatch && chosenCpe == null) {
            return Optional.empty();
        }

        IdentifiedProduct identifiedProduct = new IdentifiedProduct();
        identifiedProduct.setJobItemId(item.getId());
        identifiedProduct.setMethod(method);

        BigDecimal confidence = BigDecimal.ZERO;
        // Cheap half of the "confidence-lending" fix (senior review, 2026-08-26; the general
        // "confidence should be two separate fields" schema change stays deferred). A CPE candidate
        // only ever had to explain the item's *query* text (via plausibleContainmentOnly) to become
        // chosenCpe — never the specific package a *trusted* registry match actually resolved to,
        // which can legitimately differ (Tier2 registry arbitration, the CPE-rescue path's own
        // vendor/productName, or simply a registry search landing on a different-but-same-named
        // package than what was literally queried). Measured live: ~30 of 96 registry+CPE items in
        // job 35 had a wrong CPE riding along at the registry match's own high (typically 0.95)
        // confidence this way (e.g. "rayon" -> crayon_project:crayon, "django" ->
        // gofiber:django, "MediatR" -> m5t:mediatrix_4102s). Re-checking the chosen CPE against the
        // trusted match's own package name, through the same Fix-2-tightened containment gate,
        // catches this without touching the registry match's own confidence at all — a rejected CPE
        // here still leaves ecosystem/package/purl/confidence intact below, just with cpe=null
        // instead of a wrong one.
        if (chosenCpe != null && trustRegistryMatch) {
            RegistryMatch trustedMatch = registryMatch.get();
            if (!cpeCorroboratesRegistryPackage(item.getVendor(), chosenCpe, trustedMatch)) {
                log.info("Dropping CPE {} for item {} — it does not independently corroborate the trusted "
                        + "registry match's own package name (ecosystem={} package={}), so it must not "
                        + "ride along on that match's confidence", chosenCpe.getCpeString(), item.getId(),
                        trustedMatch.ecosystem(), trustedMatch.packageName());
                chosenCpe = null;
                cpeCandidateCount = null;
                cpeCandidateVariantDerived = null;
            }
        }
        if (trustRegistryMatch) {
            RegistryMatch match = registryMatch.get();
            identifiedProduct.setEcosystem(match.ecosystem());
            identifiedProduct.setPackageName(match.packageName());
            identifiedProduct.setPurl(match.purl());
            identifiedProduct.setVersionConfirmed(match.exactVersionConfirmed());
            confidence = registryDisambiguationConfidence != null ? registryDisambiguationConfidence : match.confidence();
            if (registryDisambiguationConfidence != null) {
                method = IdentifiedProduct.METHOD_LLM_DISAMBIGUATE;
                identifiedProduct.setMethod(method);
            }
        }
        if (chosenCpe != null) {
            identifiedProduct.setCpe(withItemVersion(chosenCpe.getCpeString(), item.getVersion()));
            identifiedProduct.setCpeCandidateCount(cpeCandidateCount);
            identifiedProduct.setCpeCandidateVariantDerived(cpeCandidateVariantDerived);
            if (disambiguationConfidence != null) {
                // CPE Tier2 actually ran an AI call and selected this candidate — the displayed
                // confidence must be *that* call's own stated number, not max()'d against an
                // unrelated static registry confidence. Blindly taking the larger of the two let a
                // static constant (e.g. registry confidence 0.95) silently win and be shown under a
                // method of llm_disambiguate, implying it reflects AI judgment it never actually
                // returned. Confirmed live: of 138 llm_disambiguate rows, 119 sat at exactly the
                // static 0.95/0.5 constants — the AI's own (usually lower, e.g. 0.7-0.9) confidence
                // was being silently discarded whenever the untouched registry number was bigger.
                confidence = disambiguationConfidence;
            } else {
                confidence = confidence.max(CPE_MATCH_CONFIDENCE);
            }
        }

        identifiedProduct.setConfidence(confidence);
        return Optional.of(identifiedProductRepository.save(identifiedProduct));
    }

    /**
     * Shared rescue path for both ways {@link #resolveCandidates} can decide a weak registry match
     * must not be trusted (the pre-existing AI-{@code matched=false} rejection, and REVISE item 3's
     * static no-AI-available rejection): the registry match being present is exactly what earlier
     * made {@link #fuzzyMatchCpe} skip its live NVD CPE lookup (see that method's own {@code
     * registryEcosystem} javadoc) — that assumption just broke. Retries now, forcing the live
     * lookup, so a real product (e.g. "Redis" the server, rejected as the unrelated PyPI "redis"
     * client) doesn't end up UNIDENTIFIED purely because the skip fired before the registry match
     * was known to be bogus.
     *
     * <p>Best-effort: takes the first candidate without a further disambiguation round, except for
     * the same "never auto-accept a lone variant-derived candidate" rule the main selection path
     * uses — a rescue lookup is just as capable of landing on a single name-variant guess. Multiple
     * rescue candidates keep the pre-existing best-effort behavior (take the first, no further AI
     * call); this rescue path has never been disambiguated, and widening that is out of scope here.
     *
     * @return the rescued CPE candidate plus its own candidate-pool provenance (measurement-only,
     *      see {@link RescuedCpe}), or {@code null} if the retried lookup still found nothing.
     */
    private RescuedCpe rescueCpeAfterRegistryMatchRejected(
            ResearchJobItem item, Long userId, String vendorForCpeRescue, String productNameForCpeRescue) {
        CpeCandidateResult rescueResult =
                fuzzyMatchCpe(vendorForCpeRescue, productNameForCpeRescue, userId, Optional.empty(), Optional.empty(),
                        item.getVersion());
        List<CpeDictionaryEntry> rescueCandidates = rescueResult.candidates();
        if (rescueCandidates.isEmpty()) {
            return null;
        }
        CpeDictionaryEntry rescueCandidate = rescueCandidates.get(0);
        Optional<ChosenCpe> chosen = (rescueCandidates.size() == 1 && rescueResult.variantDerived())
                ? resolveSingleCpeCandidate(item, userId, rescueCandidate, true)
                : Optional.of(new ChosenCpe(rescueCandidate, null));
        return chosen.map(c -> new RescuedCpe(c.entry(), rescueCandidates.size(), rescueResult.variantDerived()))
                .orElse(null);
    }

    /** Result of {@link #rescueCpeAfterRegistryMatchRejected}: {@code entry} is the rescued CPE
     *  itself; {@code candidateCount}/{@code variantDerived} are the rescue lookup's own
     *  candidate-pool provenance, carried only as far as {@link IdentifiedProduct#getCpeCandidateCount()}/
     *  {@link IdentifiedProduct#getCpeCandidateVariantDerived()} for measurement — never used in any
     *  confidence calculation. */
    private record RescuedCpe(CpeDictionaryEntry entry, int candidateCount, boolean variantDerived) {
    }

    /** Fix5 gate: whether {@code candidate} independently explains {@code trustedMatch}'s own
     *  package name, through the exact same {@link #explainsQuery} containment logic used
     *  everywhere else in this class — never a looser or bespoke check. A blank/unparseable
     *  registry package name can't meaningfully gate anything, so it defaults to trusting the CPE
     *  rather than blocking on a signal that isn't really there. */
    private boolean cpeCorroboratesRegistryPackage(String itemVendor, CpeDictionaryEntry candidate, RegistryMatch trustedMatch) {
        String normalizedRegistryQuery = normalizeForContainment(lastMeaningfulPackageSegment(trustedMatch.packageName()));
        if (normalizedRegistryQuery.isBlank()) {
            return true;
        }
        String normalizedItemVendor = normalizeForContainment(itemVendor);
        // Always the strict Direction 2 rule here (backlog item 89's pass-2 relaxation is
        // Stage1's own candidate-pool retrieval concern via plausibleContainmentOnly, not this
        // separate Fix5 corroboration check).
        return explainsQuery(normalizedItemVendor, normalizedRegistryQuery, candidate, candidate.getProduct(), false, true)
                || explainsQuery(normalizedItemVendor, normalizedRegistryQuery, candidate, candidate.getTitle(), true, true);
    }

    /**
     * Reduces a registry package name to its one meaningful identifying segment before it's used as
     * a containment query — e.g. a Maven coordinate ({@code "com.google.guava:guava"}) or a Go
     * module path ({@code "github.com/gin-gonic/gin"}) is mostly non-identity-bearing groupId/host
     * scaffolding (see {@link RegistryRoutingPolicy#stripHostPrefix} for the same reasoning applied
     * elsewhere), and running the *whole* coordinate through containment would spuriously fail on
     * that scaffolding the same way Fix 1/3 had to correct for it on the query side.
     */
    private String lastMeaningfulPackageSegment(String packageName) {
        if (packageName == null) {
            return "";
        }
        String stripped = RegistryRoutingPolicy.stripHostPrefix(packageName);
        int lastSeparator = Math.max(stripped.lastIndexOf(':'), stripped.lastIndexOf('/'));
        return lastSeparator >= 0 ? stripped.substring(lastSeparator + 1) : stripped;
    }

    /**
     * REVISE item 1 (senior review, PR #51): the multi-candidate branch of {@link
     * #resolveCandidates} has always degraded to {@code cpeCandidates.get(0)} whenever no AI verdict
     * arbitrated among the pool (no key, exhausted budget, a failed LLM call, or an invalid
     * selection index) — safe for a literal/strict-containment pool, but a relaxed-containment
     * -derived pool (see {@link CpeCandidateResult}'s own javadoc) is exactly as unverified a guess
     * as the single-candidate branch's name-variant case, which {@link #resolveSingleCpeCandidate}
     * already refuses to auto-accept without an AI verdict. Applies that same "drop rather than trust
     * an unverified guess" policy here instead of silently picking the first of several relaxed
     * -pass candidates (the Android Studio {@code google:android}/{@code motorola:android}/{@code
     * samsung:android} and Directory Opus {@code ca:directory}/{@code broadcom:directory} false
     * positives this fixes). Deliberately does NOT extend to a name-variant-derived pool — {@code
     * relaxedContainmentDerived} is {@code false} for that case, so this still returns {@code
     * cpeCandidates.get(0)} for it unchanged (backlog item 98, evaluated separately).
     */
    private CpeDictionaryEntry degradeToFirstCpeCandidateUnlessRelaxedContainmentDerived(
            ResearchJobItem item, List<CpeDictionaryEntry> cpeCandidates, boolean relaxedContainmentDerived) {
        if (!relaxedContainmentDerived) {
            return cpeCandidates.get(0);
        }
        log.info("No AI verdict available among {} relaxed-containment-derived CPE candidates for item {} — "
                + "dropping rather than trusting an unverified guess", cpeCandidates.size(), item.getId());
        return null;
    }

    /**
     * Backlog item 176 (job 203 root-cause): after a registry-distrust event discards {@code
     * discardedCpe} (the previously-chosen CPE, which only passed the target_sw gate via the
     * now-distrusted registry match's own ecosystem context — see the {@code trustRegistryMatch}
     * block in {@link #resolveCandidates}), re-checks the rest of the same {@code cpeCandidates}
     * pool against the bare (no-ecosystem-context) gate and returns the best surviving one.
     *
     * <p>{@code cpeCandidates} is already in ranked order (see {@link #rankAndGate}), so — same
     * "first candidate wins" selection {@link #degradeToFirstCpeCandidateUnlessRelaxedContainmentDerived}
     * already uses for its own best-effort degrade — this simply walks the list in order and takes
     * the first (i.e. best-ranked) one that isn't {@code discardedCpe} and independently passes the
     * bare gate. Deliberately does not touch the ranking itself (a real but separate, riskier
     * concern — see backlog item 176's own scope note): the premature-context ranking that let
     * {@code discardedCpe} outrank a correct candidate in the first place is left alone here.
     *
     * @return the best surviving candidate, or {@code null} if none of the others pass the bare gate
     *      either — the caller then correctly falls through to the existing UNIDENTIFIED outcome.
     */
    private CpeDictionaryEntry selectFallbackCpeCandidateAfterRegistryDistrust(
            CpeDictionaryEntry discardedCpe, List<CpeDictionaryEntry> cpeCandidates) {
        TargetSwContext bareContext = TargetSwContext.from(Optional.empty(), "");
        for (CpeDictionaryEntry candidate : cpeCandidates) {
            if (candidate == discardedCpe) {
                continue;
            }
            if (passesTargetSwGate(candidate, bareContext)) {
                return candidate;
            }
        }
        return null;
    }

    /** The (possibly AI-checked) result of {@link #resolveSingleCpeCandidate}: {@code aiConfidence}
     *  is non-null only when an AI call actually determined this candidate was correct, so the
     *  caller can attribute the displayed confidence/method to the real AI verdict rather than a
     *  static constant — same shape as {@link #resolveCandidates}'s own {@code
     *  disambiguationConfidence} handling for the multi-candidate Tier2 path. */
    private record ChosenCpe(CpeDictionaryEntry entry, BigDecimal aiConfidence) {
    }

    /**
     * A lone CPE candidate is normally trusted with zero AI spend — the pre-existing, high-precision
     * behavior for a literal dictionary/live-NVD match, left untouched here. But a candidate produced
     * by the name-variant search ({@code variantDerived=true}) is a mechanically-derived *guess*
     * about what an abbreviation/contraction refers to, not a corroborated hit — measured false
     * positives (senior review, 2026-08-25) showed both directions produce real wrong single-candidate
     * matches (e.g. "VM Player" -&gt; {@code vlc_media_player}, "AD Manager" -&gt; {@code
     * ams_device_manager}). Forces the same anti-hallucination AI check {@link
     * Stage1AiArbitration#verifyWeakRegistryMatchWithAi} already uses for a weak registry hit,
     * applied to this CPE case instead — but unlike that method, a missing verdict here (no key,
     * exhausted budget, or the call itself failing) drops the candidate entirely rather than
     * degrading to trusting it: today's real-world outcome for these items is UNIDENTIFIED, and
     * dropping preserves exactly that non-regression baseline instead of risking a confident wrong
     * CPE with nothing to catch it.
     */
    private Optional<ChosenCpe> resolveSingleCpeCandidate(
            ResearchJobItem item, Long userId, CpeDictionaryEntry candidate, boolean variantDerived) {
        if (!variantDerived) {
            return Optional.of(new ChosenCpe(candidate, null));
        }
        Optional<DisambiguateResponse> verdict = aiArbitration.verifyVariantDerivedCpeMatchWithAi(
                item, userId, candidate, MaskedCpeString.ofRawCpeString(candidate.getCpeString()));
        if (verdict.isEmpty()) {
            log.info("No AI verification available for name-variant-derived CPE candidate on item {} ({}) — "
                    + "dropping it rather than trusting an unverified guess", item.getId(), candidate.getCpeString());
            return Optional.empty();
        }
        if (!verdict.get().matched()) {
            log.info("AI rejected name-variant-derived CPE candidate for item {} ({}) as implausible given the usage text",
                    item.getId(), candidate.getCpeString());
            return Optional.empty();
        }
        log.info("AI confirmed name-variant-derived CPE candidate for item {} ({})", item.getId(), candidate.getCpeString());
        return Optional.of(new ChosenCpe(candidate, BigDecimal.valueOf(verdict.get().confidence())));
    }

    /**
     * Replaces a dictionary candidate's cataloged version with the item's real version before
     * persisting. The dictionary match is a vendor/product text match only (pg_trgm doesn't
     * compare versions), so the candidate's own version is essentially arbitrary/historical —
     * persisting it verbatim looked like a bug to a human reading the results (e.g. a CSV row for
     * Wireshark 4.6.0 showing `cpe:...:wireshark:0.99.2:...`), even though Stage2 already ignored
     * it and substituted the real version internally. This makes the persisted value match what
     * Stage2 actually queries with, so the displayed CPE is truthful.
     */
    private String withItemVersion(String cpeString, String itemVersion) {
        // REVISE item 6 (senior review, job 36 root-cause): must preserve every trailing segment
        // (update, edition, language, sw_edition, target_sw, target_hw, other) from the dictionary
        // candidate's own CPE string, not just vendor/product — a candidate scoped by target_sw
        // (e.g. a Jenkins plugin) has a real NVD CPE only *with* that scoping; silently resetting it
        // to "*" via CpeUtils.buildCpe produced a CPE string that doesn't actually exist in NVD.
        return CpeUtils.withVersion(cpeString, itemVersion);
    }

    /**
     * Outcome of {@link #resolveCpeCandidates}: {@code variantDerived} tells {@link
     * #resolveCandidates} whether every entry in {@code candidates} came from the name-variant
     * search ({@link #findByNameVariants}) rather than a literal dictionary/live-NVD hit — OR
     * (backlog item 89 P2) from {@link #plausibleContainmentOnly}'s relaxed second pass, which is
     * just as much a mechanically-looser guess as a name-variant match and gets exactly the same
     * "never auto-trust a lone AI-unverified candidate" treatment downstream (see {@link
     * #resolveSingleCpeCandidate}). The two provenances are never mixed within one result — either
     * the containment search's own first (strict) pass already succeeded, in which case this is
     * {@code false} and nothing here is variant/pass2-derived at all, or it didn't, in which case
     * every surviving candidate came from whichever single fallback (relaxed containment, or later
     * the name-variant search) actually produced this list — so a single flag for the whole list is
     * enough; no per-entry provenance tracking is needed.
     *
     * <p>REVISE item 1 (senior review, PR #51): {@code relaxedContainmentDerived} narrows
     * {@code variantDerived} down to specifically the relaxed-containment provenance, leaving the
     * name-variant-search provenance out — {@code true} in exactly the same cases {@code
     * variantDerived} is {@code true} via {@link LocalCpeMatches#usedRelaxedPass()} /
     * {@link ContainmentResult#usedRelaxedPass()}, but {@code false} (unlike {@code variantDerived})
     * when the pool came from {@link #findByNameVariants} instead. {@link #resolveCandidates}'s
     * multi-candidate branch needs this distinction because its pre-existing "no AI verdict, take
     * {@code get(0)}" degrade behavior must NOT apply to a relaxed-containment-derived pool (the
     * Android Studio / Directory Opus false positives this fixes), but must be left exactly as-is
     * for a name-variant-derived pool (backlog item 98, evaluated separately) — {@code
     * variantDerived} alone can't tell those two apart, and is deliberately left with its existing
     * meaning/behavior everywhere else (the single-candidate branch, {@link
     * #resolveSingleCpeCandidate}) rather than repurposed.
     */
    // Package-private (not private): referenced from Stage1AiArbitration's CpeCandidateLookup/
    // IdentificationMerger functional-interface parameters (see that class's own javadoc for why
    // tryTier3 needs method-reference callbacks rather than a constructor-injected back-reference).
    record CpeCandidateResult(
            List<CpeDictionaryEntry> candidates, boolean variantDerived, boolean relaxedContainmentDerived) {
    }

    /**
     * Fuzzy-matches against the local {@code cpe_dictionary} mirror first (fast, free); if that
     * mirror has nothing at all for this product — the common case for anything nobody has synced
     * a keyword for yet — falls back to a single live, rate-limited NVD CPE API call so an unknown
     * product can still be resolved instead of silently requiring a pre-sync, UNLESS
     * {@code registryEcosystem} is present (a registry match already confirmed this product is real
     * and already gives Stage2 vulnerability coverage via OSV/GHSA) — in that case the live round
     * trip is skipped and this returns empty rather than spending ~6.5s (or ~0.7s with an NVD key)
     * per item on a source that's merely supplementary here. Hits from the live call are upserted
     * into the local dictionary, so this also warms the cache for next time.
     *
     * <p>{@code registryEcosystem} doubles as the signal {@link #resolveCpeCandidates} needs for
     * the REVISE item 1/3 target_sw gate/ranking preference (empty when there's no registry match at
     * all, e.g. desktop software with nothing to map). {@code registryPackageName} is that same
     * registry match's own resolved package name, used only for REVISE item 1's exact-slug-match
     * ranking preference — likewise empty whenever there's no registry match to draw one from.
     */
    private CpeCandidateResult fuzzyMatchCpe(String vendor, String productName, Long userId,
            Optional<String> registryEcosystem, Optional<String> registryPackageName, String itemVersion) {
        return resolveCpeCandidates(vendor, productName, userId, registryEcosystem, registryPackageName,
                localCpeLookup(vendor, productName, itemVersion), itemVersion);
    }

    /** Just the local-dictionary half of {@link #fuzzyMatchCpe} — DB-only, no network, literal
     *  matches only (the name-variant search is a separate, later-stage last resort — see {@link
     *  #resolveCpeCandidates}) — split out so {@link #identify} can call it before the registry
     *  fan-out has run (and thus before the {@code registryEcosystem} this method's caller needs is
     *  known — see {@code identify}'s own javadoc for why the two used to run concurrently for
     *  exactly this reason, before closed-mode backlog item 193/B3 removed the network round trip
     *  that made overlapping them worthwhile). Ranked here with no target_sw preference (that
     *  context genuinely isn't known yet at this point) and, critically, ranked but NOT truncated
     *  down to {@value #CPE_CANDIDATE_LIMIT} yet — {@code limit}
     *  is passed as {@value #CPE_CANDIDATE_POOL} here, not {@value #CPE_CANDIDATE_LIMIT}. {@link
     *  #resolveCpeCandidates} re-ranks/gates with the real ecosystem once it's known via {@link
     *  #rankAndGate}, and THAT is the one place allowed to cut down to the final {@value
     *  #CPE_CANDIDATE_LIMIT}, strictly after its target_sw gate has run.
     *
     *  <p>REVISE item 1 (senior review 2026-08-26, job 38 root-cause — the {@code http}/crates.io
     *  bug): this method previously truncated to {@value #CPE_CANDIDATE_LIMIT} right here, before any
     *  ecosystem/target_sw context existed to gate on. Measured live: crates.io {@code http}'s
     *  ungated candidate pool, all tied at exact-slug rank, is {@code [ktat, ietf, dart, hyper,
     *  reactphp, tokuhirom]} — truncating to 3 *first* kept only {@code [ktat, ietf, dart]}, and only
     *  then did {@link #rankAndGate}'s gate get a chance to drop {@code ktat} (target_sw=perl) and
     *  {@code dart} (target_sw=dart); with the real answer, {@code hyper:http} (target_sw=rust),
     *  already discarded before the gate ever ran, the surviving {@code ietf:http} — merely untagged
     *  rather than actually correct — won by default. Ranking the full pool here and deferring the
     *  cut to after gating in {@link #rankAndGate} is what lets {@code hyper:http} survive to be
     *  correctly chosen once the crates.io ecosystem context is known.
     *
     *  <p>Backlog item 89 P2: returns {@link LocalCpeMatches} rather than a bare list so {@link
     *  #resolveCpeCandidates} can learn whether {@link #plausibleContainmentOnly}'s relaxed second
     *  pass is what actually produced {@code candidates} here — see that method's own javadoc. */
    private LocalCpeMatches localCpeLookup(String vendor, String productName, String itemVersion) {
        List<CpeDictionaryEntry> pool = cpeDictionaryRepository.findFuzzyMatches(
                productName, CPE_PRODUCT_SIMILARITY_THRESHOLD, CPE_TITLE_SIMILARITY_THRESHOLD, CPE_CANDIDATE_POOL);
        ContainmentResult containment = plausibleContainmentOnly(vendor, productName, pool);
        List<CpeDictionaryEntry> ranked = rankCpeCandidates(
                vendor, productName, containment.candidates(), Optional.empty(), CPE_CANDIDATE_POOL, itemVersion);
        return new LocalCpeMatches(ranked, containment.usedRelaxedPass());
    }

    /** Backlog item 89 P2: pairs {@link #localCpeLookup}'s ranked candidate list with whether {@link
     *  #plausibleContainmentOnly}'s relaxed second pass (rather than its strict first pass) is what
     *  produced it — carried through {@link #resolveCpeCandidates} into {@link
     *  CpeCandidateResult#variantDerived}, the same forced-AI-verification treatment a name-variant
     *  match already gets. */
    private record LocalCpeMatches(List<CpeDictionaryEntry> candidates, boolean usedRelaxedPass) {
    }

    /**
     * Generalized short-form&lt;-&gt;long-form candidate generation — a genuine last resort, tried
     * by {@link #resolveCpeCandidates} only after *both* the literal pg_trgm+containment search and
     * the live NVD fallback have already come back empty for this item (senior review, 2026-08-25:
     * this used to run one step earlier, inside {@link #localCpeLookup} itself, whenever the literal
     * search alone found nothing — which meant producing *a* candidate here, even a wrong one, was
     * enough to make {@link #resolveCpeCandidates} think local matches existed and skip the live NVD
     * fallback and Tier3 entirely, silently suppressing two strictly better fallback stages). Never
     * runs in addition to an already-successful literal or live-NVD match, so the common case pays
     * nothing extra. Confirmed live 2026-08-25 that plain trigram similarity misses this shape of
     * match in both directions no matter the query text tried ("VS Code", "Code" alone, and the full
     * expanded name all score under threshold against {@code visual_studio_code}), so this needs its
     * own retrieval strategy, not just a lower threshold.
     *
     * <p>Two independent, mechanical directions — not a hardcoded table of specific product-name
     * pairs — plus a related vendor-prefix strip:
     * <ul>
     *   <li><b>Contraction</b> (long form -&gt; acronym): "GNU Image Manipulation Program" -&gt;
     *       "GIMP" ({@link NameVariantGenerator#contractToAcronym}). Requires an exact product-slug
     *       match ({@link #acronymVariantSearch}) rather than the literal query's containment check
     *       — a synthetic few-letter acronym has no word-boundary protection of its own, see that
     *       method's own javadoc.</li>
     *   <li><b>Vendor-prefix strip</b>: a product name that literally begins with the item's own
     *       vendor field (e.g. "Broadcom Norton 360") retried on the remainder — the local-dictionary
     *       counterpart of {@link #liveNvdCpeLookupWithFallback}'s "drop a word, retry" shape. Re-runs
     *       the same trigram+containment pipeline the literal query already used, since a real vendor
     *       -stripped remainder is a real (if partial) product name, not a synthetic string.</li>
     *   <li><b>Expansion</b> (abbreviation + word -&gt; long form): "VS Code" -&gt; the dictionary's
     *       own {@code visual_studio_code} ({@link #expandLeadingInitialism}) — fundamentally
     *       different from the other two since it can't be reduced to an alternate query string for
     *       the same trigram pipeline (see that method's own javadoc).</li>
     * </ul>
     *
     * <p>Every candidate this produces is still only ever a *guess*, never auto-trusted the way a
     * literal match is — see {@link #resolveSingleCpeCandidate}'s forced AI check for a lone
     * variant-derived candidate.
     *
     * <p>Bounded to at most {@value #MAX_NAME_VARIANT_QUERIES_PER_ITEM} extra local-dictionary
     * queries per item (stops at the first direction that finds anything) and memoized per
     * (vendor, productName) via {@link #cpeNameVariantCache} for the rest of this process's life —
     * this project's CSVs repeat the same product name across many version-duplicate rows, so a
     * job that pays for this once for "VS Code" should not pay for it again on every other row (see
     * {@link RegistryLookupCache}'s own precedent for the same reasoning).
     */
    private List<CpeDictionaryEntry> findByNameVariants(String vendor, String productName) {
        return cpeNameVariantCache.get(vendor, productName, () -> computeNameVariantMatches(vendor, productName));
    }

    private List<CpeDictionaryEntry> computeNameVariantMatches(String vendor, String productName) {
        int queriesLeft = MAX_NAME_VARIANT_QUERIES_PER_ITEM;

        String acronym = NameVariantGenerator.contractToAcronym(productName);
        if (acronym != null) {
            List<CpeDictionaryEntry> viaContraction = acronymVariantSearch(acronym);
            queriesLeft--;
            if (!viaContraction.isEmpty()) {
                return viaContraction;
            }
        }
        if (queriesLeft <= 0) {
            return List.of();
        }

        String vendorStripped = NameVariantGenerator.stripLeadingVendor(productName, vendor);
        if (vendorStripped != null) {
            List<CpeDictionaryEntry> viaVendorStrip = literalVariantSearch(vendor, vendorStripped);
            queriesLeft--;
            if (!viaVendorStrip.isEmpty()) {
                return viaVendorStrip;
            }
        }
        if (queriesLeft <= 0) {
            return List.of();
        }

        return expandLeadingInitialism(productName);
    }

    /**
     * Contraction-direction candidate search: unlike {@link #literalVariantSearch} (used for the
     * vendor-strip direction), a mechanically-derived acronym is deliberately NOT run through {@link
     * #plausibleContainmentOnly}'s unanchored substring check. That check is calibrated for real (if
     * abbreviated) product names sharing actual words with a candidate; it's unsafe for a synthetic
     * few-letter string with no word-boundary protection of its own. Measured false positives
     * (senior review, 2026-08-25): 7 of 8 real acronym-direction candidates tested were wrong when
     * routed through containment (e.g. "animal-sniffer-annotations" -&gt; {@code pix_asa},
     * "javax.servlet-api" -&gt; {@code jsa1500}) — the same false-positive class already fixed for
     * "failureaccess" -&gt; {@code microsoft:access}. Requires the candidate's normalized product
     * slug to equal the acronym exactly instead: safe for any acronym length, since there is no
     * partial-credit path left to exploit.
     */
    private List<CpeDictionaryEntry> acronymVariantSearch(String acronym) {
        List<CpeDictionaryEntry> pool = cpeDictionaryRepository.findFuzzyMatches(
                acronym, CPE_PRODUCT_SIMILARITY_THRESHOLD, CPE_TITLE_SIMILARITY_THRESHOLD, CPE_CANDIDATE_POOL);
        return pool.stream()
                .filter(entry -> acronym.equals(normalizedProductSlug(entry)))
                .toList();
    }

    private String normalizedProductSlug(CpeDictionaryEntry entry) {
        return entry.getProduct() == null ? "" : entry.getProduct().toLowerCase(java.util.Locale.ROOT);
    }

    /** Re-runs the same trigram-search + containment pipeline {@link #localCpeLookup} uses on the
     *  literal query, but against an alternate query string (a vendor-stripped remainder) instead of
     *  the item's raw product name. NOT used for the contraction/acronym direction — see {@link
     *  #acronymVariantSearch}'s javadoc for why a synthetic acronym needs a stricter check.
     *
     *  <p>Discards {@link ContainmentResult#usedRelaxedPass} deliberately: every candidate this
     *  method can ever produce already gets forced AI verification regardless (see {@link
     *  #resolveCpeCandidates}'s name-variant branch, which sets {@code variantDerived} unconditionally
     *  whenever this whole search direction finds anything at all), so there is no separate flag to
     *  carry through here. */
    private List<CpeDictionaryEntry> literalVariantSearch(String vendor, String variantQuery) {
        List<CpeDictionaryEntry> pool = cpeDictionaryRepository.findFuzzyMatches(
                variantQuery, CPE_PRODUCT_SIMILARITY_THRESHOLD, CPE_TITLE_SIMILARITY_THRESHOLD, CPE_CANDIDATE_POOL);
        return plausibleContainmentOnly(vendor, variantQuery, pool).candidates();
    }

    /**
     * Initialism-expansion direction of name-variant matching: "VS Code" -&gt; the dictionary's own
     * {@code visual_studio_code}. Can't be reduced to "try this alternate query string against the
     * usual trigram pipeline" like {@link #literalVariantSearch} — confirmed live 2026-08-25, no
     * variant of the query text scores high enough on either product/title trigram similarity
     * ({@code similarity('visual_studio_code','vs code')} = 0.29, {@code
     * similarity('visual_studio_code','code')} = 0.26, both under the 0.3 threshold — an
     * underscore-joined slug is just too different, character-for-character, from either form of an
     * abbreviated query). Instead:
     *
     * <ol>
     *   <li>Treats the query's leading token as a possible abbreviation (bounded to {@value
     *       #MIN_INITIALISM_LENGTH}-{@value #MAX_INITIALISM_LENGTH} characters — long enough to
     *       carry real signal, short enough that a real first *word* doesn't get treated as one) and
     *       the rest of the query as the "anchor" phrase, requiring the anchor be at least {@value
     *       #MIN_ANCHOR_LENGTH_FOR_INITIALISM_EXPANSION} characters (see that constant's javadoc —
     *       shorter anchors can't use the trigram index the SQL query below relies on).</li>
     *   <li>Finds candidates whose {@code product} slug's leading per-word initials spell the
     *       abbreviation and are immediately followed by the anchor, via a left-anchored SQL regex
     *       built directly from the abbreviation and anchor (see {@link
     *       com.vulncheck.app.repository.CpeDictionaryRepositoryCustom#findByLeadingInitialismMatch}),
     *       capped at {@value #NAME_VARIANT_ANCHOR_SEARCH_LIMIT}.</li>
     *   <li>Re-applies the same initials check in Java ({@link #leadingInitialsMatch}) as a safety
     *       net after the SQL-level filter — "visual studio" -&gt; "vs". Verified against the real
     *       dictionary: of 424 distinct products whose slug contains "code", exactly 4 satisfy this
     *       for "vs", and all 4 are genuinely Visual Studio Code or one of its extensions.</li>
     * </ol>
     */
    private List<CpeDictionaryEntry> expandLeadingInitialism(String productName) {
        List<String> queryTokens = tokenize(normalizeForContainment(productName));
        if (queryTokens.size() < 2) {
            return List.of();
        }
        String abbreviation = queryTokens.get(0);
        if (abbreviation.length() < MIN_INITIALISM_LENGTH || abbreviation.length() > MAX_INITIALISM_LENGTH) {
            return List.of();
        }
        List<String> anchorTokens = queryTokens.subList(1, queryTokens.size());
        String anchor = String.join("_", anchorTokens);
        if (anchor.length() < MIN_ANCHOR_LENGTH_FOR_INITIALISM_EXPANSION) {
            return List.of();
        }

        List<CpeDictionaryEntry> pool = cpeDictionaryRepository.findByLeadingInitialismMatch(
                abbreviation, anchor, NAME_VARIANT_ANCHOR_SEARCH_LIMIT);
        return pool.stream()
                .filter(entry -> leadingInitialsMatch(abbreviation, anchorTokens, entry))
                .toList();
    }

    /** @return whether {@code entry}'s product-slug words immediately preceding the {@code
     *  anchorTokens} occurrence spell {@code abbreviation} letter-for-letter, one letter per word —
     *  the signal that separates "VS Code" -&gt; {@code visual_studio_code} (real) from a coincidental
     *  anchor-word overlap with something unrelated. */
    private boolean leadingInitialsMatch(String abbreviation, List<String> anchorTokens, CpeDictionaryEntry entry) {
        List<String> productTokens = tokenize(normalizeForContainment(entry.getProduct()));
        int start = java.util.Collections.indexOfSubList(productTokens, anchorTokens);
        if (start <= 0) {
            // start == 0: the anchor is the product's very first word — nothing left for the
            // abbreviation to explain, so this isn't the initialism-expansion shape at all.
            // start < 0: the anchor phrase isn't even present as contiguous tokens.
            return false;
        }
        StringBuilder initials = new StringBuilder();
        for (int i = 0; i < start; i++) {
            String token = productTokens.get(i);
            if (token.isEmpty()) {
                return false;
            }
            initials.append(token.charAt(0));
        }
        return initials.toString().equals(abbreviation);
    }

    /**
     * De-duplicates the wide {@value #CPE_CANDIDATE_POOL}-row pool down to one best row per distinct
     * product and ranks them, preferring ones whose CPE vendor agrees with the vendor the user typed.
     * Truncates to {@code limit} entries only at the very end — callers control how far down that
     * happens, and MUST NOT pass {@value #CPE_CANDIDATE_LIMIT} here until after {@link
     * #passesTargetSwGate} has already run over the full ranked list (see {@link #rankAndGate}); see
     * {@link #localCpeLookup}'s own javadoc for the measured {@code http}/crates.io bug this
     * ordering requirement exists to prevent.
     *
     * <p>Callers that need the small final {@value #CPE_CANDIDATE_LIMIT}-row list handed to Tier2/3
     * should call {@link #rankAndGate} instead of this method directly, so the gate is never skipped.
     *
     * <p>Two separate problems are solved here, both measured against real data 2026-08-24:
     * <ul>
     *   <li><b>Version-duplicate rows.</b> The dictionary stores one row per catalogued version,
     *       so a single product can occupy the entire candidate window (TeamViewer has dozens of
     *       rows). De-duplicating on vendor:product means the three candidates Tier2 eventually
     *       sees are three genuinely different products, not the same one three times.</li>
     *   <li><b>Vendor as a ranking signal, never as query text.</b> The old code concatenated the
     *       vendor into the pg_trgm query itself, which was actively harmful: for "Amazon Web
     *       Services TeamViewer", the vendor words scored {@code amazon_web_services_aws-c-io}
     *       (0.51) and {@code amazon_web_services_freertos} (0.50) above the real
     *       {@code teamviewer} (0.35), so with a 3-row window the correct product never surfaced
     *       at all and the item came back UNIDENTIFIED. Confirmed as the cause of a whole class of
     *       misses (TeamViewer, Microsoft Teams, ... all present in the dictionary yet
     *       unidentified). Vendor agreement is a weak *bonus* — a mismatch never rejects a
     *       candidate, since real-world vendor columns are frequently blank, wrong, or a
     *       reseller/parent-company name rather than the CPE vendor slug.</li>
     * </ul>
     *
     * <p>REVISE item 3 (senior review, job 36 root-cause): {@code mappedTargetSw} — the item's own
     * ecosystem's mapped {@code target_sw} value (see {@link #ECOSYSTEM_TO_TARGET_SW}), present
     * only when there's a registry match on a mapped ecosystem — is a ranking signal positioned
     * <em>behind</em> the exact-product-slug-match signal below but still <em>ahead of</em> {@code
     * vendorAgrees}: it's what makes rubygems "puma" prefer {@code puma:puma} over an unrelated
     * {@code intel:puma}-shaped candidate, and npm "uuid" prefer {@code uuidjs:uuid} over {@code
     * satori:uuid}, when vendor agreement alone can't distinguish them (the item's own vendor field
     * is often blank or unhelpful for a bare package name). Never a hard requirement — see {@link
     * #passesTargetSwGate} for the actual hard-reject gate.
     *
     * <p>REVISE item 1 (senior review, job 37 root-cause): {@code exactMatchQuery}'s normalized text
     * exactly equaling a candidate's normalized product slug is the <em>primary</em> sort key, ahead
     * of even {@code mappedTargetSw} — demoted from behind it, where round 2 had put it. Round 2's
     * ordering let a merely target_sw-agreeing but otherwise wrong sub-package
     * ({@code bigcat88:pillow-heif}, {@code rails_admin_project:rails_admin}, {@code
     * matrix:react_sdk}, {@code mhenrixon:sidekiq-unique-jobs}, {@code
     * typescript_deep_merge_project:typescript_deep_merge}) outrank the real, exactly-named
     * canonical package purely because target_sw happened to line up too. An exact slug match is
     * strictly stronger evidence of identity than a platform-scoping hint ever is, so it must win
     * first. {@link #passesTargetSwGate}'s hard rejection of a genuinely wrong-platform candidate is
     * unaffected by this reordering — this only changes which of several <em>already-gated-in</em>
     * candidates sorts first.
     *
     * <p>golden-300 fix (2026-08-29, item 3 "part=o excluded from the candidate pool"): {@code
     * part=o} (operating system) candidates are admitted as a fallback, but ONLY when the pool has
     * zero {@code part=a} candidates at all — see {@link #isApplicationPart}'s javadoc for why this
     * is safe. The job 37 incident this class's {@code part=a}-only gate was built to fix
     * (REVISE item 6 below) was a hardware CPE ({@code cpe:2.3:h:corsair:commander_pro}) outscoring
     * *genuine, present* software candidates on raw text similarity — i.e. the bug was a wrong
     * candidate crowding out a right one that already existed in the pool, not a right candidate
     * being altogether absent. This fallback only ever fires in the latter situation (no {@code
     * part=a} row exists anywhere in the pool), which structurally cannot recreate the former: a
     * real application CPE, whenever one is present, is always preferred and this fallback never
     * even runs. It's needed because some real, in-scope products — PAN-OS, MikroTik RouterOS — are
     * catalogued by NVD only as {@code part=o}, with no {@code part=a} entry at all (measured
     * 2026-08-30: 779 PAN-OS rows and 744 MikroTik RouterOS rows in the dictionary, zero
     * {@code part=a} among either), so the pre-fix gate silently discarded the only candidate that
     * could ever have identified them. {@code part=h} (hardware) stays excluded unconditionally
     * either way — the job 37
     * incident was specifically about hardware, and network-device software update advisories are
     * never filed against hardware CPEs.
     *
     * <p>Backlog item 15, P2 (senior review 2026-08-30): {@link #versionCoverageIsPlausible} is
     * inserted <em>after</em> {@code exactProductSlugMatch}/{@code targetSwMatchesEcosystem} but
     * <em>before</em> {@code vendorAgrees}. After exact-slug/target_sw (both job 37 REVISE item 1's
     * own ordering, left untouched) because this tie-break must never be allowed to demote a
     * candidate that already won on stronger textual/ecosystem evidence — inserting it any earlier
     * would risk re-litigating job 37 REVISE item 1's own fix. Its exact position relative to
     * {@code vendorAgrees} is the part that actually matters in the Audacity false positive this
     * tie-break was built for: both candidates ({@code audacity:audacity} and the correct
     * {@code audacityteam:audacity}) tie on every other key in the chain, including
     * {@code vendorAgrees} itself — golden-300's own vendor string for this item is "Audacity
     * Team", and {@link #containsEitherWay}'s bidirectional partial match makes both candidates'
     * vendor slugs ("audacity" and "audacityteam") match it, so {@code vendorAgrees} is {@code
     * true} for both and cannot break the tie. {@code versionCoverageIsPlausible} is the only
     * remaining signal that can, which is exactly why it has to sit somewhere in this chain at
     * all: the wrong candidate ({@code audacity:audacity}) is catalogued in the dictionary as a
     * single row at version 1.2.6 (max cataloged major 1), while the item's own version is in the
     * 3.7.x line — concrete numeric evidence that candidate's catalogue coverage cannot possibly
     * be current, which a same-named-vendor overlap alone never carries.
     *
     * <p>Backlog item 89 (senior review 2026-08-30, real job195/196 data): three more keys inserted
     * into the chain — {@code exactSlug -> targetSw -> K1 -> K2 -> versionPlausible -> vendorAgrees
     * -> K3} — to close a further four golden-300 misses without any AI spend:
     * <ul>
     *   <li><b>K1</b> ({@link #unexplainedQueryTokenCount}, ascending): how many of the query's own
     *       tokens neither the candidate's own text nor its CPE vendor account for. Fixes Adobe
     *       Acrobat Reader DC — {@code exactSlug}/{@code targetSw} tie between {@code
     *       adobe:acrobat_reader_dc} and {@code adobe:acrobat_reader} (the query "Adobe Acrobat
     *       Reader DC" doesn't equal either candidate's bare product slug), but only the wrong,
     *       shorter candidate leaves "dc" unexplained.</li>
     *   <li><b>K2</b> ({@link #versionCoverageRank}, ascending {@code COVERS(0) < UNKNOWN(1) <
     *       NOT_COVERS(2)}): a 3-value sibling of {@code versionPlausible}'s boolean soft check,
     *       inserted <em>ahead of</em> {@code vendorAgrees} rather than merely near it, specifically
     *       because {@code vendorAgrees} would otherwise win these ties for the wrong reason — e.g.
     *       PDF-XChange Editor 10.2.1's item {@code vendor} field is literally "Tracker Software
     *       Products", which makes {@code vendorAgrees} favor the wrong, version-stale {@code
     *       tracker-software:pdf-xchange_editor} (max cataloged major 9) over the correct {@code
     *       pdf-xchange:pdf-xchange_editor} (max cataloged major 10, actually covers the item).
     *       Fixes Node.js the same way ({@code nodejs:node.js} covers major 20, {@code
     *       joyent:node.js} has no cataloged evidence at all).</li>
     *   <li><b>K3</b> ({@link #catalogedRowCount}, descending, the final tie-break): Greenshot
     *       1.3.290 ties {@code getgreenshot:greenshot} and {@code greenshot:greenshot} on every key
     *       above (both are exact-slug, both contain "greenshot" in their own CPE vendor so {@code
     *       vendorAgrees} is true for both), leaving only which pair NVD has actually catalogued 80
     *       rows for versus 1 to break the tie — a real coin-flip on {@code id} otherwise.</li>
     * </ul>
     * Performance (required by the same backlog item): every key above is now computed exactly once
     * per candidate, into a {@link RankedCandidate} record, before sorting — not recomputed inside
     * the {@link java.util.Comparator} on every one of the O(n log n) comparisons the way the
     * pre-existing keys always were. K1 in particular re-tokenizes text, so leaving it comparator-side
     * would have made the existing re-normalization cost newly visible at this candidate-pool size.
     */
    private List<CpeDictionaryEntry> rankCpeCandidates(String vendor, String exactMatchQuery,
            List<CpeDictionaryEntry> candidates, Optional<String> mappedTargetSw, int limit, String itemVersion) {
        java.util.LinkedHashMap<String, CpeDictionaryEntry> bestPerProduct = new java.util.LinkedHashMap<>();
        java.util.LinkedHashMap<String, CpeDictionaryEntry> bestOsPerProductFallback = new java.util.LinkedHashMap<>();
        for (CpeDictionaryEntry entry : candidates) {
            // REVISE item 6 (senior review, job 37 root-cause): a CPE Dictionary row can be for
            // hardware or an operating system just as easily as an application — NVD really does
            // catalogue cpe:2.3:h:corsair:commander_pro alongside every software "commander"-named
            // product, and no text-matching heuristic anywhere else in this class can ever be a
            // legitimate reason to attach a hardware/OS CPE to a software inventory item. Filtered
            // here, the one choke point every candidate-producing path (literal search, live NVD
            // fallback, name-variant search) already funnels through via rankAndGate.
            if (isApplicationPart(entry)) {
                // Candidates arrive in descending trigram-score order, so the first row seen for a
                // vendor:product pair is already that product's best-scoring row.
                bestPerProduct.putIfAbsent(identityKey(entry), entry);
            } else if (isOperatingSystemPart(entry)) {
                // golden-300 fix (item 3): kept aside, only ever used below if bestPerProduct ends up
                // empty. Hardware (part=h) and anything else is still dropped outright, exactly as
                // before this fix.
                bestOsPerProductFallback.putIfAbsent(identityKey(entry), entry);
            }
        }
        if (bestPerProduct.isEmpty() && !bestOsPerProductFallback.isEmpty()) {
            log.info("No part=a (application) CPE candidates found — falling back to {} part=o "
                    + "(operating system) candidate(s) for exactMatchQuery='{}'",
                    bestOsPerProductFallback.size(), exactMatchQuery);
            bestPerProduct = bestOsPerProductFallback;
        }

        String normalizedVendor = normalizeForContainment(vendor);
        String normalizedExactMatchQuery = normalizeForContainment(exactMatchQuery);
        List<RankedCandidate> ranked = bestPerProduct.values().stream()
                .map(entry -> new RankedCandidate(
                        entry,
                        exactProductSlugMatch(normalizedExactMatchQuery, entry),
                        targetSwMatchesEcosystem(entry, mappedTargetSw),
                        unexplainedQueryTokenCount(normalizedExactMatchQuery, entry),
                        versionCoverageRank(entry, itemVersion),
                        versionCoverageIsPlausible(entry, itemVersion),
                        vendorAgrees(normalizedVendor, entry),
                        catalogedRowCount(entry)))
                .toList();
        // Stable sort: preserves the underlying trigram ranking within each group (RankedCandidate
        // is built directly off bestPerProduct.values()'s own already-ordered stream), so this only
        // promotes candidates that actually win one of the keys below rather than re-ordering
        // arbitrarily.
        return ranked.stream()
                .sorted(java.util.Comparator
                        .comparing((RankedCandidate c) -> c.exactSlugMatch() ? 0 : 1)
                        .thenComparing(c -> c.targetSwMatch() ? 0 : 1)
                        .thenComparingInt(RankedCandidate::unexplainedTokenCount)
                        .thenComparingInt(RankedCandidate::versionCoverageRank)
                        // REVISE item 2 (senior review, PR #51): versionPlausible()==false is now
                        // always equivalent to versionCoverageRank()==2 (K2 already incorporates
                        // versionCoverageIsPlausible's own ratio guard — see that method's javadoc),
                        // so this key is redundant with the one just above it. Left in rather than
                        // removed since it's harmless (a genuine tie-break no-op) and removing it is
                        // out of scope for this fix.
                        .thenComparing(c -> c.versionPlausible() ? 0 : 1)
                        .thenComparing(c -> c.vendorAgrees() ? 0 : 1)
                        .thenComparing(java.util.Comparator.comparingInt(RankedCandidate::catalogedRowCount).reversed()))
                .limit(limit)
                .map(RankedCandidate::entry)
                .toList();
    }

    /** Backlog item 89: every {@link #rankCpeCandidates} comparison key, computed exactly once per
     *  candidate — see that method's own javadoc for what each field means and why precomputing them
     *  into a record (rather than recomputing inside the {@link java.util.Comparator} on every
     *  comparison) matters here. */
    private record RankedCandidate(
            CpeDictionaryEntry entry,
            boolean exactSlugMatch,
            boolean targetSwMatch,
            int unexplainedTokenCount,
            int versionCoverageRank,
            boolean versionPlausible,
            boolean vendorAgrees,
            int catalogedRowCount) {
    }

    /**
     * Backlog item 15, P2 ranking tie-break (senior review 2026-08-30): whether {@code entry}'s own
     * catalogued version history plausibly covers {@code itemVersion} — used ONLY as a soft ranking
     * tie-break in {@link #rankCpeCandidates}, never as a hard reject anywhere in this class. Per the
     * design's own "no evidence means always plausible" requirement, this only ever returns {@code
     * false} when there is concrete numeric evidence the item's version is newer than anything this
     * (vendor, product) pair has ever been catalogued at — every other case (no catalogued versions
     * at all, only {@code "*"}/{@code "-"}/non-numeric catalogued values, or an unparseable item
     * version) defaults to {@code true}.
     *
     * <p>That "no evidence means always plausible" invariant has to hold not just for the obvious
     * null {@link CpeDictionaryEntry#getMaxCatalogedMajor()} case, but also whenever the aggregation
     * window backing it is merely partial — a {@code max_cataloged_major} that's missing some of the
     * pair's real catalogued versions looks identical, from here, to "genuinely has no newer
     * versions", and would wrongly demote a candidate for a version this method never actually saw
     * evidence against. That's exactly why {@link
     * com.vulncheck.app.repository.CpeDictionaryRepositoryImpl#findFuzzyMatches}'s {@code
     * max_cataloged_major} aggregate deliberately runs with no per-column trigram filter, unlike
     * {@code target_sw_values} above — it aggregates every row in the (vendor, product) partition,
     * not just whichever subset happened to trigram-match this particular query column (see that
     * method's own comment).
     *
     * <p>Backlog item 36 (senior review 2026-08-30): that same "no evidence means always plausible"
     * invariant also has to hold for the more common case where {@code maxCatalogedMajor} is real
     * but simply lower than {@code itemMajor} — that fact alone is not evidence the candidate is
     * wrong, because the NVD dictionary only ever catalogues the versions a CVE happened to name.
     * A product with few CVEs filed against it stops accumulating catalogued versions long before
     * its real-world release history does, and this is <em>not</em> rare: measured against
     * golden-300's own 68 correct answers, 9 (13.2%) have a correct candidate whose {@code
     * maxCatalogedMajor} is lower than the item's own major version (2026-08-30). That is why this
     * method demotes only on a ratio (see {@link #VERSION_COVERAGE_IMPLAUSIBILITY_RATIO}) rather
     * than on {@code itemMajor > maxCatalogedMajor} alone — a candidate whose catalogue simply
     * trails a few majors behind is exactly the common, innocent case this ratio guard exists to
     * keep plausible, reserving an actual demotion for when the item's version is implausibly far
     * beyond anything ever catalogued for that (vendor, product) pair.
     */
    private boolean versionCoverageIsPlausible(CpeDictionaryEntry entry, String itemVersion) {
        Integer maxCatalogedMajor = entry.getMaxCatalogedMajor();
        if (maxCatalogedMajor == null || maxCatalogedMajor <= 0) {
            return true;
        }
        java.util.OptionalInt itemMajor = leadingMajorVersion(itemVersion);
        if (itemMajor.isEmpty()) {
            return true;
        }
        return itemMajor.getAsInt() <= maxCatalogedMajor * VERSION_COVERAGE_IMPLAUSIBILITY_RATIO;
    }

    /** Parses the leading run of ASCII digits at the very start of {@code version} as an integer
     *  major-version number (e.g. {@code "3.7.1"} -&gt; {@code 3}) — empty when {@code version} is
     *  null/blank or doesn't start with a digit at all (e.g. {@code "v3.7.1"}, {@code "-"}, {@code
     *  "*"}), which {@link #versionCoverageIsPlausible} treats as "no usable evidence" rather than
     *  a parse failure to reject on. */
    private static java.util.OptionalInt leadingMajorVersion(String version) {
        if (version == null) {
            return java.util.OptionalInt.empty();
        }
        int end = 0;
        while (end < version.length() && Character.isDigit(version.charAt(end))) {
            end++;
        }
        if (end == 0) {
            return java.util.OptionalInt.empty();
        }
        try {
            return java.util.OptionalInt.of(Integer.parseInt(version.substring(0, end)));
        } catch (NumberFormatException e) {
            return java.util.OptionalInt.empty();
        }
    }

    /** REVISE item 1's primary ranking signal: whether {@code normalizedExactMatchQuery} (already
     *  run through {@link #normalizeForContainment}) is exactly equal to {@code entry}'s own
     *  normalized product slug — not mere containment, which every candidate in this list has
     *  already passed to get this far. */
    private boolean exactProductSlugMatch(String normalizedExactMatchQuery, CpeDictionaryEntry entry) {
        return !normalizedExactMatchQuery.isBlank()
                && normalizedExactMatchQuery.equals(normalizeForContainment(entry.getProduct()));
    }

    /** REVISE item 6: whether {@code entry}'s CPE {@code part} segment (index 2, 0-indexed) is
     *  {@code a} (application) — the primary part value for a software inventory item's own
     *  identity (see {@link #isOperatingSystemPart} for the narrow {@code part=o} fallback added by
     *  the golden-300 fix, item 3). A plain split is safe here (never the escape-aware {@link
     *  CpeUtils} splitter): the part segment always precedes any vendor/product field, so it can
     *  never itself contain an escaped colon. Defensively permissive (returns true) for a CPE string
     *  too short to even have a part segment, mirroring this class's other defensive CPE-parsing
     *  fallbacks. */
    private boolean isApplicationPart(CpeDictionaryEntry entry) {
        String cpeString = entry.getCpeString();
        if (cpeString == null) {
            return true;
        }
        String[] segments = cpeString.split(":", -1);
        return segments.length <= 2 || "a".equals(segments[2]);
    }

    /** golden-300 fix (2026-08-29, item 3): whether {@code entry}'s CPE {@code part} segment is
     *  {@code o} (operating system) — used by {@link #rankCpeCandidates} only as a fallback pool for
     *  when zero {@code part=a} candidates exist at all (see that method's javadoc). Deliberately
     *  narrower than {@link #isApplicationPart}: a CPE string too short to have a part segment is
     *  NOT defensively treated as {@code o} here (that permissiveness only ever makes sense for the
     *  primary, always-checked-first {@code part=a} case), and {@code part=h} (hardware) is never
     *  included by either method — the job 37 incident this whole gate exists to prevent was
     *  specifically a hardware CPE. */
    private boolean isOperatingSystemPart(CpeDictionaryEntry entry) {
        String cpeString = entry.getCpeString();
        if (cpeString == null) {
            return false;
        }
        String[] segments = cpeString.split(":", -1);
        return segments.length > 2 && "o".equals(segments[2]);
    }

    /** Derived from the CPE string rather than the entity's own vendor/product columns: the CPE
     *  string is the one field guaranteed to be present and authoritative for every row, and
     *  parsing it keeps this correct even for rows written before those columns existed (or by a
     *  caller that only populated the CPE itself). */
    private String identityKey(CpeDictionaryEntry entry) {
        CpeUtils.VendorProduct vendorProduct = CpeUtils.parseVendorProduct(entry.getCpeString());
        return vendorProduct != null
                ? vendorProduct.vendor() + ":" + vendorProduct.product()
                : String.valueOf(entry.getCpeString());
    }

    /**
     * Backlog item 89, K1 ranking tie-break: how many of {@code normalizedExactMatchQuery}'s own
     * tokens are accounted for by neither {@code entry}'s own text (product or title) nor its CPE
     * vendor. Deliberately a fresh method rather than a change to {@link #explainsQuery} — this asks
     * a different question ("how much of the query is unaccounted for", a graded signal for ranking
     * among already-admitted candidates) from what {@link #explainsQuery} answers ("does this
     * candidate explain the query at all", a boolean admission gate) — but reuses that method's own
     * {@link #tokenize}/{@link #vendorExplains} building blocks rather than inventing new ones.
     *
     * <p>Checking both {@code product} and {@code title} tokens (not product alone) matters for the
     * Adobe Acrobat Reader DC case this key was built for: the query "Adobe Acrobat Reader DC"
     * includes the vendor word "Adobe", which {@code acrobat_reader_dc}'s bare product slug doesn't
     * contain, but a real dictionary title ("Adobe Acrobat Reader DC") does — checking product alone
     * would wrongly count "adobe" as unexplained for the *correct* candidate too, losing the signal
     * that actually separates it from the wrong, shorter {@code acrobat_reader} candidate (which
     * leaves "dc" unexplained by either its product or its title, and "dc" is too short/unrelated
     * for {@link #vendorExplains} to credit to Adobe's own CPE vendor either).
     */
    private int unexplainedQueryTokenCount(String normalizedExactMatchQuery, CpeDictionaryEntry entry) {
        List<String> queryTokens = tokenize(normalizedExactMatchQuery);
        if (queryTokens.isEmpty()) {
            return 0;
        }
        List<String> productTokens = tokenize(normalizeForContainment(entry.getProduct()));
        List<String> titleTokens = tokenize(normalizeForContainment(entry.getTitle()));
        String normalizedCpeVendor = normalizeForContainment(cpeVendorOf(entry));
        int unexplained = 0;
        for (String token : queryTokens) {
            boolean explainedByCandidateText = productTokens.contains(token) || titleTokens.contains(token);
            if (!explainedByCandidateText && !vendorExplains(normalizedCpeVendor, token)) {
                unexplained++;
            }
        }
        return unexplained;
    }

    /**
     * Backlog item 89, K2 ranking tie-break: a 3-value sibling of {@link #versionCoverageIsPlausible}
     * — {@code COVERS(0)} when {@code entry}'s cataloged history already reaches at least the item's
     * own major version, {@code UNKNOWN(1)} when there's no usable evidence either way (mirrors that
     * method's own "no evidence means always plausible" cases exactly), {@code NOT_COVERS(2)}
     * otherwise. Never a hard reject (same as {@code versionCoverageIsPlausible}) — purely a ranking
     * order among already-admitted candidates, and deliberately placed ahead of {@code vendorAgrees}
     * in {@link #rankCpeCandidates}'s own key chain (see that method's own javadoc for why: a raw
     * boolean {@code versionCoverageIsPlausible} tie-break sitting only after {@code vendorAgrees}
     * isn't enough on its own here, because {@code vendorAgrees} itself would otherwise pick the
     * wrong, version-stale candidate first for PDF-XChange Editor).
     *
     * <p>REVISE item 2 (senior review, PR #51): a candidate whose cataloged major merely trails the
     * item's own major version — but stays within {@link #versionCoverageIsPlausible}'s own ratio
     * guard — is NOT the same as a candidate with zero cataloged evidence at all, and must not share
     * the same (worst) rank. {@code versionCoverageIsPlausible} exists precisely to protect that
     * "trails a bit but still plausible" candidate (see its own javadoc, backlog item 36, measured
     * against 13.2% of golden-300's correct answers) from being treated as equivalent to "no evidence
     * whatsoever" — collapsing both into {@code NOT_COVERS(2)} here silently defeated that guard one
     * key earlier in the same chain. Only a candidate that exceeds the ratio guard (implausibly far
     * beyond anything ever cataloged, e.g. Citrix Workspace's item major 2405 against a same-slug
     * competitor with zero catalog history) is ranked {@code NOT_COVERS(2)}; "no evidence" and
     * "trails but plausible" both share {@code UNKNOWN(1)}, exactly like {@code
     * versionCoverageIsPlausible} itself treats them.
     */
    private int versionCoverageRank(CpeDictionaryEntry entry, String itemVersion) {
        Integer maxCatalogedMajor = entry.getMaxCatalogedMajor();
        if (maxCatalogedMajor == null || maxCatalogedMajor <= 0) {
            return 1; // UNKNOWN — no cataloged evidence at all.
        }
        java.util.OptionalInt itemMajor = leadingMajorVersion(itemVersion);
        if (itemMajor.isEmpty()) {
            return 1; // UNKNOWN — item's own version isn't parseable.
        }
        if (itemMajor.getAsInt() <= maxCatalogedMajor) {
            return 0; // COVERS.
        }
        // REVISE item 2: only demote to NOT_COVERS when even versionCoverageIsPlausible's own ratio
        // guard rejects it — a candidate merely trailing behind (still within the guard) stays at
        // UNKNOWN, the same rank "no evidence at all" gets, rather than falling to the worst rank.
        return versionCoverageIsPlausible(entry, itemVersion) ? 1 : 2;
    }

    /** Backlog item 89, K3 ranking tie-break (the final one in the chain): {@code entry}'s own
     *  {@link CpeDictionaryEntry#getCatalogedRowCount()}, defaulting to 0 when a candidate wasn't
     *  sourced from the {@code collect()} query that populates it (e.g. the name-variant search) —
     *  the same "no evidence" default {@link #catalogedRowCount} treats as the lowest priority, never
     *  a hard reject. See {@link #rankCpeCandidates}'s own javadoc for the Greenshot tie this exists
     *  to break. */
    private int catalogedRowCount(CpeDictionaryEntry entry) {
        Integer count = entry.getCatalogedRowCount();
        return count == null ? 0 : count;
    }

    private boolean vendorAgrees(String normalizedVendor, CpeDictionaryEntry entry) {
        if (normalizedVendor.isBlank()) {
            return false;
        }
        return containsEitherWay(normalizedVendor, normalizeForContainment(cpeVendorOf(entry)));
    }

    /** Prefers the vendor parsed out of the CPE string over the entity column, for the same reason
     *  {@link #identityKey} does: the CPE string is the one field every row is guaranteed to have. */
    private String cpeVendorOf(CpeDictionaryEntry entry) {
        CpeUtils.VendorProduct vendorProduct = CpeUtils.parseVendorProduct(entry.getCpeString());
        return vendorProduct != null ? vendorProduct.vendor() : entry.getVendor();
    }

    /**
     * The rest of {@link #fuzzyMatchCpe} once the local (literal-only) lookup's result is already in
     * hand (whether computed just now or, in {@link #identify}'s case, before the registry fan-out
     * — see {@link #localCpeLookup}'s own javadoc) — decides whether a live NVD fallback is
     * warranted at all, and only as a
     * genuine last resort (after that live fallback has itself been attempted and failed) tries the
     * name-variant search ({@link #findByNameVariants}).
     *
     * <p>The variant search deliberately does NOT run any earlier than this: it used to live inside
     * {@link #localCpeLookup} itself, firing whenever the literal search alone found nothing — which
     * meant producing *a* candidate there, even a wrong one, made this method think local matches
     * already existed, permanently skipping the live NVD fallback below and, via {@link #identify},
     * Tier3 as well (both gated on "found literally nothing at all"). Trying it only after the live
     * fallback has already come back empty preserves both of those strictly-better fallback stages.
     *
     * <p>REVISE item 1 (senior review, job 36 root-cause): every candidate list this method can
     * return is passed through {@link #rankAndGate}, which — on top of the existing ranking — hard
     * -rejects a candidate whose {@code target_sw} set scopes it to a platform the item doesn't
     * belong to (see {@link #passesTargetSwGate}). A rejection empties out whichever branch produced
     * it, which naturally falls through to the next fallback stage exactly like "found nothing" did
     * before this fix — never a silent drop to a lower-ranked candidate within the same branch.
     */
    private CpeCandidateResult resolveCpeCandidates(String vendor, String productName, Long userId,
            Optional<String> registryEcosystem, Optional<String> registryPackageName,
            LocalCpeMatches localMatches, String itemVersion) {
        // REVISE item 1: a registry-sourced item's own resolved package name — reduced to its one
        // meaningful segment the same way Fix 5's cpeCorroboratesRegistryPackage already does for a
        // Maven groupId:artifactId coordinate or a Go module path — is a strictly more precise exact
        // -match query than the item's raw productName, since it's a real registry's own canonical
        // name rather than whatever free text the inventory happened to record. Falls back to
        // productName whenever there's no registry match to draw on.
        String exactMatchQuery = registryPackageName.map(this::lastMeaningfulPackageSegment).orElse(productName);
        TargetSwContext targetSwContext = TargetSwContext.from(registryEcosystem, exactMatchQuery);

        List<CpeDictionaryEntry> gatedLocalMatches = rankAndGate(vendor, localMatches.candidates(), targetSwContext, itemVersion);
        if (!gatedLocalMatches.isEmpty()) {
            // Backlog item 89 P2: localMatches.candidates() is either entirely strict-pass-derived or
            // (only when the strict pass found nothing at all) entirely relaxed-pass-derived — see
            // LocalCpeMatches's own javadoc — so localMatches's own flag is exactly right here,
            // whether or not the target_sw gate above happened to drop some of those candidates.
            return new CpeCandidateResult(gatedLocalMatches, localMatches.usedRelaxedPass(), localMatches.usedRelaxedPass());
        }

        String query = cpeQuery(vendor, productName);
        if (registryEcosystem.isPresent()) {
            log.info("Local CPE dictionary had no candidates for '{}' — skipping live NVD CPE lookup "
                    + "since a registry match already covers this item", query);
            return new CpeCandidateResult(List.of(), false, false);
        }

        Optional<String> nvdApiKey = userApiKeyService.getNvdApiKey(userId);
        Optional<String> successfulQuery = liveNvdCpeLookupWithFallback(query, nvdApiKey);
        if (successfulQuery.isEmpty()) {
            // Genuine last resort: even the live, rate-limited NVD keyword search (already retried
            // with several word-dropped fallback queries) found nothing at all for this product.
            List<CpeDictionaryEntry> variantMatches =
                    rankAndGate(vendor, findByNameVariants(vendor, productName), targetSwContext, itemVersion);
            // Name-variant provenance, never relaxed-containment provenance — see
            // CpeCandidateResult's own javadoc (REVISE item 1) for why this stays false here.
            return new CpeCandidateResult(variantMatches, !variantMatches.isEmpty(), false);
        }

        // Re-query with whichever (possibly word-dropped) variant actually found results, not the
        // original full query — observed live: a live sync for "GitKraken GitLens - Git
        // supercharged" only succeeded after dropping "supercharged" down to "GitKraken GitLens -
        // Git", but re-querying the local dictionary with the original, longer string diluted
        // trigram similarity below both thresholds (0.276/0.286 vs. 0.3/0.6), silently discarding
        // the very entries the live call had just upserted a moment earlier.
        LocalCpeMatches refreshedLocal = localCpeLookup(vendor, productName, itemVersion);
        List<CpeDictionaryEntry> refreshed = rankAndGate(vendor, refreshedLocal.candidates(), targetSwContext, itemVersion);
        if (!refreshed.isEmpty()) {
            return new CpeCandidateResult(refreshed, refreshedLocal.usedRelaxedPass(), refreshedLocal.usedRelaxedPass());
        }
        ContainmentResult liveContainment = plausibleContainmentOnly(vendor, productName,
                cpeDictionaryRepository.findFuzzyMatches(successfulQuery.get(),
                        CPE_PRODUCT_SIMILARITY_THRESHOLD, CPE_TITLE_SIMILARITY_THRESHOLD, CPE_CANDIDATE_POOL));
        return new CpeCandidateResult(
                rankAndGate(vendor, liveContainment.candidates(), targetSwContext, itemVersion),
                liveContainment.usedRelaxedPass(),
                liveContainment.usedRelaxedPass());
    }

    private String cpeQuery(String vendor, String productName) {
        return vendor != null && !vendor.isBlank() ? vendor + " " + productName : productName;
    }

    /** Ranks {@code candidates} (see {@link #rankCpeCandidates}) and then applies the REVISE item 1
     *  target_sw hard-reject gate ({@link #passesTargetSwGate}) — the one place both operations are
     *  applied together, so every exit point of {@link #resolveCpeCandidates} gets both regardless
     *  of which branch produced the raw candidate list.
     *
     *  <p>REVISE item 1 (senior review 2026-08-26, job 38 root-cause): ranks over the full {@value
     *  #CPE_CANDIDATE_POOL}-sized pool (passing {@code CPE_CANDIDATE_POOL}, not {@code
     *  CPE_CANDIDATE_LIMIT}, as {@link #rankCpeCandidates}'s {@code limit}) and gates BEFORE
     *  truncating to the final {@value #CPE_CANDIDATE_LIMIT} — not the other way around. Truncating
     *  first was the entire bug: crates.io {@code http}'s correct answer, {@code hyper:http}, sat
     *  outside the first 3 rows of the ungated, ecosystem-unaware ranking (tied with several wrong
     *  candidates at exact-slug rank), so a truncate-then-gate order discarded it before the gate
     *  that would have rejected the other 2 finalists (and kept {@code hyper}) ever got to run. */
    private List<CpeDictionaryEntry> rankAndGate(
            String vendor, List<CpeDictionaryEntry> candidates, TargetSwContext ctx, String itemVersion) {
        return rankCpeCandidates(vendor, ctx.exactMatchQuery(), candidates, ctx.mappedTargetSw(), CPE_CANDIDATE_POOL, itemVersion)
                .stream()
                .filter(entry -> passesTargetSwGate(entry, ctx))
                .limit(CPE_CANDIDATE_LIMIT)
                .toList();
    }

    /**
     * Gating/ranking context for target_sw-aware CPE matching (REVISE items 1/3, senior review
     * 2026-08-26 / job 36 root-cause). {@code hasRegistryMatch} distinguishes two cases {@link
     * #passesTargetSwGate} treats differently: "no registry match at all" (desktop software with no
     * ecosystem to map, e.g. Slack/Atom/OWASP ZAP/Camtasia — the stricter "reject anything entirely
     * platform-scoped" gate) versus "a registry matched, but its ecosystem has no target_sw mapping"
     * (hex, maven — deliberately treated as no signal at all, per {@link #ECOSYSTEM_TO_TARGET_SW}'s
     * own javadoc and REVISE item 8, which leaves hex's "tesla" alone entirely). {@code
     * mappedTargetSw} is therefore only ever present when there IS a registry match AND its
     * ecosystem is one of the eight mapped ones.
     */
    private record TargetSwContext(boolean hasRegistryMatch, Optional<String> mappedTargetSw, String exactMatchQuery) {
        static TargetSwContext from(Optional<String> registryEcosystem, String exactMatchQuery) {
            return registryEcosystem.isEmpty()
                    ? new TargetSwContext(false, Optional.empty(), exactMatchQuery)
                    : new TargetSwContext(true, mapEcosystemToTargetSw(registryEcosystem.get()), exactMatchQuery);
        }
    }

    private static Optional<String> mapEcosystemToTargetSw(String ecosystem) {
        return Optional.ofNullable(ecosystem).map(ECOSYSTEM_TO_TARGET_SW::get);
    }

    /**
     * REVISE item 1 (senior review, job 36 root-cause): a CPE whose {@code target_sw} set scopes it
     * to being a component of some other platform (e.g. {@code target_sw=jenkins} — "this CPE is
     * the Jenkins Slack Notification plugin for Jenkins", not Slack itself) can never be a
     * standalone item's own identity, and can only be a *registry-sourced* item's identity when that
     * scoping actually matches the item's own ecosystem. A blank/absent target_sw set — the common
     * case, since only candidates sourced from {@link
     * com.vulncheck.app.repository.CpeDictionaryRepositoryImpl#findFuzzyMatches} ever get one
     * populated at all (see {@link CpeDictionaryEntry#getTargetSwValues}) — means there's no signal
     * to gate on at all, so it always passes rather than being treated as evidence of anything.
     */
    private boolean passesTargetSwGate(CpeDictionaryEntry entry, TargetSwContext ctx) {
        java.util.Set<String> targetSwValues = entry.getTargetSwValues();
        if (targetSwValues == null || targetSwValues.isEmpty()) {
            return true;
        }
        // REVISE item 3: checked before anything else, including the wildcard passthrough just
        // below — a (vendor, product) pair whose rows span both a wildcard-scoped version and a
        // Jenkins-plugin-scoped version is not a realistic case in practice, but "unconditional"
        // means unconditional: this must never be reachable via any other branch of this method,
        // including the hex/maven orElse(true) default-allow at the bottom.
        if (targetSwValues.contains(JENKINS_TARGET_SW)) {
            return false;
        }
        boolean isWildcardOrNotApplicableOrNonScoping = targetSwValues.stream()
                .anyMatch(v -> "*".equals(v) || "-".equals(v) || NON_SCOPING_TARGET_SW_VALUES.contains(v));
        if (isWildcardOrNotApplicableOrNonScoping) {
            return true;
        }
        if (!ctx.hasRegistryMatch()) {
            // No registry match at all, so no ecosystem of the item's own to compare against — a
            // CPE scoped only to being a component of *some* other platform can never be this
            // standalone item's identity.
            return false;
        }
        if (ctx.mappedTargetSw().isPresent()) {
            return targetSwValues.contains(ctx.mappedTargetSw().get());
        }
        // A registry match exists but its ecosystem has no target_sw mapping (hex/maven) reaches
        // here — default-allow (see ECOSYSTEM_TO_TARGET_SW's own javadoc for why guessing a mapping
        // for those two would be worse than having none).
        return true;
    }

    /** REVISE item 3's soft ranking-preference signal: whether {@code entry}'s target_sw set
     *  contains the item's own ecosystem's mapped value — see {@link #rankCpeCandidates}'s own
     *  javadoc for where this sits in the sort priority. */
    private boolean targetSwMatchesEcosystem(CpeDictionaryEntry entry, Optional<String> mappedTargetSw) {
        if (mappedTargetSw.isEmpty()) {
            return false;
        }
        java.util.Set<String> targetSwValues = entry.getTargetSwValues();
        return targetSwValues != null && targetSwValues.contains(mappedTargetSw.get());
    }

    /**
     * A pg_trgm threshold alone isn't reliable for long, multi-word CPE product slugs — trigram
     * similarity is inflated by generic shared words even between unrelated products. Observed
     * live: querying "Python Extension Pack for Visual Studio Code" scored 0.59 product-similarity
     * against {@code visual_studio_code_eslint_extension} (comfortably past the 0.3 threshold)
     * purely from sharing "visual"/"studio"/"code"/"extension" — a completely different VS Code
     * extension. Every confirmed-correct match observed live (gson, wireshark, notepad++, nuget,
     * gimp) satisfies plain case-insensitive substring containment one way or the other between the
     * query and the candidate's product/title; the false positive above does not (neither contains
     * "python" nor "eslint"). Cheap, no extra query, applied as a post-filter after the pg_trgm
     * candidate search rather than replacing it — pg_trgm still does the real work of finding
     * candidates at all despite typos/word-order/punctuation differences.
     *
     * <p>Callers deliberately pass the bare {@code productName} here, not the vendor-prefixed
     * search query used for the pg_trgm lookup itself — found live 2026-08-24: a query like
     * "Mozilla Zoom" or "Mozilla echo" (vendor "Mozilla" + an unrelated product) matched NVD's
     * real but low-quality {@code cpe:2.3:a:mozilla:mozilla:-:*:*:*:*:*:*:*} entry (product
     * literally "mozilla", title "Mozilla Mozilla") purely because the *vendor* word "mozilla"
     * is trivially contained in that candidate — 94 items across two test jobs ended up
     * misidentified as generic "Mozilla Mozilla" this way, regardless of what the actual product
     * was. Requiring containment against the product name alone (vendor's role stays limited to
     * widening the initial pg_trgm search) closes this off without narrowing genuine matches,
     * since a real candidate's title/product almost always still contains the bare product name.
     *
     * <p>Backlog item 89 P2 (senior review 2026-08-30, real job195/196 data): when this strict first
     * pass rejects every single candidate in {@code candidates}, retries the exact same in-memory
     * pool (no DB re-query) with {@link #explainsQuery}'s Direction 2 trailing-vendor-explanation
     * requirement relaxed — the rule that a single-token candidate matching at the very head of the
     * query (nothing preceding it) must also have every *trailing* query token vendor-explained.
     * That rule is what silently drops {@code Metasploit Framework} -&gt; {@code rapid7:metasploit}
     * (the trailing "framework" isn't explained by rapid7's own CPE vendor), a genuine false
     * negative once the strict pass finds nothing else to fall back on. Only ever fires when pass 1
     * came back completely empty — never widens an already-nonempty strict result — and callers must
     * treat a relaxed-pass result the same low-trust way {@link #findByNameVariants} results already
     * are (see {@link ContainmentResult#usedRelaxedPass}).
     */
    private ContainmentResult plausibleContainmentOnly(String vendor, String query, List<CpeDictionaryEntry> candidates) {
        // A Go module path anchors on its VCS host ("github.com/gin-gonic/gin"), and that host
        // component has no CPE identity of its own — left in, it made containment matching anchor
        // on the near-universal "github"/"gitlab"/etc. vendor:vendor CPE entry instead of the
        // module's real, meaningful path segments (confirmed live: "github.com/gin-gonic/gin"
        // resolved to the generic github:github CPE). Reuses the same host.tld/path detection
        // RegistryRoutingPolicy already applies when routing registry lookups, rather than
        // inventing a second one here.
        String normalizedQuery = normalizeForContainment(RegistryRoutingPolicy.stripHostPrefix(query));
        String normalizedItemVendor = normalizeForContainment(vendor);
        List<CpeDictionaryEntry> strict = candidates.stream()
                .filter(entry -> explainsQuery(normalizedItemVendor, normalizedQuery, entry, entry.getProduct(), false, true)
                        || explainsQuery(normalizedItemVendor, normalizedQuery, entry, entry.getTitle(), true, true))
                .toList();
        if (!strict.isEmpty()) {
            return new ContainmentResult(strict, false);
        }
        List<CpeDictionaryEntry> relaxed = candidates.stream()
                .filter(entry -> explainsQuery(normalizedItemVendor, normalizedQuery, entry, entry.getProduct(), false, false)
                        || explainsQuery(normalizedItemVendor, normalizedQuery, entry, entry.getTitle(), true, false))
                .toList();
        return new ContainmentResult(relaxed, !relaxed.isEmpty());
    }

    /** Backlog item 89 P2: outcome of {@link #plausibleContainmentOnly}. {@code usedRelaxedPass} is
     *  {@code true} only when the strict first pass rejected every candidate and the relaxed second
     *  pass is what actually produced {@code candidates} — see that method's own javadoc. */
    private record ContainmentResult(List<CpeDictionaryEntry> candidates, boolean usedRelaxedPass) {
    }

    /**
     * Decides whether {@code candidateText} (a candidate's product slug or title) actually accounts
     * for the query, rather than merely overlapping with it.
     *
     * <p>The old check was a symmetric substring test, and the "query contains candidate" half of it
     * turned out to be the dominant source of *false positives* once the dictionary went from 1,791
     * entries to the full 1,815,263: with 1.8M products there is now always some short slug lurking
     * inside any multi-word name. Measured on jobs 30/31/32 (2026-08-25), it produced:
     *
     * <ul>
     *   <li>"GitHub Desktop", "Power BI Desktop" and "Tableau Desktop" → {@code docker:desktop},
     *       because NVD really does catalogue Docker Desktop as vendor {@code docker}, product
     *       {@code desktop}. "Docker Desktop" is the only one of the four that is correct, and the
     *       thing that distinguishes it is that its leftover word *is* the CPE vendor.</li>
     *   <li>"OBS Studio" → {@code nvidia:studio}, "7-Zip File Manager" → {@code horde:file_manager},
     *       "Paint.NET" → {@code microsoft:.net}, "ramsey/uuid" → {@code satori:uuid}.</li>
     *   <li>Mid-word overlaps with no word boundary at all: "failureaccess" → {@code microsoft:access},
     *       "javapoet" → {@code ibm:java}, "guice" → {@code sap:gui}, "ioredis" → {@code
     *       pivotal_software:redis}.</li>
     * </ul>
     *
     * <p>These are worse than a miss: an UNIDENTIFIED item is visibly handed back for review, whereas
     * a confident wrong CPE quietly attaches someone else's CVEs to the product. So the two
     * directions are no longer treated alike:
     *
     * <ul>
     *   <li><b>Candidate contains query</b> — accepted as before. The candidate is the broader
     *       string ("Sublime Text" → {@code sublime_text_3}), so nothing in the query is unaccounted
     *       for.</li>
     *   <li><b>Query contains candidate</b> — the candidate is narrower, so the leftover words are
     *       exactly what distinguishes GitHub Desktop from Docker Desktop. Accepted only if the
     *       candidate lines up on <em>whole tokens</em> (killing the mid-word class outright) and
     *       every leftover token <em>ahead of</em> the match is explained by the CPE vendor
     *       ({@link #vendorExplains}).</li>
     * </ul>
     *
     * <p>Only the <em>leading</em> leftovers are policed, because the head of a software name is
     * where its identity lives; everything after is routinely descriptive ("IntelliJ IDEA Community
     * Edition", "VLC Media Player Portable", "GitKraken GitLens - Git supercharged"). Every one of
     * the false positives above matched in the interior or at the tail — "desktop" is the second
     * word of "GitHub Desktop", "file manager" the third of "7-Zip File Manager" — while every
     * correct narrower match either starts at the head ("qBittorrent Enhanced Edition") or has the
     * CPE vendor as its head ("Docker Desktop", "Adobe Acrobat Reader", "Apache HTTP Server"). That
     * makes a curated stop-word list unnecessary, which matters: such a list is unbounded in
     * practice and silently wrong for whatever product ships the word it omits.
     *
     * <p>Verified against every CPE-backed identification in jobs 30/31/32: all eight false
     * positives above are rejected and no correct match is lost. The residual risk it accepts is a
     * name whose head is a real product but whose tail changes what it is ("Redis Desktop Manager"
     * → {@code redis}); that is rarer than the class removed here, and the trigram search still
     * ranks an exact full-name entry above it whenever NVD has one.
     *
     * <p>REVISE item 5 (senior review, job 37 root-cause): direction 2 above only ever policed the
     * query tokens <em>ahead of</em> the matched candidate run, never the ones <em>after</em> it —
     * fine when there's already a leading anchor proving the vendor tie ("AVG AntiVirus Free" against
     * {@code avg:antivirus}: "avg" leads and is vendor-explained, "free" trails unchecked), but a
     * real gap when the candidate is a single, generic token that matches at the very head of the
     * query with nothing preceding it at all to prove anything — "Windows Terminal" against {@code
     * microsoft:windows}, "Android Studio" against {@code google:android}, "Chrome Remote Desktop"
     * against {@code 360:chrome}, "Unity Hub" against {@code ayatana_project:unity} all matched this
     * way with the entire rest of the query silently unaccounted for. Requiring the trailing tokens
     * to be vendor-explained too, but only when there was no leading anchor to already vouch for the
     * match, closes this without re-breaking the AVG case (whose leading "avg" already proves it).
     *
     * <p>Backlog item 89 P3 (senior review 2026-08-30): Direction 1 itself has a mirror-image gap —
     * when the *query* is the single-token side and it only aligns against a *leading* portion of a
     * longer candidate product slug ("Slack" against {@code slack_archivebot_project}'s product
     * {@code slack_archivebot}), the trailing leftover candidate tokens ("archivebot") were never
     * policed at all, the same class of gap REVISE item 5 already closed for Direction 2. Closed the
     * same way — leftover trailing candidate tokens must be explained — but by the *item's own*
     * vendor field, never the candidate's own CPE vendor (which would trivially "explain" its own
     * leftover fragment the same way REVISE item 4 already guards against for {@link
     * #alignPrefixAtAnyBoundary}). Only checked for a single-token query, mirroring REVISE item 5's
     * own single-token-candidate condition: a multi-token query that merely happens to align against
     * a shorter leading run of the candidate already has its own internal structure proving the tie
     * (the same reasoning REVISE item 2's {@code queryTokens.size() >= 2} guard above relies on), so
     * widening this to every query would risk re-breaking a real multi-word match. Only checked when
     * the item has a non-blank vendor field at all — same "no evidence means permissive" default this
     * class uses everywhere else (e.g. {@link #versionCoverageIsPlausible}, {@link
     * #passesTargetSwGate}'s blank-target_sw passthrough): a blank item vendor gives {@link
     * #vendorExplains} nothing to ever confirm against, and a query like bare "apache" (item vendor
     * routinely blank for a package with no inventory-recorded vendor) legitimately matching
     * {@code apache:apache_http_server} must not be rejected purely because there's no vendor text to
     * check the leftover "http"/"server" tokens against — measured live via this project's own test
     * suite (see {@code Stage1IdentificationServiceTest}'s several blank-vendor single-token-query
     * fixtures) once an unconditional version of this check was tried.
     *
     * <p>Backlog item 89 P2 (senior review 2026-08-30): {@code requireTrailingVendorExplanation}
     * controls whether Direction 2's REVISE item 5 trailing-vendor-explanation rule (see above) is
     * enforced at all — {@code true} everywhere except {@link #plausibleContainmentOnly}'s own
     * relaxed second pass, which only ever runs after the strict pass (this flag {@code true})
     * already rejected every candidate in the pool. Does not affect Direction 1 or this method's own
     * new P3 check above, both of which stay unconditionally strict regardless of this flag — P2's
     * relaxation is calibrated narrowly to the one rule it was measured against (Metasploit Framework
     * -&gt; rapid7:metasploit), not a general loosening of every containment rule at once.
     */
    private boolean explainsQuery(String normalizedItemVendor, String normalizedQuery, CpeDictionaryEntry entry,
            String candidateText, boolean isTitleField, boolean requireTrailingVendorExplanation) {
        String candidate = normalizeForContainment(candidateText);
        if (normalizedQuery.isBlank() || candidate.isBlank()) {
            return false;
        }

        List<String> queryTokens = tokenize(normalizedQuery);
        List<String> candidateTokens = tokenize(candidate);
        if (queryTokens.isEmpty() || candidateTokens.isEmpty()) {
            return false;
        }

        // Direction 1 (2026-08-26 fix): candidate is the broader string — the whole query must
        // align, token-boundary-and-concatenation-aware, against a *leading* run of candidate
        // tokens (see alignPrefix's own javadoc for the concatenation handling). This replaces the
        // old raw, unconstrained `candidate.contains(normalizedQuery)` fast path, which matched any
        // short query mid-word against any candidate that happened to embed it as a substring
        // (confirmed live: "rayon" -> crayon_project:crayon, "log" -> siemens:logo!, "get" ->
        // ...:set-or-get) — this same loose check ran against entry.getTitle() too, which is far
        // worse: with 1.8M NVD titles formatted "Vendor Product Version", any short query trivially
        // substring-matches thousands of unrelated titles purely off their leading vendor word
        // (confirmed live: "slack" -> jenkins:slack / a WordPress plugin titled "Slack WP
        // SlackSync..." merely because its vendor happens to be "Slack"). For a title specifically
        // (never for a bare product slug — see stillAcceptsANarrowerCandidateWhenTheLeftoverWordIs
        // TheCpeVendor, a legitimate case of the *opposite* direction below, for why the vendor
        // can't just be exempted from policing here the way it's used to *explain* leftovers there),
        // a match consumed entirely within the entry's own vendor-token count proves nothing about
        // the actual product and is rejected outright, since the title format guarantees its
        // leading word(s) literally *are* the vendor.
        int candidateTokensConsumed = alignPrefix(queryTokens, candidateTokens);
        // REVISE item 2 (senior review, job 36): a real multi-word product name doesn't only ever
        // sit at the very front of a longer candidate product slug — "Process Monitor" is a real,
        // previously-working match against sysinternals_process_monitor that Fix 2's index-0-only
        // anchoring above silently broke (a regression, not a new gap). Retried at any later
        // candidate token boundary, but ONLY for the product field (never the title field, which
        // stays strictly prefix-anchored via vendorTokenCount above) and ONLY when the query itself
        // has at least two tokens — a single-token query (e.g. "get" against "set-or-get") has no
        // internal structure of its own to prove the match landed on a real word boundary rather
        // than a coincidental one, which is exactly why an unconditional relaxation would wrongly
        // re-accept "get" -> ...:set-or-get, the very false positive Fix 2 closed off.
        if (candidateTokensConsumed <= 0 && !isTitleField && queryTokens.size() >= 2) {
            candidateTokensConsumed = alignPrefixAtAnyBoundary(queryTokens, candidateTokens, normalizedItemVendor);
        }
        boolean direction1Match = candidateTokensConsumed > 0
                && (!isTitleField || candidateTokensConsumed > vendorTokenCount(entry));
        // Backlog item 89 P3: a single-token query that only consumed a *leading* portion of a
        // longer candidate leaves candidateTokens[candidateTokensConsumed..] unaccounted for — see
        // this method's own javadoc above for why this is checked only for a single-token query, only
        // against the item's own vendor field, and only when that vendor field is non-blank at all.
        if (direction1Match && queryTokens.size() == 1 && candidateTokensConsumed < candidateTokens.size()
                && !normalizedItemVendor.isBlank()) {
            for (int i = candidateTokensConsumed; i < candidateTokens.size(); i++) {
                if (!vendorExplains(normalizedItemVendor, candidateTokens.get(i))) {
                    direction1Match = false;
                    break;
                }
            }
        }
        if (direction1Match) {
            return true;
        }

        // Direction 2 (unchanged since the 2026-08-25 fix): candidate is the narrower string, found
        // as a contiguous run of whole tokens somewhere within the query. Accepted only if every
        // query token *ahead of* that run is explained by the candidate's own CPE vendor — see this
        // method's own class-level javadoc above for the full Docker/GitHub Desktop reasoning.
        int start = java.util.Collections.indexOfSubList(queryTokens, candidateTokens);
        if (start < 0) {
            return false;
        }
        String cpeVendor = normalizeForContainment(cpeVendorOf(entry));
        for (int i = 0; i < start; i++) {
            if (!vendorExplains(cpeVendor, queryTokens.get(i))) {
                return false;
            }
        }
        // REVISE item 5: a single-token candidate that matched with nothing ahead of it (start == 0)
        // has no leading anchor at all vouching for the tie — the trailing leftovers must be
        // vendor-explained too in that case, the same way the leading ones already are above. A
        // multi-token candidate, or one with a nonempty (and therefore already vendor-explained)
        // leading run, is left exactly as before — see this method's own javadoc for the AVG
        // AntiVirus Free / Windows Terminal contrast this distinction is calibrated against.
        //
        // Backlog item 89 P2: this specific rule is what plausibleContainmentOnly's relaxed second
        // pass exists to lift (requireTrailingVendorExplanation=false) — see this method's own
        // javadoc for why only this rule, not the whole method, is relaxable.
        if (requireTrailingVendorExplanation && start == 0 && candidateTokens.size() == 1) {
            for (int i = start + candidateTokens.size(); i < queryTokens.size(); i++) {
                if (!vendorExplains(cpeVendor, queryTokens.get(i))) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * REVISE item 2 (senior review, job 36): retries {@link #alignPrefix} starting at every later
     * candidate token boundary (index 1 onward — index 0 is already tried by the caller first, see
     * that call site's own guard for why this is gated on the query having at least two tokens and
     * never running for the title field). Returns the first successful alignment's own consumed-
     * token count (relative to the sublist it was tried against) — the caller only ever tests this
     * for {@code > 0}, so the exact count doesn't need adjusting back to the original indices.
     *
     * <p>REVISE item 4 (senior review, job 37 root-cause): a successful alignment at a non-zero
     * boundary leaves candidate tokens {@code [0, start)} unaccounted for, and those must be
     * explained by the <em>item's own vendor field</em> — never the CPE's own vendor, which trivially
     * "explains" its own leftover fragment (measured live: {@code vendorExplains("goanother",
     * "another")} passed purely because the CPE's vendor slug itself contains the word "another",
     * wrongly matching "Redis Desktop Manager" — item vendor "RDM Dev Team", which does not — against
     * {@code goanother:another_redis_desktop_manager}'s leftover "another" token). "Process Monitor"
     * (item vendor "Microsoft Sysinternals") against {@code sysinternals_process_monitor}'s leftover
     * "sysinternals" is the positive case this must keep working.
     */
    private int alignPrefixAtAnyBoundary(List<String> queryTokens, List<String> candidateTokens, String normalizedItemVendor) {
        for (int start = 1; start < candidateTokens.size(); start++) {
            int consumed = alignPrefix(queryTokens, candidateTokens.subList(start, candidateTokens.size()));
            if (consumed > 0 && precedingCandidateTokensExplainedByItemVendor(candidateTokens, start, normalizedItemVendor)) {
                return consumed;
            }
        }
        return -1;
    }

    /** REVISE item 4's own vendor-explanation check: every candidate token before {@code start} must
     *  be explained by the item's own (already-normalized) vendor field. */
    private boolean precedingCandidateTokensExplainedByItemVendor(
            List<String> candidateTokens, int start, String normalizedItemVendor) {
        for (int i = 0; i < start; i++) {
            if (!vendorExplains(normalizedItemVendor, candidateTokens.get(i))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Attempts to align the *entirety* of {@code queryTokens}, token-boundary-and-concatenation-
     * aware, against a leading run of {@code containerTokens} — a run of consecutive whole tokens
     * on either side may need to be concatenated together to line up with a single token on the
     * other side (e.g. query tokens "wamp"+"server" against a single container token
     * "wampserver"), since a real product name is sometimes split differently by whitespace/
     * punctuation on one side than the other. Any leftover once the query is fully consumed must
     * fall exactly on a container token boundary, never mid-token — that's what keeps "log" from
     * matching "logo!" (the leftover "o" is not a whole token gap) while still letting "win"+"rar"
     * match "winrar" exactly.
     *
     * @return the number of leading {@code containerTokens} consumed by the match, or {@code -1} if
     *         no such alignment exists — including when {@code containerTokens} runs out before
     *         {@code queryTokens} does, since a container that's actually the *shorter* side is
     *         direction 2's job above, not this one.
     */
    private int alignPrefix(List<String> queryTokens, List<String> containerTokens) {
        int qi = 0;
        int ci = 0;
        String qRemainder = "";
        String cRemainder = "";
        while (qi < queryTokens.size() || !qRemainder.isEmpty()) {
            if (qRemainder.isEmpty()) {
                qRemainder = queryTokens.get(qi++);
            }
            if (cRemainder.isEmpty()) {
                if (ci >= containerTokens.size()) {
                    return -1;
                }
                cRemainder = containerTokens.get(ci++);
            }
            if (qRemainder.equals(cRemainder)) {
                qRemainder = "";
                cRemainder = "";
            } else if (cRemainder.length() > qRemainder.length() && cRemainder.startsWith(qRemainder)) {
                cRemainder = cRemainder.substring(qRemainder.length());
                qRemainder = "";
            } else if (qRemainder.length() > cRemainder.length() && qRemainder.startsWith(cRemainder)) {
                qRemainder = qRemainder.substring(cRemainder.length());
                cRemainder = "";
            } else {
                return -1;
            }
        }
        // The query is fully consumed; a nonempty cRemainder means the match ended mid-token on the
        // container side rather than at a real token boundary.
        return cRemainder.isEmpty() ? ci : -1;
    }

    /** How many leading tokens of {@code entry}'s own CPE vendor there are — see direction 1's
     *  javadoc in {@link #explainsQuery} for why a title match confined to this many tokens doesn't
     *  count as explaining the query. */
    private int vendorTokenCount(CpeDictionaryEntry entry) {
        return tokenize(normalizeForContainment(cpeVendorOf(entry))).size();
    }

    /**
     * Whether a leftover query word is accounted for by the candidate's CPE vendor — the signal that
     * separates "Docker Desktop" from "GitHub Desktop".
     *
     * <p>Deliberately stricter than plain substring containment: CPE vendor slugs are short, so a
     * loose test lets two-letter fragments through (the leftover "go" of "github.com/go-redis/redis"
     * is a substring of {@code google}). A whole-token hit is always enough; a substring hit has to
     * clear four characters, which still admits the run-together vendor slugs this exists for
     * ("Charles Proxy" → {@code charlesproxy:charles}).
     */
    private boolean vendorExplains(String normalizedCpeVendor, String token) {
        if (normalizedCpeVendor.isBlank() || token.isBlank()) {
            return false;
        }
        List<String> vendorTokens = tokenize(normalizedCpeVendor);
        return vendorTokens.contains(token)
                || (token.length() >= 4 && String.join("", vendorTokens).contains(token));
    }

    private List<String> tokenize(String normalized) {
        return java.util.Arrays.stream(normalized.split("[^a-z0-9]+"))
                .filter(token -> !token.isEmpty())
                .toList();
    }

    /** Blank-guarded both ways — an empty string is trivially "contained" in everything in Java,
     *  which would make this check vacuously pass for entries with no title (or, defensively, no
     *  product) rather than actually requiring evidence. */
    private boolean containsEitherWay(String a, String b) {
        if (a.isBlank() || b.isBlank()) {
            return false;
        }
        return a.contains(b) || b.contains(a);
    }

    // Package-private (not private) solely so Stage1IdentificationServiceTest can exercise it
    // directly — no other production caller outside this class, no behavior change.
    String normalizeForContainment(String value) {
        // CPE 2.3 strings backslash-escape reserved characters (e.g. "notepad\+\+") — strip those
        // so "Notepad++" (the query, unescaped) still matches its own dictionary entry.
        return value == null ? "" : value.toLowerCase(java.util.Locale.ROOT).replace('_', ' ').replace("\\", "").trim();
    }

    /**
     * NVD's {@code keywordSearch} is a literal, all-words-must-roughly-match search, not a fuzzy
     * one — confirmed live: {@code "Apache Log4j Core"} returns zero results while
     * {@code "Apache Log4j"} (drop the trailing "Core") returns 162. A Tier3-resolved vendor+
     * product string (e.g. "The Apache Software Foundation" + "Apache Log4j Core") very easily
     * picks up qualifier words that don't appear in NVD's own terse CPE titles, silently losing a
     * product NVD actually has cataloged — a real miss observed live for Log4j (CVE-2021-44228).
     * Mitigates by retrying with trailing words dropped one at a time (bounded to a few extra
     * rate-limited calls) until a query returns something or words run out.
     */
    private Optional<String> liveNvdCpeLookupWithFallback(String query, Optional<String> nvdApiKey) {
        String[] words = query.trim().split("\\s+");
        int wordsToTry = words.length;
        int attempts = 0;

        while (wordsToTry >= 1 && attempts < MAX_LIVE_NVD_QUERY_ATTEMPTS) {
            String attempt = String.join(" ", Arrays.copyOfRange(words, 0, wordsToTry));
            log.info("Querying NVD CPE API live for '{}' (apiKey={})", attempt, nvdApiKey.isPresent());
            int upserted = nvdCpeSyncService.syncKeywordSinglePage(attempt, LIVE_NVD_LOOKUP_RESULTS_PER_PAGE, nvdApiKey);
            log.info("Live NVD CPE lookup for '{}' upserted {} dictionary entries", attempt, upserted);
            if (upserted > 0) {
                return Optional.of(attempt);
            }
            wordsToTry--;
            attempts++;
        }
        return Optional.empty();
    }
}
