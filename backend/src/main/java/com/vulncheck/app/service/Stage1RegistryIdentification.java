package com.vulncheck.app.service;

import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.service.llm.LlmServiceClient;
import com.vulncheck.app.service.llm.LlmServiceModels.CandidateDto;
import com.vulncheck.app.service.llm.LlmServiceModels.DisambiguateResponse;
import com.vulncheck.app.service.llm.LlmServiceModels.EcosystemCandidateDto;
import com.vulncheck.app.service.registry.PackageRegistryLookup;
import com.vulncheck.app.service.registry.RegistryLookupCache;
import com.vulncheck.app.service.registry.RegistryMatch;
import com.vulncheck.app.service.registry.RegistryRoutingPolicy;
import java.math.BigDecimal;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

/**
 * Closed-mode backlog item 166 / {@code docs/spec/closed-mode-plan.md} §3-3 (A3): the Tier1
 * external-registry half of what used to be inlined, line-by-line, inside {@link
 * Stage1IdentificationService}. Everything here talks to one of the 10 registry clients ({@link
 * PackageRegistryLookup} implementations) or arbitrates among several same-named registry hits —
 * the whole point of pulling it into its own class is that, in the future closed-processing-mode
 * branch (see the plan doc), this entire file — along with the 10 registry clients themselves —
 * is deleted outright, and {@link Stage1IdentificationService} only has to lose its two
 * constructor arguments for this class and {@link Stage1AiArbitration}, plus a handful of call
 * sites in {@code identify}/{@code resolveCandidates}, rather than having registry logic
 * hand-picked back out of a single interleaved method.
 *
 * <p>Depends on {@link LlmServiceClient} for exactly one thing: arbitrating among several
 * same-named registry candidates via the same {@code disambiguate} endpoint CPE Tier2 uses (see
 * {@link #resolveRegistryMatch}). That's fine even though the Java AI path is also deleted in
 * closed mode — this whole class dies in the same changeset, so there's nothing left depending on
 * {@code llmServiceRestClient}/{@code LlmServiceClient} once both are gone.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class Stage1RegistryIdentification {

    /** Margin used by {@link #maxConfidenceMatch} to decide whether several matches are "tied" —
     *  registry clients only ever emit confidence from a small, discrete set of constants (0.4/0.5
     *  unconfirmed, 0.95 version-confirmed — see e.g. {@link RegistryLookupCache}'s
     *  VERSION_CONFIRMED/UNCONFIRMED_CONFIDENCE), so in practice this margin only ever collapses
     *  exact ties, but is expressed as a small tolerance rather than {@code equals} in case a future
     *  registry client's confidence is computed rather than a fixed constant. */
    private static final BigDecimal REGISTRY_MATCH_TIE_MARGIN = new BigDecimal("0.05");

    /**
     * Maps an OSV/registry ecosystem to the {@code usage_text} keywords that indicate it —
     * deliberately conservative, multi-character phrases (never a bare "go" or "pub", which occur
     * as ordinary English substrings, e.g. "go"-inside-"django"/"algorithm") so a hit here is real
     * signal, not noise. Only consulted by {@link #maxConfidenceMatch} as a tie-break among already-
     * tied top candidates — see that method's javadoc for why this can never override a single clear
     * winner.
     *
     * <p>REVISE item 2 (senior review 2026-08-29, round 1): values are pre-compiled word-boundary {@link
     * Pattern}s, not plain strings matched via {@link String#contains}. Plain substring containment
     * let short keywords false-positive inside unrelated words — "JavaScript" contains maven's
     * "java", "CI pipeline" contains pypi's "pip", "hex editor" contains hex's "hex",
     * "sourceforge.net" contains nuget's ".net", "Gemini" contains rubygems' "gem" — any of which
     * could flip a genuine npm/maven (or similar) tie to the wrong ecosystem. {@code
     * (?<![a-z0-9])keyword(?![a-z0-9])} requires the keyword not be immediately adjacent to another
     * alphanumeric character on either side, so it only matches a real standalone word/token, not a
     * substring inside a longer one — {@link Pattern#quote} keeps punctuation-bearing keywords
     * ({@code .net}, {@code c#}) literal rather than being interpreted as regex metacharacters.
     */
    private static final Map<String, List<Pattern>> ECOSYSTEM_USAGE_TEXT_KEYWORDS =
            buildEcosystemUsageTextKeywordPatterns();

    private static Map<String, List<Pattern>> buildEcosystemUsageTextKeywordPatterns() {
        Map<String, List<String>> rawKeywords = Map.ofEntries(
                Map.entry("pypi", List.of("pypi", "pip")),
                Map.entry("npm", List.of("npm", "node")),
                Map.entry("rubygems", List.of("gem", "ruby")),
                Map.entry("crates.io", List.of("crate", "rust", "cargo")),
                Map.entry("packagist", List.of("packagist", "composer", "php")),
                Map.entry("hex", List.of("hex", "elixir")),
                Map.entry("pub", List.of("pub.dev", "dart", "flutter")),
                Map.entry("maven", List.of("maven", "gradle", "java")),
                Map.entry("nuget", List.of("nuget", ".net", "c#")),
                Map.entry("go", List.of("go get", "golang")));
        Map<String, List<Pattern>> compiled = new LinkedHashMap<>();
        rawKeywords.forEach((ecosystem, keywords) -> compiled.put(ecosystem, keywords.stream()
                .map(keyword -> Pattern.compile("(?<![a-z0-9])" + Pattern.quote(keyword) + "(?![a-z0-9])"))
                .toList()));
        return Map.copyOf(compiled);
    }

    private final List<PackageRegistryLookup> registryLookups;
    private final RegistryRoutingPolicy registryRoutingPolicy;
    private final RegistryLookupCache registryLookupCache;
    private final UserApiKeyService userApiKeyService;
    private final LlmServiceClient llmServiceClient;
    private final JobCostBudgetService jobCostBudgetService;
    @Qualifier("registryLookupExecutor")
    private final Executor registryLookupExecutor;

    /**
     * Outcome of {@link #resolveRegistryMatch}: {@code aiVerified} tells {@link
     * Stage1IdentificationService#resolveCandidates} whether this already went through an AI
     * plausibility check (arbitration among multiple same-named registry candidates), so it can
     * skip its own single-candidate weak-match check rather than spending a second, redundant LLM
     * call on an already-answered question.
     */
    public record RegistryResolution(Optional<RegistryMatch> match, boolean aiVerified, BigDecimal aiConfidence) {
    }

    /**
     * Tier1 static registry lookup, with the same AI-arbitration pattern CPE Tier2 already had: a
     * generic/common product name (e.g. "commons-io", "phoenix", "http") can get a match from
     * *multiple* registries simultaneously — previously this just took the max-confidence one with
     * no arbitration, so ties/near-ties silently went to whichever registry client happened to be
     * injected first. Observed live repeatedly, including one case where the AI correctly rejected
     * a wrong npm hit but the CPE-rescue fallback then landed on yet *another* wrong generic-name
     * collision from a different registry that was never even considered. When more than one
     * registry matches, this asks the LLM to pick (or reject all) among them using the item's
     * usage_text — same anti-hallucination shape as CPE Tier2 (index-select only, never invents a
     * new package) and the same {@code disambiguate} endpoint/cost as the existing single-candidate
     * weak-match check, just applied across registries instead of within one.
     */
    public RegistryResolution resolveRegistryMatch(ResearchJobItem item, Long userId, String productName, String version) {
        // Narrowed by RegistryRoutingPolicy *before* any request is issued: each registry's own
        // naming grammar (npm's @scope/name, Maven's groupId:artifactId, a Go module's host.tld/path,
        // Composer's vendor/package, ...) can already rule out most registries for a given name with
        // zero network calls — measured live (job 35): Stage1 spent ~99% of its time on rate-limiter
        // waits, with Maven Central alone accounting for 32 minutes, much of it on names that could
        // never have been a Maven coordinate in the first place. Falls back to asking everyone when
        // the routing rule can't narrow anything down (see RegistryRoutingPolicy's own javadoc).
        List<PackageRegistryLookup> routedLookups = registryRoutingPolicy.route(productName, registryLookups);

        // Dispatched concurrently, not via a sequential stream: each registry is an independent
        // several-second network round trip, so scanning them one at a time serializes the
        // slowest registry's latency behind every other one. Measured live: this was the single
        // largest contributor to per-item processing time (see registryLookupExecutor's javadoc).
        List<CompletableFuture<Optional<RegistryMatch>>> futures = routedLookups.stream()
                .map(lookup -> CompletableFuture.supplyAsync(() -> safeLookup(lookup, productName, version), registryLookupExecutor))
                .toList();
        List<RegistryMatch> matches = futures.stream()
                .map(CompletableFuture::join)
                .flatMap(Optional::stream)
                .toList();

        if (matches.isEmpty()) {
            return new RegistryResolution(Optional.empty(), false, null);
        }
        if (matches.size() == 1) {
            return new RegistryResolution(Optional.of(matches.get(0)), false, null);
        }

        Optional<String> apiKey = userApiKeyService.getClaudeApiKey(userId);
        boolean withinBudget = apiKey.isPresent()
                && jobCostBudgetService.tryReserve(item.getJobId(), JobCostBudgetService.TIER2_DISAMBIGUATE_COST_USD);
        if (!withinBudget) {
            return new RegistryResolution(Optional.of(maxConfidenceMatch(matches, item.getUsageText())), false, null);
        }

        List<CandidateDto> candidateDtos = matches.stream()
                .map(m -> new CandidateDto(m.ecosystem(), m.packageName(), null, m.purl(), "registry"))
                .toList();
        Optional<DisambiguateResponse> result = llmServiceClient.disambiguate(
                apiKey.get(), item, candidateDtos, JobCostBudgetService.TIER2_DISAMBIGUATE_COST_USD);

        if (result.isEmpty()) {
            // LLM call failed — degrade to the pre-arbitration best-effort behavior.
            return new RegistryResolution(Optional.of(maxConfidenceMatch(matches, item.getUsageText())), false, null);
        }
        if (!result.get().matched()) {
            log.info("AI rejected all {} same-named registry candidates for item {} ('{}') as implausible "
                    + "given the usage text", matches.size(), item.getId(), productName);
            return new RegistryResolution(Optional.empty(), true, null);
        }
        Integer selectedIndex = result.get().selectedIndex();
        if (selectedIndex == null || selectedIndex < 0 || selectedIndex >= matches.size()) {
            log.warn("LLM registry arbitration returned an invalid selection for item {}: {}", item.getId(), result.get());
            return new RegistryResolution(Optional.of(maxConfidenceMatch(matches, item.getUsageText())), false, null);
        }
        RegistryMatch selected = matches.get(selectedIndex);
        log.info("AI arbitrated {} same-named registry candidates for item {} ('{}') -> selected ecosystem={} package={}",
                matches.size(), item.getId(), productName, selected.ecosystem(), selected.packageName());
        return new RegistryResolution(Optional.of(selected), true, BigDecimal.valueOf(result.get().confidence()));
    }

    /**
     * Tier3's one place a specific registry package name gets guessed directly (rather than only a
     * human-readable name fed back into fuzzy lookup) — see {@link
     * Stage1AiArbitration#tryTier3}'s own javadoc for why. Each guess is still verified against the
     * real registry before being trusted — never persisted on the LLM's say-so alone.
     */
    public Optional<RegistryMatch> bestEcosystemCandidateMatch(Long itemId, List<EcosystemCandidateDto> candidates, String version) {
        if (candidates == null) {
            return Optional.empty();
        }
        for (EcosystemCandidateDto candidate : candidates) {
            if (candidate.ecosystem() == null || candidate.packageName() == null || candidate.packageName().isBlank()) {
                continue;
            }
            Optional<PackageRegistryLookup> lookup = registryLookups.stream()
                    .filter(l -> l.ecosystem().equalsIgnoreCase(candidate.ecosystem()))
                    .findFirst();
            if (lookup.isEmpty()) {
                log.warn("AI proposed ecosystem candidate '{}' for item {} which is not an enabled ecosystem — ignored",
                        candidate.ecosystem(), itemId);
                continue;
            }
            Optional<RegistryMatch> match = safeLookup(lookup.get(), candidate.packageName(), version);
            if (match.isPresent()) {
                log.info("AI-guessed ecosystem candidate matched for item {}: ecosystem={} package={}",
                        itemId, candidate.ecosystem(), candidate.packageName());
                return match;
            }
        }
        return Optional.empty();
    }

    /** Routes every registry call through {@link RegistryLookupCache} (keyed on ecosystem+productName,
     *  not version — see that class's javadoc) so a product name repeated across many CSV rows, the
     *  common case at real inventory scale, costs at most one request per registry instead of one
     *  per row. */
    private Optional<RegistryMatch> safeLookup(PackageRegistryLookup lookup, String productName, String version) {
        try {
            return registryLookupCache.get(lookup.ecosystem(), productName, version,
                    () -> lookup.lookup(productName, version));
        } catch (Exception e) {
            log.warn("Registry lookup {} threw unexpectedly for product {}", lookup.getClass().getSimpleName(), productName, e);
            return Optional.empty();
        }
    }

    /**
     * golden-300 fix (2026-08-29, item 2 "cross-registry same-name collision"): when the AI
     * disambiguation budget is exhausted (or unavailable), this degrades to picking the
     * highest-confidence registry match with no other signal — which silently picks whichever
     * registry happened to be queried/injected first among several equally-confident same-named
     * matches (numpy, jekyll, redis, phoenix, phoenix_live_view, http all mis-routed this way in
     * golden-300). {@code item.usage_text} is already stored and available but was never consulted
     * here at all. Deliberately narrow: only ever consulted when {@code matches} has more than one
     * candidate within {@link #REGISTRY_MATCH_TIE_MARGIN} of the top confidence — a single clear
     * leader (the overwhelmingly common case, and the only case reachable when {@code matches} has
     * exactly one entry in the first place, per this method's only caller) is returned exactly as
     * before, unaffected by this fallback. Even among tied candidates, this only overrides the
     * default max-confidence pick when the usage text narrows the tie down to exactly one
     * ecosystem — 0 or 2+ surviving keyword hits leaves the original (arbitrary but unchanged)
     * max-confidence behavior in place, so this can only ever narrow an already-ambiguous pick, not
     * introduce a new wrong one.
     */
    private RegistryMatch maxConfidenceMatch(List<RegistryMatch> matches, String usageText) {
        RegistryMatch best = matches.stream().max((a, b) -> a.confidence().compareTo(b.confidence())).orElseThrow();
        List<RegistryMatch> tied = matches.stream()
                .filter(m -> m.confidence().subtract(best.confidence()).abs().compareTo(REGISTRY_MATCH_TIE_MARGIN) <= 0)
                .toList();
        if (tied.size() <= 1 || usageText == null || usageText.isBlank()) {
            return best;
        }
        String normalizedUsageText = usageText.toLowerCase(Locale.ROOT);
        List<RegistryMatch> usageTextNarrowed = tied.stream()
                .filter(m -> usageTextMentionsEcosystem(normalizedUsageText, m.ecosystem()))
                .toList();
        if (usageTextNarrowed.size() == 1) {
            log.info("Tie-breaking {} equally-confident same-named registry matches using usage_text -> "
                    + "ecosystem={} package={}", tied.size(), usageTextNarrowed.get(0).ecosystem(),
                    usageTextNarrowed.get(0).packageName());
            return usageTextNarrowed.get(0);
        }
        return best;
    }

    /** @param normalizedUsageText already lower-cased by the caller. */
    private boolean usageTextMentionsEcosystem(String normalizedUsageText, String ecosystem) {
        List<Pattern> patterns = ECOSYSTEM_USAGE_TEXT_KEYWORDS.get(ecosystem);
        if (patterns == null) {
            return false;
        }
        return patterns.stream().anyMatch(p -> p.matcher(normalizedUsageText).find());
    }
}
