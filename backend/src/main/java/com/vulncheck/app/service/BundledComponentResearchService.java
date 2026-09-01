package com.vulncheck.app.service;

import com.vulncheck.app.entity.CpeDictionaryEntry;
import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.repository.CpeDictionaryRepository;
import com.vulncheck.app.repository.JobItemVulnerabilityRepository;
import com.vulncheck.app.repository.VulnerabilityRepository;
import com.vulncheck.app.service.llm.LlmServiceClient;
import com.vulncheck.app.service.llm.LlmServiceModels.BundledChangelogResponse;
import com.vulncheck.app.service.llm.LlmServiceModels.BundledComponentDto;
import com.vulncheck.app.service.llm.LlmServiceModels.BundledExtractResponse;
import com.vulncheck.app.service.nvd.CpeUtils;
import com.vulncheck.app.service.vuln.NvdVulnerabilitySource;
import com.vulncheck.app.service.vuln.OsvLiveQueryClient;
import com.vulncheck.app.service.vuln.SourceResult;
import com.vulncheck.app.service.vuln.VulnFinding;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Bundled-package detection (formerly "Stage 3.5" in project notes) — see
 * {@code docs/spec/bundled-package-detection-plan.md} for the full design. Detects vulnerabilities
 * in third-party components a product bundles/embeds internally (e.g. a desktop installer shipping
 * its own copy of 7-Zip) that never show up as a package-manager dependency Stage2 can see, by
 * reading the product's own official changelog text via web search and extracting plain
 * {@code (component, version)} facts from it — never letting the LLM name a CVE/GHSA id directly
 * (see {@link com.vulncheck.app.service.llm.LlmServiceModels.BundledComponentDto}'s javadoc).
 *
 * <p>Two LLM calls (changelog discovery, then text-only extraction), each reserved/reconciled
 * against the separate {@link JobCostBudgetService#tryReserveBundledComponent} ledger — never the
 * always-on {@link JobCostBudgetService#tryReserve} budget every job (opted in or not) relies on.
 * Called from {@link ResearchJobProcessingService} in the same slot {@link
 * Stage4WebSearchResearchService} fires from (Stage2 found zero findings for a confidently-
 * identified item), additionally gated on the job's opt-in flag ({@code ResearchJob
 * #bundledComponentCheckEnabled}).
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class BundledComponentResearchService {

    /** Mirrors {@code Stage4WebSearchResearchService#MAX_ID_LENGTH}'s rationale, applied to an
     *  extracted component name instead of an LLM-proposed vulnerability id: a string this long is
     *  not a real product/component name and is pointless (or abusive) to push into a downstream
     *  trigram/OSV query. */
    static final int MAX_COMPONENT_NAME_LENGTH = 100;

    /** REVISE item 5 (senior review 2026-08-26): caps the raw, unescaped string {@link
     *  #adjudicate} concatenates into a CPE via {@link CpeUtils#buildCpe} — see {@link
     *  #isValidCandidate}'s javadoc. */
    static final int MAX_VERSION_LENGTH = 50;

    static final String SOURCE = "bundled_component";

    /** Same thresholds {@code Stage1IdentificationService#localCpeLookup} uses for its own trigram
     *  pool, kept in sync manually rather than shared — see {@link #findCpeMatch}'s javadoc for why
     *  this method doesn't call into that class's private ranking pipeline directly. */
    private static final double CPE_PRODUCT_SIMILARITY_THRESHOLD = 0.3;
    private static final double CPE_TITLE_SIMILARITY_THRESHOLD = 0.6;

    /** REVISE item 1 (senior review 2026-08-26): the pool size handed to {@code findFuzzyMatches}
     *  before any vendor-disambiguation gate runs — mirrors {@code
     *  Stage1IdentificationService#CPE_CANDIDATE_POOL}'s own value and rationale (kept as a separate
     *  constant here rather than a shared import since that one is private to its own class). See
     *  {@link #findCpeMatch}'s javadoc for why a small limit here previously reintroduced a
     *  false-positive class that class's own javadoc documents as already fixed. */
    private static final int CPE_CANDIDATE_POOL = 40;

    /** REVISE item 2 (senior review 2026-08-26): hard cap on how many bundled-component candidates
     *  one item's extraction is adjudicated for — a changelog listing dozens of components would
     *  otherwise issue that many (rate-limited, cache-miss) NVD/OSV queries for a single item. Kept
     *  in sync with {@code llm-service}'s own {@code BUNDLED_EXTRACT_SCHEMA} {@code maxItems}. */
    static final int MAX_COMPONENTS_PER_ITEM = 10;

    private static final Pattern NPM_SCOPED_PACKAGE_PATTERN = Pattern.compile("^@[a-zA-Z0-9][\\w.-]*/[a-zA-Z0-9][\\w.-]*$");
    private static final Pattern MAVEN_COORDINATE_PATTERN = Pattern.compile("^[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+$");

    /** REVISE item 5 (senior review 2026-08-26): a real version string, not free text — must start
     *  with a digit (rejects "latest"/"stable"), and only characters that are safe to concatenate
     *  unescaped into a CPE 2.3 string via {@link CpeUtils#buildCpe} (rejects e.g. a stray {@code :}
     *  that would otherwise silently shift every later CPE segment). */
    private static final Pattern VALID_VERSION_PATTERN = Pattern.compile("^[0-9][0-9A-Za-z.\\-_+]*$");

    private final UserApiKeyService userApiKeyService;
    private final LlmServiceClient llmServiceClient;
    private final JobCostBudgetService jobCostBudgetService;
    private final CpeDictionaryRepository cpeDictionaryRepository;
    private final NvdVulnerabilitySource nvdVulnerabilitySource;
    private final OsvLiveQueryClient osvLiveQueryClient;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final JobItemVulnerabilityRepository jobItemVulnerabilityRepository;

    public int research(ResearchJobItem item, Long userId) {
        Optional<String> apiKey = userApiKeyService.getClaudeApiKey(userId);
        if (apiKey.isEmpty()) {
            log.info("Bundled-component research skipped for item {}: no Claude API key configured for user {}",
                    item.getId(), userId);
            return 0;
        }

        if (!jobCostBudgetService.tryReserveBundledComponent(
                item.getJobId(), JobCostBudgetService.BUNDLED_COMPONENT_CHANGELOG_DISCOVERY_COST_USD)) {
            log.info("Bundled-component research skipped for item {}: bundled-component budget exhausted "
                    + "before changelog discovery", item.getId());
            return 0;
        }
        Optional<BundledChangelogResponse> changelog = llmServiceClient.discoverBundledComponentChangelog(
                apiKey.get(), item, JobCostBudgetService.BUNDLED_COMPONENT_CHANGELOG_DISCOVERY_COST_USD);
        if (changelog.isEmpty() || !changelog.get().found() || isBlank(changelog.get().changelogText())) {
            log.info("Bundled-component research for item {}: no official changelog text found", item.getId());
            return 0;
        }

        if (!jobCostBudgetService.tryReserveBundledComponent(
                item.getJobId(), JobCostBudgetService.BUNDLED_COMPONENT_EXTRACTION_COST_USD)) {
            log.info("Bundled-component research skipped for item {}: bundled-component budget exhausted "
                    + "before extraction (changelog discovery already spent)", item.getId());
            return 0;
        }
        Optional<BundledExtractResponse> extraction = llmServiceClient.extractBundledComponents(
                apiKey.get(), item, changelog.get().changelogText(), JobCostBudgetService.BUNDLED_COMPONENT_EXTRACTION_COST_USD);
        if (extraction.isEmpty() || extraction.get().bundledComponents() == null) {
            return 0;
        }

        List<BundledComponentDto> allCandidates = extraction.get().bundledComponents();
        List<BundledComponentDto> candidates = allCandidates;
        if (allCandidates.size() > MAX_COMPONENTS_PER_ITEM) {
            log.info("Bundled-component research item {}: extraction returned {} candidates, truncating to {}",
                    item.getId(), allCandidates.size(), MAX_COMPONENTS_PER_ITEM);
            candidates = allCandidates.subList(0, MAX_COMPONENTS_PER_ITEM);
        }

        int persisted = 0;
        for (BundledComponentDto candidate : candidates) {
            if (!isValidCandidate(candidate, item)) {
                continue;
            }
            for (VulnFinding finding : adjudicate(candidate, userId)) {
                // Task-backlog item 104: finding.url() is NVD/OSV-sourced (not LLM-authored), but
                // OSV entries are third-party-submitted and NVD reference data isn't scheme-validated
                // either — sanitize defensively before it reaches jobs/detail.html's th:href, same as
                // Stage4's citation_url. Dropped to null (not escaped/shown as text) per this app's
                // existing "silence over a wrong guess" stance for untrusted URLs.
                String url = SafeUrlValidator.sanitizeHttpUrl(finding.url());
                // REVISE item 6 (senior review 2026-08-26): vulnerabilities.source records real
                // provenance (finding.source() — "nvd"/"osv", the LLM never supplies the CVE/GHSA id
                // itself) rather than the SOURCE constant, which is reserved for
                // job_item_vulnerabilities.discovered_via_tier (a per-item discovery-tier
                // attribution, not the shared master row's own provenance). upsertAndGetId, not
                // insertIfAbsentAndGetId: NVD/OSV are authoritative sources here, so this path is
                // allowed to enrich a row Stage4 previously wrote with null severity/description,
                // unlike Stage4's own low-trust LLM-named finding.
                Long vulnerabilityId = vulnerabilityRepository.upsertAndGetId(
                        finding.cveOrGhsaId(), finding.source(), finding.severity(), finding.description(), url, finding.fixedVersion());
                jobItemVulnerabilityRepository.linkIfAbsentWithBundledComponent(
                        item.getId(), vulnerabilityId, SOURCE, url, candidate.componentName(), candidate.version());
                persisted++;
            }
        }

        log.info("Bundled-component research item {}: {} candidate(s) extracted, {} finding(s) persisted",
                item.getId(), allCandidates.size(), persisted);
        return persisted;
    }

    /**
     * Validation before trusting an LLM-extracted pair at all (plan's §3-3), before any adjudication
     * or DB write: rejects a blank/oversized component name, a self-flagged low-confidence
     * extraction (REVISE item 8), a version that isn't a plausible version string at all (REVISE
     * item 5 — the design plan required this server-side, not prompt-only, and the unvalidated
     * string is concatenated raw into a CPE by {@link CpeUtils#buildCpe} with no escaping, so a
     * value like {@code "1:2"} produces a malformed CPE that burns a rate-limited NVD slot on a
     * guaranteed miss), and — the guard most likely to catch a real, observed mis-extraction shape —
     * a version that exactly equals the item's own version (the LLM re-extracting the product's own
     * version as if it were a "bundled component").
     */
    private boolean isValidCandidate(BundledComponentDto candidate, ResearchJobItem item) {
        if (candidate.componentName() == null || candidate.componentName().isBlank()) {
            return false;
        }
        if (candidate.componentName().length() > MAX_COMPONENT_NAME_LENGTH) {
            log.info("Rejecting bundled-component candidate for item {} — component_name exceeds {} chars",
                    item.getId(), MAX_COMPONENT_NAME_LENGTH);
            return false;
        }
        if ("low".equalsIgnoreCase(candidate.confidence())) {
            log.info("Rejecting bundled-component candidate '{}' for item {} — self-flagged low confidence",
                    candidate.componentName(), item.getId());
            return false;
        }
        if (candidate.version() == null || candidate.version().isBlank()) {
            return false;
        }
        if (candidate.version().length() > MAX_VERSION_LENGTH || !VALID_VERSION_PATTERN.matcher(candidate.version()).matches()) {
            log.info("Rejecting bundled-component candidate '{}' for item {} — version '{}' is not a plausible "
                            + "version string", candidate.componentName(), item.getId(), candidate.version());
            return false;
        }
        if (candidate.version().equals(item.getVersion())) {
            log.info("Rejecting bundled-component candidate '{}' for item {} — extracted version '{}' exactly "
                            + "matches the item's own version (likely the LLM re-extracting the product's own "
                            + "version rather than a real bundled component)",
                    candidate.componentName(), item.getId(), candidate.version());
            return false;
        }
        return true;
    }

    /**
     * Adjudicates one validated {@code (component, version)} pair via both applicable paths (plan's
     * §3-1 — deliberately never OSV alone: it has no generic/CPE-style query, so a native-binary
     * bundled component like 7-Zip is entirely outside its 14-ecosystem coverage model): a local
     * CPE-dictionary trigram lookup feeding NVD's CVE API, and — only when the component name
     * clearly matches a known ecosystem naming convention — an OSV query. Neither path hitting is
     * "adjudication inconclusive", not "no vulnerability found": this method simply returns an
     * empty list either way, and the caller persists nothing for an empty list, rather than this
     * method ever synthesizing a fake all-clear finding.
     */
    private List<VulnFinding> adjudicate(BundledComponentDto candidate, Long userId) {
        List<VulnFinding> findings = new ArrayList<>();

        Optional<CpeUtils.VendorProduct> cpeMatch = findCpeMatch(candidate.componentName());
        if (cpeMatch.isPresent()) {
            String cpeName = CpeUtils.buildCpe(cpeMatch.get().vendor(), cpeMatch.get().product(), candidate.version());
            log.info("Bundled-component CPE adjudication for '{}': querying NVD for {}:{}",
                    candidate.componentName(), cpeMatch.get().vendor(), cpeMatch.get().product());
            // fetchFromNvdCached, not fetchFromNvd (REVISE item 2): bundled components recur across
            // many unrelated products in a real inventory (openssl/zlib/curl/7-zip, ...), so this
            // path's cache hit rate is high — bypassing the cache here was measured live to be a
            // real rate-limit exposure, not a low-volume edge case.
            SourceResult nvdResult = nvdVulnerabilitySource.fetchFromNvdCached(cpeName, userId);
            if (nvdResult.succeeded()) {
                findings.addAll(nvdResult.findings());
            }
        }

        Optional<String> osvEcosystem = guessOsvEcosystem(candidate.componentName());
        if (osvEcosystem.isPresent()) {
            SourceResult osvResult = osvLiveQueryClient.queryPackage(osvEcosystem.get(), candidate.componentName(), candidate.version());
            if (osvResult.succeeded()) {
                findings.addAll(osvResult.findings());
            }
        }

        return findings;
    }

    /**
     * Lightweight trigram lookup against the local CPE dictionary, reusing {@link
     * com.vulncheck.app.repository.CpeDictionaryRepositoryCustom#findFuzzyMatches} directly rather
     * than {@code Stage1IdentificationService#localCpeLookup} itself: that method's real value is a
     * private, heavily-tuned ranking/name-variant/target_sw-gating pipeline built around a very
     * different input shape (a CSV row's own vendor/product_name, cross-checked against a resolved
     * registry match) — none of that context exists for a bare string an LLM extracted from
     * changelog text. This deliberately stays conservative instead: no per-pair AI disambiguation
     * budget is spent here (per the plan's §4 cost design, this adjudication step is the one
     * "$0 — not an LLM call" leg), so a candidate is only trusted when its own product slug
     * literally equals (case/whitespace/hyphen-insensitively) the normalized component name — a
     * near-miss trigram hit is left unmatched (adjudication falls through to OSV/inconclusive)
     * rather than risking a wrong vendor:product pairing with nothing downstream to catch it.
     *
     * <p>REVISE item 1 (senior review 2026-08-26, live-data root cause): this previously truncated
     * the dictionary search to {@code CPE_CANDIDATE_LIMIT = 3} results before doing the exact-slug
     * scan above — the same bug pattern {@code Stage1IdentificationService#localCpeLookup}'s own
     * javadoc documents as already fixed there (truncating before any vendor-disambiguation gate can
     * run silently drops the correct vendor when several vendors share a product slug). Measured
     * live: {@code zlib} with a 3-row limit returned only {@code [cloudflare:zlib, gnu:zlib,
     * ruby-lang:zlib]} — the correct {@code zlib:zlib} was truncated out before it was ever
     * considered. Fixed by pulling a wide {@value #CPE_CANDIDATE_POOL}-row pool first, collecting
     * every exact-slug match in it (not just the first), then applying a {@code target_sw} gate:
     * when {@code componentName} doesn't match a known ecosystem naming grammar (npm/Maven — i.e.
     * it's a bare native-binary name, not a package-manager coordinate), only a candidate whose
     * {@code target_sw} set contains {@code *} survives — this drops e.g. {@code curl_project:curl}
     * (target_sw=ruby, the Ruby binding, not native curl) and {@code jenkins:git} (a Jenkins plugin).
     *
     * <p>This is a <em>triage</em> feature, not an authoritative one (per product direction,
     * 2026-08-26): if more than one distinct vendor still survives after gating — a genuinely
     * ambiguous case, e.g. {@code zlib} itself still leaves {@code cloudflare:zlib}/{@code gnu:zlib}/
     * {@code zlib:zlib} all target_sw=* — this deliberately does NOT guess or query every surviving
     * vendor; it's treated exactly like "no CPE match" (adjudication falls through to OSV/
     * inconclusive). Silence beats a specific wrong guess for a tool whose whole job is "flag a
     * possible issue and prompt the user to go check", not hand back a precise, possibly-wrong
     * vendor:product pairing.
     */
    private Optional<CpeUtils.VendorProduct> findCpeMatch(String componentName) {
        List<CpeDictionaryEntry> pool = cpeDictionaryRepository.findFuzzyMatches(
                componentName, CPE_PRODUCT_SIMILARITY_THRESHOLD, CPE_TITLE_SIMILARITY_THRESHOLD, CPE_CANDIDATE_POOL);
        String normalizedQuery = normalize(componentName);
        List<CpeDictionaryEntry> exactMatches = pool.stream()
                .filter(entry -> normalize(entry.getProduct()).equals(normalizedQuery))
                .toList();

        if (!matchesKnownEcosystemGrammar(componentName)) {
            exactMatches = exactMatches.stream()
                    .filter(entry -> entry.getTargetSwValues() != null && entry.getTargetSwValues().contains("*"))
                    .toList();
        }

        Set<String> distinctVendors = new LinkedHashSet<>();
        for (CpeDictionaryEntry entry : exactMatches) {
            distinctVendors.add(entry.getVendor());
        }
        if (distinctVendors.size() != 1) {
            if (distinctVendors.size() > 1) {
                log.info("Bundled-component CPE adjudication for '{}': {} distinct vendors survived gating {} — "
                                + "ambiguous, treating as no CPE match rather than guessing",
                        componentName, distinctVendors.size(), distinctVendors);
            }
            return Optional.empty();
        }

        CpeDictionaryEntry match = exactMatches.get(0);
        return Optional.of(new CpeUtils.VendorProduct(match.getVendor(), match.getProduct()));
    }

    /** Shared by {@link #findCpeMatch}'s target_sw gate and {@link #guessOsvEcosystem}: whether
     *  {@code componentName} matches one of the two package-naming grammars unambiguous enough to
     *  guess from a bare extracted string alone. */
    private boolean matchesKnownEcosystemGrammar(String componentName) {
        return NPM_SCOPED_PACKAGE_PATTERN.matcher(componentName).matches()
                || MAVEN_COORDINATE_PATTERN.matcher(componentName).matches();
    }

    private String normalize(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ROOT).replaceAll("[\\s_-]+", "");
    }

    /**
     * Only two ecosystems, deliberately (plan's §3-1: "pick one ecosystem, don't fan out to all
     * 14"): npm's {@code @scope/name} convention and Maven's {@code groupId:artifactId} convention
     * are the two package-naming grammars unambiguous enough to guess from the bare extracted
     * component name alone — unlike Stage2's own OSV source, there is no {@code IdentifiedProduct
     * #ecosystem} hint here to route by, only the string itself.
     */
    private Optional<String> guessOsvEcosystem(String componentName) {
        if (NPM_SCOPED_PACKAGE_PATTERN.matcher(componentName).matches()) {
            return Optional.of("npm");
        }
        if (MAVEN_COORDINATE_PATTERN.matcher(componentName).matches()) {
            return Optional.of("Maven");
        }
        return Optional.empty();
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
