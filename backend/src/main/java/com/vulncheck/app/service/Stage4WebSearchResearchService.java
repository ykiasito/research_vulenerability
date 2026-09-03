package com.vulncheck.app.service;

import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.repository.JobItemVulnerabilityRepository;
import com.vulncheck.app.repository.VulnerabilityRepository;
import com.vulncheck.app.service.llm.LlmServiceClient;
import com.vulncheck.app.service.llm.LlmServiceModels.WebSearchVulnFindingDto;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Stage4: last-resort LLM+web_search vulnerability research. Two call sites, both gated on the
 * job owner having a Claude key configured, to keep this expensive fallback rare per the plan's
 * cost design:
 * <ul>
 *   <li>{@link ResearchJobProcessingService} — Stage2 (NVD/OSV/GHSA) found zero vulnerabilities
 *       for an already-identified item; scope is the item's ecosystem/package name.</li>
 *   <li>{@link ResearchJobProcessingService} — Stage1 never produced a queryable ecosystem/CPE at
 *       all, but Tier3 still recognized a platform-specific identifier (see
 *       {@code ResearchJobItem.hintPlatform}/{@code hintIdentifier}); scope is that platform/
 *       identifier pair instead. This is the only way an UNIDENTIFIED item still gets a
 *       vulnerability answer.</li>
 * </ul>
 * Takes a plain ecosystem/package-name pair rather than an {@link com.vulncheck.app.entity.IdentifiedProduct}
 * specifically so both call sites can share this one implementation.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class Stage4WebSearchResearchService {

    static final String SOURCE = "llm_web_search";

    // A bare CVE/GHSA id is safe to use directly as the global dedup key (vulnerabilities.cve_or_ghsa_id
    // is UNIQUE across all products). Anything else the LLM returns is free text and NOT guaranteed
    // unique across unrelated products — scoped below to avoid silently merging two different
    // products' findings into one row.
    private static final Pattern KNOWN_ID_PATTERN = Pattern.compile("^(CVE-\\d{4}-\\d+|GHSA-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4})$");
    private static final int MAX_ID_LENGTH = 100;

    private final UserApiKeyService userApiKeyService;
    private final LlmServiceClient llmServiceClient;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final JobItemVulnerabilityRepository jobItemVulnerabilityRepository;
    private final JobCostBudgetService jobCostBudgetService;

    /** Outcome of a {@link #research} call. {@code incompleteReason} is one of {@code
     *  ResearchJobItem#INCOMPLETE_REASON_AI_NOT_AVAILABLE}/{@code
     *  ResearchJobItem#INCOMPLETE_REASON_BUDGET_EXHAUSTED} when this Stage4 pass never actually ran
     *  (so the caller can record that on the item, distinguishing "not checked" from "checked, clean"
     *  — see {@code ResearchJobItem#researchIncompleteReason}'s javadoc); {@code
     *  ResearchJobItem#INCOMPLETE_REASON_AI_CALL_FAILED} when the pass was attempted but {@link
     *  com.vulncheck.app.service.llm.LlmServiceClient#webSearchResearch} itself reports the call
     *  failed (its {@code Optional.empty()} — network/timeout/4xx/5xx/unexpected error); or {@code
     *  null} when the pass ran to completion (regardless of how many findings it persisted — a
     *  genuinely empty findings list is a real "checked, clean" result, not a failure, and must not
     *  be conflated with the {@code AI_CALL_FAILED} case above). */
    public record Stage4ResearchResult(int persistedCount, String incompleteReason) {
    }

    public Stage4ResearchResult research(ResearchJobItem item, String ecosystem, String packageName, Long userId) {
        Optional<String> apiKey = userApiKeyService.getClaudeApiKey(userId);
        if (apiKey.isEmpty()) {
            log.info("Stage4 skipped for item {}: no Claude API key configured for user {}", item.getId(), userId);
            return new Stage4ResearchResult(0, ResearchJobItem.INCOMPLETE_REASON_AI_NOT_AVAILABLE);
        }
        if (!jobCostBudgetService.tryReserve(item.getJobId(), JobCostBudgetService.STAGE4_WEB_SEARCH_RESEARCH_COST_USD)) {
            log.info("Stage4 skipped for item {}: job cost budget exhausted", item.getId());
            return new Stage4ResearchResult(0, ResearchJobItem.INCOMPLETE_REASON_BUDGET_EXHAUSTED);
        }

        log.info("Stage4 firing for item {} (ecosystem={}, package={})", item.getId(), ecosystem,
                LogSanitizer.sanitize(packageName));

        Optional<List<WebSearchVulnFindingDto>> findingsResult = llmServiceClient.webSearchResearch(
                apiKey.get(), item, ecosystem, packageName, JobCostBudgetService.STAGE4_WEB_SEARCH_RESEARCH_COST_USD);

        // PR #68 item 121 REVISE (senior review 2026-09-01): LlmServiceClient#webSearchResearch swallowed
        // RestClientException/RuntimeException internally and returned an empty List either way, so this
        // call site could never distinguish "LLM service call failed" from "call succeeded, found
        // nothing" -- the exact case ResearchJobProcessingService's stage4Threw flag was meant to catch,
        // but never fired for because no exception ever escaped this far. Optional.empty() now carries
        // that signal explicitly.
        if (findingsResult.isEmpty()) {
            log.error("Stage4 web-search research call failed for item {} (ecosystem={}, package={})",
                    item.getId(), ecosystem, LogSanitizer.sanitize(packageName));
            return new Stage4ResearchResult(0, ResearchJobItem.INCOMPLETE_REASON_AI_CALL_FAILED);
        }
        List<WebSearchVulnFindingDto> findings = findingsResult.get();

        int persisted = 0;
        for (WebSearchVulnFindingDto finding : findings) {
            if (finding.identifier() == null || finding.identifier().isBlank()) {
                continue;
            }
            String dedupeId = scopedId(finding.identifier(), packageName, item.getId());
            // Task-backlog item 104: citation_url is LLM free text with no scheme allowlist upstream —
            // a prompt-injected javascript:/data: URL would otherwise become a live XSS link when
            // jobs/detail.html renders it as th:href. Dropped to null (not escaped/shown as text) per
            // this app's existing "silence over a wrong guess" stance for low-trust LLM output.
            String citationUrl = SafeUrlValidator.sanitizeHttpUrl(finding.citationUrl());
            // insertIfAbsentAndGetId (not upsertAndGetId): this is a low-trust LLM finding, so it
            // must never overwrite content an authoritative Stage2 source (NVD/OSV/GHSA) already
            // wrote for the same CVE/GHSA id. It still gets linked to this item below either way.
            Long vulnerabilityId = vulnerabilityRepository.insertIfAbsentAndGetId(
                    dedupeId, SOURCE, finding.severity(), finding.description(), citationUrl, finding.fixedVersion());
            jobItemVulnerabilityRepository.linkIfAbsent(item.getId(), vulnerabilityId, SOURCE, citationUrl);
            persisted++;
        }

        log.info("Stage4 item {}: LLM returned {} findings, {} persisted (blank identifiers skipped)",
                item.getId(), findings.size(), persisted);

        return new Stage4ResearchResult(findings.size(), null);
    }

    private String scopedId(String identifier, String packageName, Long jobItemId) {
        String trimmed = identifier.trim();
        if (KNOWN_ID_PATTERN.matcher(trimmed).matches()) {
            return trimmed;
        }
        String scope = packageName != null ? packageName : "item" + jobItemId;
        String scoped = "llm:" + scope + ":" + trimmed;
        return scoped.length() > MAX_ID_LENGTH ? scoped.substring(0, MAX_ID_LENGTH) : scoped;
    }
}
