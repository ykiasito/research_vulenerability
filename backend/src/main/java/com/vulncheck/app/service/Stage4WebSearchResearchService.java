package com.vulncheck.app.service;

import com.vulncheck.app.entity.ResearchJobItem;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Closed-mode B2 (docs/spec/closed-mode-plan.md §9-2): Stage4 was last-resort LLM+web_search
 * vulnerability research (via the Python {@code llm-service}), gated on the job owner having a
 * Claude key configured — closed mode never has one, so {@link #research} now always takes the
 * exact same fallback {@link ResearchJobProcessingService} already saw whenever no key was
 * configured: nothing persisted, {@link ResearchJobItem#INCOMPLETE_REASON_AI_NOT_AVAILABLE}
 * recorded so the item is distinguishable from a genuinely "checked, clean" result.
 */
@Service
@Slf4j
public class Stage4WebSearchResearchService {

    /** Outcome of a {@link #research} call — see this class's own javadoc; {@code incompleteReason}
     *  is always {@link ResearchJobItem#INCOMPLETE_REASON_AI_NOT_AVAILABLE} now. */
    public record Stage4ResearchResult(int persistedCount, String incompleteReason) {
    }

    public Stage4ResearchResult research(ResearchJobItem item, String ecosystem, String packageName, Long userId) {
        log.debug("Stage4 skipped for item {}: AI research is unavailable in this deployment", item.getId());
        return new Stage4ResearchResult(0, ResearchJobItem.INCOMPLETE_REASON_AI_NOT_AVAILABLE);
    }
}
