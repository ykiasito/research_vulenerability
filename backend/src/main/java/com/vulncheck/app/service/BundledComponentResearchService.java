package com.vulncheck.app.service;

import com.vulncheck.app.entity.ResearchJobItem;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Closed-mode B2 (docs/spec/closed-mode-plan.md §9-2): bundled-package detection (formerly
 * "Stage 3.5") ran two Claude web_search calls (changelog discovery, then extraction) via the
 * Python {@code llm-service}, gated on the job owner having a Claude key configured — closed mode
 * never has one, so {@link #research} now always takes the exact same fallback {@link
 * ResearchJobProcessingService} already saw whenever no key was configured: nothing found,
 * nothing persisted.
 */
@Service
@Slf4j
public class BundledComponentResearchService {

    public int research(ResearchJobItem item, Long userId) {
        log.debug("Bundled-component research skipped for item {}: AI research is unavailable in this deployment",
                item.getId());
        return 0;
    }
}
