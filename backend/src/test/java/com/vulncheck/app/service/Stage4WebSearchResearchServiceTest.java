package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.vulncheck.app.entity.ResearchJobItem;
import org.junit.jupiter.api.Test;

/**
 * Closed-mode B2 (docs/spec/closed-mode-plan.md §9-2): {@link Stage4WebSearchResearchService} was
 * gutted down to an unconditional "AI unavailable" no-op — every AI-response-shaped test this class
 * used to have (bare-CVE-id dedup, citation URL sanitization, AI-call-failed vs. genuinely-empty
 * distinction, etc.) tested behavior that no longer exists. What remains is the one contract every
 * caller still relies on: no findings are ever persisted, and the incomplete reason always reports
 * AI as unavailable.
 */
class Stage4WebSearchResearchServiceTest {

    private final Stage4WebSearchResearchService service = new Stage4WebSearchResearchService();

    private ResearchJobItem item() {
        ResearchJobItem item = new ResearchJobItem();
        item.setId(9L);
        item.setJobId(1L);
        item.setProductName("some-tool");
        item.setVersion("1.2.3");
        item.setUsageText("usage");
        return item;
    }

    @Test
    void alwaysSkipsWithAiNotAvailable() {
        Stage4WebSearchResearchService.Stage4ResearchResult result = service.research(item(), "npm", "some-tool", 7L);

        assertThat(result.persistedCount()).isZero();
        assertThat(result.incompleteReason()).isEqualTo(ResearchJobItem.INCOMPLETE_REASON_AI_NOT_AVAILABLE);
    }
}
