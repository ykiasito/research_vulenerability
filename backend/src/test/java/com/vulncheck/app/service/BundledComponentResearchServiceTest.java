package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.vulncheck.app.entity.ResearchJobItem;
import org.junit.jupiter.api.Test;

/**
 * Closed-mode B2 (docs/spec/closed-mode-plan.md §9-2): {@link BundledComponentResearchService} was
 * gutted down to an unconditional no-op — every AI-response-shaped test this class used to have
 * (changelog discovery, component extraction/validation, CPE/OSV adjudication, etc.) tested
 * behavior that no longer exists. What remains is the one contract every caller still relies on: no
 * findings are ever persisted.
 */
class BundledComponentResearchServiceTest {

    private final BundledComponentResearchService service = new BundledComponentResearchService();

    private ResearchJobItem item() {
        ResearchJobItem item = new ResearchJobItem();
        item.setId(9L);
        item.setJobId(1L);
        item.setProductName("Chocolatey CLI");
        item.setVersion("4.6.0");
        item.setUsageText("used to install packages");
        return item;
    }

    @Test
    void alwaysFindsNothing() {
        int count = service.research(item(), 7L);

        assertThat(count).isZero();
    }
}
