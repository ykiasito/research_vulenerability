package com.vulncheck.app.service;

import com.vulncheck.app.entity.IdentifiedProduct;
import com.vulncheck.app.entity.ResearchJobItem;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * Closed-mode B2 (docs/spec/closed-mode-plan.md §9-2): this backstop existed purely to run an extra
 * AI+web_search plausibility check (via the Python {@code llm-service}) against a high-confidence
 * static CPE match. It was already off by default and always degraded to leaving the match
 * completely untouched whenever no Claude key was configured — closed mode never has one, so {@link
 * #verifyIfEligible} now always takes that exact same fallback unconditionally, with no {@code
 * enabled}/threshold/downgrade-factor configuration left to consult at all.
 */
@Service
public class HighConfidenceVerificationService {

    /**
     * Always returns {@code product} unchanged — see this class's own javadoc. Callers must still
     * treat the return value as the item's final Stage1 result (never actually {@link
     * Optional#empty()} here, but kept as {@code Optional} so every call site's existing {@code
     * flatMap}/{@code Optional}-based composition keeps compiling unchanged).
     *
     * @param product the already-persisted static match; never null
     */
    public Optional<IdentifiedProduct> verifyIfEligible(ResearchJobItem item, IdentifiedProduct product, Long userId) {
        return Optional.of(product);
    }
}
