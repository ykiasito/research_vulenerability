package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.vulncheck.app.entity.IdentifiedProduct;
import com.vulncheck.app.entity.ResearchJobItem;
import java.math.BigDecimal;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * Closed-mode B2 (docs/spec/closed-mode-plan.md §9-2): {@link HighConfidenceVerificationService}
 * was gutted down to an unconditional no-op — every AI-verdict-shaped test this class used to have
 * (confirmed/ambiguous/incorrect outcomes, verification_note truncation, etc.) tested behavior that
 * no longer exists. What remains is the one contract every caller still relies on: the input
 * product always comes back unchanged, for any input shape.
 */
class HighConfidenceVerificationServiceTest {

    private final HighConfidenceVerificationService service = new HighConfidenceVerificationService();

    private ResearchJobItem item() {
        ResearchJobItem item = new ResearchJobItem();
        item.setId(11L);
        item.setJobId(1L);
        item.setProductName("Zoom");
        item.setVersion("6.1.0");
        item.setUsageText("video conferencing client");
        return item;
    }

    private IdentifiedProduct staticProductWithCpe(BigDecimal confidence, String ecosystem) {
        IdentifiedProduct product = new IdentifiedProduct();
        product.setJobItemId(11L);
        product.setMethod(IdentifiedProduct.METHOD_STATIC);
        product.setCpe("cpe:2.3:a:zoom:zoom:6.1.0:*:*:*:*:*:*:*");
        product.setConfidence(confidence);
        product.setEcosystem(ecosystem);
        return product;
    }

    @Test
    void alwaysReturnsTheGivenProductUnchanged() {
        IdentifiedProduct product = staticProductWithCpe(new BigDecimal("0.95"), null);

        Optional<IdentifiedProduct> result = service.verifyIfEligible(item(), product, 3L);

        assertThat(result).contains(product);
        assertThat(product.getVerificationStatus()).isNull();
        assertThat(product.getVerificationNote()).isNull();
        assertThat(product.getCpe()).isNotNull();
    }

    @Test
    void alwaysReturnsTheGivenProductUnchangedRegardlessOfMethodOrConfidence() {
        IdentifiedProduct product = staticProductWithCpe(new BigDecimal("0.6"), "npm");
        product.setMethod(IdentifiedProduct.METHOD_LLM_DISAMBIGUATE);

        Optional<IdentifiedProduct> result = service.verifyIfEligible(item(), product, 3L);

        assertThat(result).contains(product);
    }
}
