package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.vulncheck.app.entity.IdentifiedProduct;
import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.repository.IdentifiedProductRepository;
import com.vulncheck.app.service.llm.LlmServiceClient;
import com.vulncheck.app.service.llm.LlmServiceModels.AmbiguousCandidateDto;
import com.vulncheck.app.service.llm.LlmServiceModels.VerifyHighConfidenceResponse;
import com.vulncheck.app.service.llm.LlmServiceModels.UsageDto;
import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class HighConfidenceVerificationServiceTest {

    private static final Long USER_ID = 3L;
    private static final UsageDto TEST_USAGE = new UsageDto(200, 100, 1);

    @Mock
    private UserApiKeyService userApiKeyService;

    @Mock
    private LlmServiceClient llmServiceClient;

    @Mock
    private JobCostBudgetService jobCostBudgetService;

    @Mock
    private IdentifiedProductRepository identifiedProductRepository;

    @BeforeEach
    void allowAiSpendByDefault() {
        // REVISE item 1 (senior review 2026-08-29): verification now reserves against its own
        // separate ledger (tryReserveVerification), not the always-on MAIN budget (tryReserve).
        lenient().when(jobCostBudgetService.tryReserveVerification(any(), any())).thenReturn(true);
        lenient().when(userApiKeyService.getClaudeApiKey(USER_ID)).thenReturn(Optional.of("sk-ant-test"));
        lenient().when(identifiedProductRepository.save(any(IdentifiedProduct.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
    }

    private HighConfidenceVerificationService service(boolean enabled) {
        HighConfidenceVerificationService service = new HighConfidenceVerificationService(
                userApiKeyService, llmServiceClient, jobCostBudgetService, identifiedProductRepository);
        ReflectionTestUtils.setField(service, "enabled", enabled);
        ReflectionTestUtils.setField(service, "confidenceThreshold", 0.95);
        ReflectionTestUtils.setField(service, "downgradeFactor", 0.5);
        return service;
    }

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
    void noOpWhenFeatureDisabled() {
        IdentifiedProduct product = staticProductWithCpe(new BigDecimal("0.95"), null);

        Optional<IdentifiedProduct> result = service(false).verifyIfEligible(item(), product, USER_ID);

        assertThat(result).contains(product);
        assertThat(product.getVerificationStatus()).isNull();
        verifyNoInteractions(llmServiceClient);
    }

    @Test
    void noOpWhenMethodIsNotStatic() {
        IdentifiedProduct product = staticProductWithCpe(new BigDecimal("0.95"), null);
        product.setMethod(IdentifiedProduct.METHOD_LLM_DISAMBIGUATE);

        Optional<IdentifiedProduct> result = service(true).verifyIfEligible(item(), product, USER_ID);

        assertThat(result).contains(product);
        verifyNoInteractions(llmServiceClient);
    }

    @Test
    void noOpWhenConfidenceBelowThreshold() {
        IdentifiedProduct product = staticProductWithCpe(new BigDecimal("0.6"), null);

        Optional<IdentifiedProduct> result = service(true).verifyIfEligible(item(), product, USER_ID);

        assertThat(result).contains(product);
        verifyNoInteractions(llmServiceClient);
    }

    @Test
    void noOpWhenNoCpeToVerify() {
        IdentifiedProduct product = staticProductWithCpe(new BigDecimal("0.95"), "npm");
        product.setCpe(null);

        Optional<IdentifiedProduct> result = service(true).verifyIfEligible(item(), product, USER_ID);

        assertThat(result).contains(product);
        verifyNoInteractions(llmServiceClient);
    }

    @Test
    void noOpWhenNoApiKeyConfigured() {
        when(userApiKeyService.getClaudeApiKey(USER_ID)).thenReturn(Optional.empty());
        IdentifiedProduct product = staticProductWithCpe(new BigDecimal("0.95"), null);

        Optional<IdentifiedProduct> result = service(true).verifyIfEligible(item(), product, USER_ID);

        assertThat(result).contains(product);
        verifyNoInteractions(llmServiceClient);
    }

    @Test
    void noOpWhenBudgetExhausted() {
        when(jobCostBudgetService.tryReserveVerification(any(), any())).thenReturn(false);
        IdentifiedProduct product = staticProductWithCpe(new BigDecimal("0.95"), null);

        Optional<IdentifiedProduct> result = service(true).verifyIfEligible(item(), product, USER_ID);

        assertThat(result).contains(product);
        verifyNoInteractions(llmServiceClient);
    }

    @Test
    void confirmedVerdictLeavesMatchIntactButRecordsStatus() {
        IdentifiedProduct product = staticProductWithCpe(new BigDecimal("0.95"), "npm");
        when(llmServiceClient.verifyHighConfidence(eq("sk-ant-test"), any(), eq("zoom"), eq("zoom"), any()))
                .thenReturn(Optional.of(new VerifyHighConfidenceResponse(
                        "correct", "matches official product", null, null, List.of(), TEST_USAGE)));

        Optional<IdentifiedProduct> result = service(true).verifyIfEligible(item(), product, USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getVerificationStatus()).isEqualTo(IdentifiedProduct.VERIFICATION_CONFIRMED);
        assertThat(result.get().getCpe()).isNotNull();
        assertThat(result.get().getConfidence()).isEqualByComparingTo("0.95");
    }

    @Test
    void ambiguousVerdictFlagsForHumanReviewWithoutTouchingConfidenceOrCpe() {
        IdentifiedProduct product = staticProductWithCpe(new BigDecimal("0.95"), "npm");
        when(llmServiceClient.verifyHighConfidence(eq("sk-ant-test"), any(), eq("zoom"), eq("zoom"), any()))
                .thenReturn(Optional.of(new VerifyHighConfidenceResponse(
                        "ambiguous", "could be windows or mac build", null, null,
                        List.of(new AmbiguousCandidateDto("zoom", "zoom", "Windows版"),
                                new AmbiguousCandidateDto("zoom", "zoom_client_for_mac", "Mac版")),
                        TEST_USAGE)));

        Optional<IdentifiedProduct> result = service(true).verifyIfEligible(item(), product, USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getVerificationStatus()).isEqualTo(IdentifiedProduct.VERIFICATION_AMBIGUOUS);
        assertThat(result.get().getVerificationNote()).contains("Windows版").contains("Mac版");
        // Ambiguous is not "wrong" -- the existing candidate may well be correct, so nothing about
        // the match itself changes, only the flag.
        assertThat(result.get().getCpe()).isNotNull();
        assertThat(result.get().getConfidence()).isEqualByComparingTo("0.95");
    }

    @Test
    void incorrectVerdictWithRegistryFallbackDropsCpeAndDowngradesConfidence() {
        IdentifiedProduct product = staticProductWithCpe(new BigDecimal("0.95"), "npm");
        when(llmServiceClient.verifyHighConfidence(eq("sk-ant-test"), any(), eq("zoom"), eq("zoom"), any()))
                .thenReturn(Optional.of(new VerifyHighConfidenceResponse(
                        "incorrect", "wrong vendor entirely", "othervendor", "otherproduct", List.of(), TEST_USAGE)));

        Optional<IdentifiedProduct> result = service(true).verifyIfEligible(item(), product, USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getCpe()).isNull();
        assertThat(result.get().getVerificationStatus()).isEqualTo(IdentifiedProduct.VERIFICATION_INCORRECT);
        // 0.95 * 0.5 = 0.475
        assertThat(result.get().getConfidence()).isEqualByComparingTo("0.475");
        verify(identifiedProductRepository, never()).delete(any());
    }

    @Test
    void incorrectVerdictWithNoRegistryFallbackDemotesToUnidentified() {
        IdentifiedProduct product = staticProductWithCpe(new BigDecimal("0.95"), null);
        when(llmServiceClient.verifyHighConfidence(eq("sk-ant-test"), any(), eq("zoom"), eq("zoom"), any()))
                .thenReturn(Optional.of(new VerifyHighConfidenceResponse(
                        "incorrect", "wrong vendor entirely", null, null, List.of(), TEST_USAGE)));

        Optional<IdentifiedProduct> result = service(true).verifyIfEligible(item(), product, USER_ID);

        assertThat(result).isEmpty();
        verify(identifiedProductRepository).delete(product);
    }

    @Test
    void incorrectVerdictWithNoRegistryFallbackDemotesToUnidentifiedEvenWithAHighDowngradeFactor() {
        // REVISE item 4 (senior review 2026-08-29, PR #1): with the removed demotion-floor gate, a
        // downgradeFactor of 0.8 (0.95 * 0.8 = 0.76, which would have stayed above the old default
        // 0.5 floor) must still demote to UNIDENTIFIED when there's no registry fallback -- the CPE
        // was just dropped as implausible, so nothing is left to look vulnerabilities up against
        // regardless of how high the discounted confidence number happens to be.
        HighConfidenceVerificationService serviceWithHighDowngradeFactor = new HighConfidenceVerificationService(
                userApiKeyService, llmServiceClient, jobCostBudgetService, identifiedProductRepository);
        ReflectionTestUtils.setField(serviceWithHighDowngradeFactor, "enabled", true);
        ReflectionTestUtils.setField(serviceWithHighDowngradeFactor, "confidenceThreshold", 0.95);
        ReflectionTestUtils.setField(serviceWithHighDowngradeFactor, "downgradeFactor", 0.8);

        IdentifiedProduct product = staticProductWithCpe(new BigDecimal("0.95"), null);
        when(llmServiceClient.verifyHighConfidence(eq("sk-ant-test"), any(), eq("zoom"), eq("zoom"), any()))
                .thenReturn(Optional.of(new VerifyHighConfidenceResponse(
                        "incorrect", "wrong vendor entirely", null, null, List.of(), TEST_USAGE)));

        Optional<IdentifiedProduct> result = serviceWithHighDowngradeFactor.verifyIfEligible(item(), product, USER_ID);

        assertThat(result).isEmpty();
        verify(identifiedProductRepository).delete(product);
    }

    @Test
    void degradesToTrustingTheMatchWhenTheCallItselfFails() {
        IdentifiedProduct product = staticProductWithCpe(new BigDecimal("0.95"), null);
        when(llmServiceClient.verifyHighConfidence(eq("sk-ant-test"), any(), eq("zoom"), eq("zoom"), any()))
                .thenReturn(Optional.empty());

        Optional<IdentifiedProduct> result = service(true).verifyIfEligible(item(), product, USER_ID);

        assertThat(result).contains(product);
        assertThat(product.getVerificationStatus()).isNull();
    }
}
