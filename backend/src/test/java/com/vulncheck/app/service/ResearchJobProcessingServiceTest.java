package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.vulncheck.app.entity.IdentifiedProduct;
import com.vulncheck.app.entity.ResearchJob;
import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.repository.IdentifiedProductRepository;
import com.vulncheck.app.repository.ResearchJobItemRepository;
import com.vulncheck.app.repository.ResearchJobRepository;
import com.vulncheck.app.service.Stage2VulnerabilityResearchService.Stage2Result;
import com.vulncheck.app.service.nvd.NvdRateLimiter;
import com.vulncheck.app.service.registry.ExternalRegistryRateLimiter;
import com.vulncheck.app.service.vuln.GhsaRateLimiter;
import com.vulncheck.app.service.vuln.OsvRateLimiter;
import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Executor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Exercises {@link ResearchJobProcessingService}'s Stage4 firing policy end-to-end (via the public
 * {@link ResearchJobProcessingService#processJobAsync} entry point, since the decision itself lives
 * in the private {@code processItem}) — this is the actual policy consumer of {@link
 * Stage2VulnerabilityResearchService.Stage2Result#anySourceSucceeded()}; {@code
 * Stage2VulnerabilityResearchServiceTest} already covers the flag's own computation, but nothing
 * previously asserted that {@link ResearchJobProcessingService} reads it correctly.
 */
@ExtendWith(MockitoExtension.class)
class ResearchJobProcessingServiceTest {

    @Mock
    private ResearchJobRepository researchJobRepository;
    @Mock
    private ResearchJobItemRepository researchJobItemRepository;
    @Mock
    private IdentifiedProductRepository identifiedProductRepository;
    @Mock
    private Stage1IdentificationService stage1IdentificationService;
    @Mock
    private Stage2VulnerabilityResearchService stage2VulnerabilityResearchService;
    @Mock
    private Stage4WebSearchResearchService stage4WebSearchResearchService;
    @Mock
    private BundledComponentResearchService bundledComponentResearchService;
    @Mock
    private JobCostBudgetService jobCostBudgetService;

    // Runs item tasks synchronously on the calling (test) thread rather than a real thread pool —
    // keeps these tests deterministic (Mockito verify() below runs after processJobAsync returns,
    // which requires every dispatched item to have actually finished by then) without pulling in
    // the real itemProcessingExecutor bean; the concurrency behavior itself isn't what's under test
    // here (that's Stage2VulnerabilityResearchServiceTest/AsyncConfig's own responsibility).
    private final Executor itemProcessingExecutor = Runnable::run;

    private ResearchJobProcessingService newService() {
        return new ResearchJobProcessingService(researchJobRepository, researchJobItemRepository,
                identifiedProductRepository, stage1IdentificationService, stage2VulnerabilityResearchService,
                stage4WebSearchResearchService, bundledComponentResearchService, jobCostBudgetService, new NvdRateLimiter(),
                ExternalRegistryRateLimiter.disabledForTesting(), GhsaRateLimiter.disabledForTesting(),
                OsvRateLimiter.disabledForTesting(), itemProcessingExecutor);
    }

    private ResearchJob job(Long id, Long userId) {
        ResearchJob job = new ResearchJob();
        job.setId(id);
        job.setUserId(userId);
        job.setCsvFilename("test.csv");
        job.setStatus(ResearchJob.STATUS_PENDING);
        return job;
    }

    private ResearchJobItem item(Long id, Long jobId) {
        ResearchJobItem item = new ResearchJobItem();
        item.setId(id);
        item.setJobId(jobId);
        item.setProductName("lodash");
        item.setVersion("4.17.15");
        item.setUsageText("used in build tooling");
        item.setStatus(ResearchJobItem.STATUS_PENDING);
        return item;
    }

    // Defaults to a high (AI-arbitrated/version-confirmed-shaped) confidence so the pre-existing
    // Stage2-firing-policy tests below aren't incidentally exercising the confidence gate too —
    // see identifiedProductWithConfidence for tests that specifically target the gate.
    private IdentifiedProduct identifiedProduct(Long itemId) {
        return identifiedProductWithConfidence(itemId, new BigDecimal("0.95"));
    }

    private IdentifiedProduct identifiedProductWithConfidence(Long itemId, BigDecimal confidence) {
        IdentifiedProduct product = new IdentifiedProduct();
        product.setJobItemId(itemId);
        product.setEcosystem("npm");
        product.setPackageName("lodash");
        product.setConfidence(confidence);
        return product;
    }

    @Test
    void stage4FiresWhenSomeSourcesFailedButAtLeastOneGenuinelySucceededWithZeroFindings() {
        ResearchJob job = job(1L, 10L);
        ResearchJobItem item = item(5L, 1L);
        IdentifiedProduct product = identifiedProduct(5L);

        when(researchJobRepository.findById(1L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdAndStatusOrderById(1L, ResearchJobItem.STATUS_PENDING))
                .thenReturn(List.of(item));
        when(stage1IdentificationService.identify(item, 10L)).thenReturn(Optional.of(product));
        // Mixed outcome: some sources failed, but at least one genuinely completed and found
        // nothing — this is a real zero signal, so Stage4 must still fire.
        when(stage2VulnerabilityResearchService.research(item, product, 10L))
                .thenReturn(new Stage2Result(0, true));

        newService().processJobAsync(1L);

        verify(stage4WebSearchResearchService).research(eq(item), eq("npm"), eq("lodash"), eq(10L));
    }

    @Test
    void stage4IsSuppressedWhenEverySourceFailedEvenThoughFindingCountIsAlsoZero() {
        ResearchJob job = job(2L, 10L);
        ResearchJobItem item = item(6L, 2L);
        IdentifiedProduct product = identifiedProduct(6L);

        when(researchJobRepository.findById(2L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdAndStatusOrderById(2L, ResearchJobItem.STATUS_PENDING))
                .thenReturn(List.of(item));
        when(stage1IdentificationService.identify(item, 10L)).thenReturn(Optional.of(product));
        // Every source errored out (e.g. GHSA rate-limited, NVD/OSV/CVE.org all down) — findingCount
        // is 0 but there's no real "nothing found" signal, so the paid AI web-search must not fire.
        when(stage2VulnerabilityResearchService.research(item, product, 10L))
                .thenReturn(new Stage2Result(0, false));

        newService().processJobAsync(2L);

        verify(stage4WebSearchResearchService, never()).research(any(), any(), any(), anyLong());
    }

    @Test
    void stage4DoesNotFireWhenSourcesFoundRealFindings() {
        ResearchJob job = job(3L, 10L);
        ResearchJobItem item = item(7L, 3L);
        IdentifiedProduct product = identifiedProduct(7L);

        when(researchJobRepository.findById(3L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdAndStatusOrderById(3L, ResearchJobItem.STATUS_PENDING))
                .thenReturn(List.of(item));
        when(stage1IdentificationService.identify(item, 10L)).thenReturn(Optional.of(product));
        when(stage2VulnerabilityResearchService.research(item, product, 10L))
                .thenReturn(new Stage2Result(3, true));

        newService().processJobAsync(3L);

        verify(stage4WebSearchResearchService, never()).research(any(), any(), any(), anyLong());
    }

    @Test
    void stage4IsSuppressedForLowConfidenceIdentificationEvenWhenStage2GenuinelyFoundZero() {
        ResearchJob job = job(4L, 10L);
        ResearchJobItem item = item(8L, 4L);
        // Weak/static-only identification (e.g. an unconfirmed registry hit or CPE-only match) —
        // exactly the shape the OSV.dev audit found fabricated CVEs coming from.
        IdentifiedProduct product = identifiedProductWithConfidence(8L, new BigDecimal("0.6"));

        when(researchJobRepository.findById(4L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdAndStatusOrderById(4L, ResearchJobItem.STATUS_PENDING))
                .thenReturn(List.of(item));
        when(stage1IdentificationService.identify(item, 10L)).thenReturn(Optional.of(product));
        when(stage2VulnerabilityResearchService.research(item, product, 10L))
                .thenReturn(new Stage2Result(0, true));

        newService().processJobAsync(4L);

        verify(stage4WebSearchResearchService, never()).research(any(), any(), any(), anyLong());
    }

    @Test
    void itemIsMarkedSourcesFailedWhenEverySourceFailed() {
        // The gap this asserts against: before this reason field existed, an item where every
        // Stage2 source failed persisted (and rendered) identically to a genuine zero-findings
        // result — a false-negative security report, since the user would see "no vulnerabilities"
        // for an item that was never actually checked.
        ResearchJob job = job(6L, 10L);
        ResearchJobItem item = item(10L, 6L);
        IdentifiedProduct product = identifiedProduct(10L);

        when(researchJobRepository.findById(6L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdAndStatusOrderById(6L, ResearchJobItem.STATUS_PENDING))
                .thenReturn(List.of(item));
        when(stage1IdentificationService.identify(item, 10L)).thenReturn(Optional.of(product));
        when(stage2VulnerabilityResearchService.research(item, product, 10L))
                .thenReturn(new Stage2Result(0, false));

        newService().processJobAsync(6L);

        assertThat(item.getResearchIncompleteReason()).isEqualTo(ResearchJobItem.INCOMPLETE_REASON_SOURCES_FAILED);
        assertThat(item.isResearchIncomplete()).isTrue();
        // Saved twice: once for the Stage1 identification status, once for the
        // researchIncompleteReason set after Stage2 — see processItem. Stage4 isn't reached here
        // (anySourceSucceeded is false), so there's no third save from the confidence gate.
        verify(researchJobItemRepository, times(2)).save(item);
    }

    @Test
    void itemIsMarkedIdentificationTooWeakWhenStage4SkippedForLowConfidence() {
        // The bug this asserts against: Stage4's confidence gate (added after the SOURCES_FAILED
        // fix above) reintroduced the same false-negative rendering bug one file away — an item with
        // a weak identification, where Stage2 genuinely found zero and Stage4 is deliberately
        // skipped, must not render identically to a fully-verified clean result.
        ResearchJob job = job(8L, 10L);
        ResearchJobItem item = item(12L, 8L);
        IdentifiedProduct product = identifiedProductWithConfidence(12L, new BigDecimal("0.5"));

        when(researchJobRepository.findById(8L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdAndStatusOrderById(8L, ResearchJobItem.STATUS_PENDING))
                .thenReturn(List.of(item));
        when(stage1IdentificationService.identify(item, 10L)).thenReturn(Optional.of(product));
        when(stage2VulnerabilityResearchService.research(item, product, 10L))
                .thenReturn(new Stage2Result(0, true));

        newService().processJobAsync(8L);

        assertThat(item.getResearchIncompleteReason())
                .isEqualTo(ResearchJobItem.INCOMPLETE_REASON_IDENTIFICATION_TOO_WEAK);
        assertThat(item.isResearchIncomplete()).isTrue();
        verify(stage4WebSearchResearchService, never()).research(any(), any(), any(), anyLong());
    }

    @Test
    void itemHasNoIncompleteReasonWhenAtLeastOneSourceSucceeded() {
        // Regression guard: a genuine "checked and found nothing" result (at least one source
        // completed) must not be flagged incomplete, whether or not other sources also failed.
        ResearchJob job = job(7L, 10L);
        ResearchJobItem item = item(11L, 7L);
        IdentifiedProduct product = identifiedProduct(11L);

        when(researchJobRepository.findById(7L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdAndStatusOrderById(7L, ResearchJobItem.STATUS_PENDING))
                .thenReturn(List.of(item));
        when(stage1IdentificationService.identify(item, 10L)).thenReturn(Optional.of(product));
        when(stage2VulnerabilityResearchService.research(item, product, 10L))
                .thenReturn(new Stage2Result(0, true));

        newService().processJobAsync(7L);

        assertThat(item.getResearchIncompleteReason()).isNull();
        assertThat(item.isResearchIncomplete()).isFalse();
    }

    @Test
    void stage4StillFiresForHighConfidenceIdentificationWhenStage2GenuinelyFoundZero() {
        ResearchJob job = job(5L, 10L);
        ResearchJobItem item = item(9L, 5L);
        // AI-arbitrated/version-confirmed-shaped identification — the audit found zero fabrications
        // in this bucket, so the gate must not suppress Stage4 here.
        IdentifiedProduct product = identifiedProductWithConfidence(9L, new BigDecimal("0.95"));

        when(researchJobRepository.findById(5L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdAndStatusOrderById(5L, ResearchJobItem.STATUS_PENDING))
                .thenReturn(List.of(item));
        when(stage1IdentificationService.identify(item, 10L)).thenReturn(Optional.of(product));
        when(stage2VulnerabilityResearchService.research(item, product, 10L))
                .thenReturn(new Stage2Result(0, true));

        newService().processJobAsync(5L);

        verify(stage4WebSearchResearchService).research(eq(item), eq("npm"), eq("lodash"), eq(10L));
        // Fully verified: Stage2 succeeded and Stage4 actually ran, so there's no incomplete
        // reason — this is the genuine all-clear case the 🟢 branch must be reserved for.
        assertThat(item.getResearchIncompleteReason()).isNull();
    }

    // --- Task backlog item 102 (2026-08-31): Stage4's own "never actually ran" exits (no Claude API
    // key / job budget exhausted) must not render identically to a genuine all-clear ------------

    @Test
    void itemIsMarkedAiNotAvailableWhenStage4HasNoApiKeyConfigured() {
        // The gap this asserts against: an unconfigured Claude API key is this app's default state,
        // so without this, every Stage2-zero-findings item silently rendered as a fully-verified
        // all-clear even though the AI verification pass never ran at all.
        ResearchJob job = job(9L, 10L);
        ResearchJobItem item = item(13L, 9L);
        IdentifiedProduct product = identifiedProduct(13L);

        when(researchJobRepository.findById(9L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdAndStatusOrderById(9L, ResearchJobItem.STATUS_PENDING))
                .thenReturn(List.of(item));
        when(stage1IdentificationService.identify(item, 10L)).thenReturn(Optional.of(product));
        when(stage2VulnerabilityResearchService.research(item, product, 10L))
                .thenReturn(new Stage2Result(0, true));
        when(stage4WebSearchResearchService.research(item, "npm", "lodash", 10L))
                .thenReturn(new Stage4WebSearchResearchService.Stage4ResearchResult(
                        0, ResearchJobItem.INCOMPLETE_REASON_AI_NOT_AVAILABLE));

        newService().processJobAsync(9L);

        assertThat(item.getResearchIncompleteReason()).isEqualTo(ResearchJobItem.INCOMPLETE_REASON_AI_NOT_AVAILABLE);
        assertThat(item.isResearchIncomplete()).isTrue();
    }

    @Test
    void itemIsMarkedBudgetExhaustedWhenStage4SkipsForBudget() {
        ResearchJob job = job(14L, 10L);
        ResearchJobItem item = item(18L, 14L);
        IdentifiedProduct product = identifiedProduct(18L);

        when(researchJobRepository.findById(14L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdAndStatusOrderById(14L, ResearchJobItem.STATUS_PENDING))
                .thenReturn(List.of(item));
        when(stage1IdentificationService.identify(item, 10L)).thenReturn(Optional.of(product));
        when(stage2VulnerabilityResearchService.research(item, product, 10L))
                .thenReturn(new Stage2Result(0, true));
        when(stage4WebSearchResearchService.research(item, "npm", "lodash", 10L))
                .thenReturn(new Stage4WebSearchResearchService.Stage4ResearchResult(
                        0, ResearchJobItem.INCOMPLETE_REASON_BUDGET_EXHAUSTED));

        newService().processJobAsync(14L);

        assertThat(item.getResearchIncompleteReason()).isEqualTo(ResearchJobItem.INCOMPLETE_REASON_BUDGET_EXHAUSTED);
        assertThat(item.isResearchIncomplete()).isTrue();
    }

    // --- Task backlog item 121 (2026-08-31): unlike the two orderly skips above, Stage4 can also be
    // attempted and then throw (LLM service down, timeout, ...) -------------------------------------

    @Test
    void itemIsMarkedAiCallFailedWhenStage4ThrowsAnException() {
        // The gap this asserts against: ResearchJobProcessingService's Stage4 try/catch previously
        // only logged the exception, leaving researchIncompleteReason at the null Stage2 already set
        // — indistinguishable from a genuine, fully-verified all-clear. This condition is more likely
        // in practice than a fully exhausted budget, since it covers every transient LLM microservice
        // failure, not just a rare cap.
        ResearchJob job = job(15L, 10L);
        ResearchJobItem item = item(19L, 15L);
        IdentifiedProduct product = identifiedProduct(19L);

        when(researchJobRepository.findById(15L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdAndStatusOrderById(15L, ResearchJobItem.STATUS_PENDING))
                .thenReturn(List.of(item));
        when(stage1IdentificationService.identify(item, 10L)).thenReturn(Optional.of(product));
        when(stage2VulnerabilityResearchService.research(item, product, 10L))
                .thenReturn(new Stage2Result(0, true));
        when(stage4WebSearchResearchService.research(item, "npm", "lodash", 10L))
                .thenThrow(new RuntimeException("LLM service unavailable"));

        newService().processJobAsync(15L);

        assertThat(item.getResearchIncompleteReason()).isEqualTo(ResearchJobItem.INCOMPLETE_REASON_AI_CALL_FAILED);
        assertThat(item.isResearchIncomplete()).isTrue();
    }

    @Test
    void itemIsMarkedAiCallFailedWhenStage4ReportsTheClientCallFailed() {
        // PR #68 item 121 REVISE (senior review 2026-09-01): unlike itemIsMarkedAiCallFailedWhenStage4ThrowsAnException
        // above (an exception thrown outside Stage4WebSearchResearchService's own try/catch), this
        // covers the primary failure path -- LlmServiceClient#webSearchResearch itself reporting the
        // LLM call failed (Optional.empty()) -- which Stage4WebSearchResearchService turns into a
        // Stage4ResearchResult carrying AI_CALL_FAILED without ever throwing, so this must be routed
        // through the stage4Result.incompleteReason() branch, not stage4Threw.
        ResearchJob job = job(16L, 10L);
        ResearchJobItem item = item(20L, 16L);
        IdentifiedProduct product = identifiedProduct(20L);

        when(researchJobRepository.findById(16L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdAndStatusOrderById(16L, ResearchJobItem.STATUS_PENDING))
                .thenReturn(List.of(item));
        when(stage1IdentificationService.identify(item, 10L)).thenReturn(Optional.of(product));
        when(stage2VulnerabilityResearchService.research(item, product, 10L))
                .thenReturn(new Stage2Result(0, true));
        when(stage4WebSearchResearchService.research(item, "npm", "lodash", 10L))
                .thenReturn(new Stage4WebSearchResearchService.Stage4ResearchResult(
                        0, ResearchJobItem.INCOMPLETE_REASON_AI_CALL_FAILED));

        newService().processJobAsync(16L);

        assertThat(item.getResearchIncompleteReason()).isEqualTo(ResearchJobItem.INCOMPLETE_REASON_AI_CALL_FAILED);
        assertThat(item.isResearchIncomplete()).isTrue();
    }

    // --- Task backlog item 128 (2026-09-01): the hint-based Stage4 call site (UNIDENTIFIED item,
    // Tier3-recognized platform hint) discarded Stage4ResearchResult entirely, the same class of bug
    // item 121 fixed for the IDENTIFIED call site above ------------------------------------------

    @Test
    void hintBasedItemIsMarkedAiCallFailedWhenStage4ReportsTheClientCallFailed() {
        ResearchJob job = job(17L, 10L);
        ResearchJobItem item = item(21L, 17L);
        item.setHintPlatform("vscode-marketplace");
        item.setHintIdentifier("some.extension-id");

        when(researchJobRepository.findById(17L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdAndStatusOrderById(17L, ResearchJobItem.STATUS_PENDING))
                .thenReturn(List.of(item));
        when(stage1IdentificationService.identify(item, 10L)).thenReturn(Optional.empty());
        when(stage4WebSearchResearchService.research(item, "vscode-marketplace", "some.extension-id", 10L))
                .thenReturn(new Stage4WebSearchResearchService.Stage4ResearchResult(
                        0, ResearchJobItem.INCOMPLETE_REASON_AI_CALL_FAILED));

        newService().processJobAsync(17L);

        assertThat(item.getStatus()).isEqualTo(ResearchJobItem.STATUS_UNIDENTIFIED);
        assertThat(item.getResearchIncompleteReason()).isEqualTo(ResearchJobItem.INCOMPLETE_REASON_AI_CALL_FAILED);
        assertThat(item.isResearchIncomplete()).isTrue();
    }

    @Test
    void hintBasedItemIsMarkedAiCallFailedWhenStage4ThrowsAnException() {
        ResearchJob job = job(18L, 10L);
        ResearchJobItem item = item(22L, 18L);
        item.setHintPlatform("vscode-marketplace");
        item.setHintIdentifier("some.extension-id");

        when(researchJobRepository.findById(18L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdAndStatusOrderById(18L, ResearchJobItem.STATUS_PENDING))
                .thenReturn(List.of(item));
        when(stage1IdentificationService.identify(item, 10L)).thenReturn(Optional.empty());
        when(stage4WebSearchResearchService.research(item, "vscode-marketplace", "some.extension-id", 10L))
                .thenThrow(new RuntimeException("LLM service unavailable"));

        newService().processJobAsync(18L);

        assertThat(item.getResearchIncompleteReason()).isEqualTo(ResearchJobItem.INCOMPLETE_REASON_AI_CALL_FAILED);
        assertThat(item.isResearchIncomplete()).isTrue();
    }

    @Test
    void hintBasedItemHasNoIncompleteReasonWhenStage4RunsToCompletion() {
        // Regression guard: a hint-based Stage4 pass that actually completes (whether or not it
        // found anything) must not be flagged incomplete — only a skipped/failed pass should be.
        ResearchJob job = job(19L, 10L);
        ResearchJobItem item = item(23L, 19L);
        item.setHintPlatform("vscode-marketplace");
        item.setHintIdentifier("some.extension-id");

        when(researchJobRepository.findById(19L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdAndStatusOrderById(19L, ResearchJobItem.STATUS_PENDING))
                .thenReturn(List.of(item));
        when(stage1IdentificationService.identify(item, 10L)).thenReturn(Optional.empty());
        when(stage4WebSearchResearchService.research(item, "vscode-marketplace", "some.extension-id", 10L))
                .thenReturn(new Stage4WebSearchResearchService.Stage4ResearchResult(0, null));

        newService().processJobAsync(19L);

        assertThat(item.getResearchIncompleteReason()).isNull();
        assertThat(item.isResearchIncomplete()).isFalse();
    }

    @Test
    void bundledComponentResearchDoesNotFireWhenJobHasNotOptedIn() {
        ResearchJob job = job(30L, 10L);
        ResearchJobItem item = item(50L, 30L);
        IdentifiedProduct product = identifiedProduct(50L);

        when(researchJobRepository.findById(30L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdAndStatusOrderById(30L, ResearchJobItem.STATUS_PENDING))
                .thenReturn(List.of(item));
        when(stage1IdentificationService.identify(item, 10L)).thenReturn(Optional.of(product));
        when(stage2VulnerabilityResearchService.research(item, product, 10L))
                .thenReturn(new Stage2Result(0, true));

        newService().processJobAsync(30L);

        verify(bundledComponentResearchService, never()).research(any(), anyLong());
        verify(jobCostBudgetService, never()).startBundledComponentBudget(any(), anyInt());
        verify(jobCostBudgetService, never()).endBundledComponentBudget(any());
    }

    @Test
    void bundledComponentResearchFiresInTheSameSlotAsStage4WhenOptedIn() {
        ResearchJob job = job(31L, 10L);
        job.setBundledComponentCheckEnabled(true);
        ResearchJobItem item = item(51L, 31L);
        IdentifiedProduct product = identifiedProduct(51L);

        when(researchJobRepository.findById(31L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdAndStatusOrderById(31L, ResearchJobItem.STATUS_PENDING))
                .thenReturn(List.of(item));
        when(stage1IdentificationService.identify(item, 10L)).thenReturn(Optional.of(product));
        when(stage2VulnerabilityResearchService.research(item, product, 10L))
                .thenReturn(new Stage2Result(0, true));

        newService().processJobAsync(31L);

        verify(bundledComponentResearchService).research(item, 10L);
        verify(jobCostBudgetService).startBundledComponentBudget(31L, 1);
        verify(jobCostBudgetService).endBundledComponentBudget(31L);
    }

    @Test
    void bundledComponentResearchDoesNotFireWhenOptedInButIdentificationConfidenceIsTooWeak() {
        // Same confidence gate Stage4 uses (STAGE4_MIN_IDENTIFICATION_CONFIDENCE) — bundled-
        // component research fires from inside that same else-branch, so a weak identification must
        // suppress it exactly like it suppresses Stage4.
        ResearchJob job = job(32L, 10L);
        job.setBundledComponentCheckEnabled(true);
        ResearchJobItem item = item(52L, 32L);
        IdentifiedProduct product = identifiedProductWithConfidence(52L, new BigDecimal("0.5"));

        when(researchJobRepository.findById(32L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdAndStatusOrderById(32L, ResearchJobItem.STATUS_PENDING))
                .thenReturn(List.of(item));
        when(stage1IdentificationService.identify(item, 10L)).thenReturn(Optional.of(product));
        when(stage2VulnerabilityResearchService.research(item, product, 10L))
                .thenReturn(new Stage2Result(0, true));

        newService().processJobAsync(32L);

        verify(bundledComponentResearchService, never()).research(any(), anyLong());
    }

    @Test
    void bundledComponentResearchDoesNotFireWhenStage2FoundRealFindings() {
        ResearchJob job = job(33L, 10L);
        job.setBundledComponentCheckEnabled(true);
        ResearchJobItem item = item(53L, 33L);
        IdentifiedProduct product = identifiedProduct(53L);

        when(researchJobRepository.findById(33L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdAndStatusOrderById(33L, ResearchJobItem.STATUS_PENDING))
                .thenReturn(List.of(item));
        when(stage1IdentificationService.identify(item, 10L)).thenReturn(Optional.of(product));
        when(stage2VulnerabilityResearchService.research(item, product, 10L))
                .thenReturn(new Stage2Result(3, true));

        newService().processJobAsync(33L);

        verify(bundledComponentResearchService, never()).research(any(), anyLong());
    }

    /** Builds {@code count} registry-resolved (ecosystem+purl set) IdentifiedProducts for job
     *  {@code jobId}, with the first {@code confirmedCount} of them version-confirmed and the rest
     *  not — and stubs both repository calls {@link ResearchJobProcessingService
     *  #computeVersionPlausibilityWarning} reads at job completion. */
    private void stubRegistryResolvedItems(Long jobId, int count, int confirmedCount) {
        List<ResearchJobItem> allItems = new java.util.ArrayList<>();
        List<IdentifiedProduct> products = new java.util.ArrayList<>();
        for (int i = 0; i < count; i++) {
            ResearchJobItem it = item(90_000L + i, jobId);
            allItems.add(it);
            IdentifiedProduct product = new IdentifiedProduct();
            product.setJobItemId(it.getId());
            product.setEcosystem("npm");
            product.setPurl("pkg:npm/item" + i + "@1.0." + i);
            product.setVersionConfirmed(i < confirmedCount);
            products.add(product);
        }
        when(researchJobItemRepository.findByJobIdOrderById(jobId)).thenReturn(allItems);
        when(identifiedProductRepository.findByJobItemIdIn(any())).thenReturn(products);
    }

    @Test
    void versionPlausibilityWarningFiresForJob30ShapedData() {
        // Calibration target (senior review): job 30's real shape — 864 registry-resolved items,
        // only ~2.3% (20) version-confirmed — must fire the warning.
        ResearchJob job = job(20L, 10L);
        when(researchJobRepository.findById(20L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdAndStatusOrderById(20L, ResearchJobItem.STATUS_PENDING))
                .thenReturn(List.of());
        stubRegistryResolvedItems(20L, 864, 20);

        newService().processJobAsync(20L);

        assertThat(job.isVersionPlausibilityWarning()).isTrue();
    }

    @Test
    void versionPlausibilityWarningDoesNotFireForJob31ShapedData() {
        // Calibration target (senior review): jobs 31/34-40's real shape — well over the 30-item
        // floor, 85-97% version-confirmed — must NOT fire the warning.
        ResearchJob job = job(21L, 10L);
        when(researchJobRepository.findById(21L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdAndStatusOrderById(21L, ResearchJobItem.STATUS_PENDING))
                .thenReturn(List.of());
        stubRegistryResolvedItems(21L, 200, 180); // 90% confirmed

        newService().processJobAsync(21L);

        assertThat(job.isVersionPlausibilityWarning()).isFalse();
    }

    @Test
    void versionPlausibilityWarningDoesNotFireBelowTheThirtyItemFloorEvenWithALowConfirmedRate() {
        // Calibration target (senior review): the tiny desktop jobs 32/33 never reach the 30-item
        // registry-resolved floor at all — a low confirmed rate among too few items must not fire.
        ResearchJob job = job(22L, 10L);
        when(researchJobRepository.findById(22L)).thenReturn(Optional.of(job));
        when(researchJobItemRepository.findByJobIdAndStatusOrderById(22L, ResearchJobItem.STATUS_PENDING))
                .thenReturn(List.of());
        stubRegistryResolvedItems(22L, 10, 0); // 0% confirmed, but only 10 items

        newService().processJobAsync(22L);

        assertThat(job.isVersionPlausibilityWarning()).isFalse();
    }
}
