package com.vulncheck.app.service;

import com.vulncheck.app.entity.IdentifiedProduct;
import com.vulncheck.app.entity.ResearchJob;
import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.repository.IdentifiedProductRepository;
import com.vulncheck.app.repository.ResearchJobItemRepository;
import com.vulncheck.app.repository.ResearchJobRepository;
import com.vulncheck.app.service.nvd.NvdRateLimiter;
import com.vulncheck.app.service.registry.ExternalRegistryRateLimiter;
import com.vulncheck.app.service.vuln.GhsaRateLimiter;
import com.vulncheck.app.service.vuln.OsvRateLimiter;
import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

/**
 * Runs Stage1 identification (Tier1 static, with Tier2/3 LLM fallback), then Stage2 vulnerability
 * research, then Stage4 LLM+web_search vulnerability research if Stage2 found nothing <em>and</em>
 * the item's identification is confident enough (see {@link #STAGE4_MIN_IDENTIFICATION_CONFIDENCE}),
 * for every item in a job, off the request thread. Stage3 (NVD keyword search) exists in code but
 * is not wired in yet — see the project notes on why it was held back pending an LLM relevance
 * filter.
 *
 * <p>An item that stays UNIDENTIFIED (no queryable ecosystem/CPE at all) still gets a Stage4 pass
 * if Tier3 left a platform hint ({@code hintPlatform}/{@code hintIdentifier}) — this is the only
 * way such an item still gets a vulnerability answer, using the AI-recognized platform identifier
 * (e.g. a VS Code Marketplace extension id) as the search scope instead of an ecosystem/package.
 *
 * <p>Every job gets a {@link JobCostBudgetService} allotment sized to its own item count
 * (target: $5/1,000 items) before processing starts; once exhausted, every AI call site across
 * Stage1/Stage4 degrades exactly like "no Claude key configured" for the rest of that job.
 *
 * <p>A job whose owner opted in ({@code ResearchJob#bundledComponentCheckEnabled}) additionally
 * gets {@link BundledComponentResearchService} fired from the same slot as Stage4, against its own
 * separate {@link JobCostBudgetService} allotment (see {@link JobCostBudgetService
 * #tryReserveBundledComponent}) — off by default and never drawing down the always-on budget above,
 * since this feature (formerly "Stage 3.5") roughly doubles per-item AI cost when it fires (see
 * {@code docs/spec/bundled-package-detection-plan.md}).
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ResearchJobProcessingService {

    /**
     * Stage4 (paid AI web-search) only fires for an identified item whose {@link
     * IdentifiedProduct#getConfidence()} is strictly above this threshold. A 42-finding audit
     * against OSV.dev found every fabricated/non-existent CVE (4/42, 10%) came from items with a
     * weak, static-only identification confidence of 0.5-0.6 (an unconfirmed registry hit or a
     * CPE-only match — see {@code CPE_MATCH_CONFIDENCE} and the registry client {@code
     * versionExists ? 0.95 : 0.5} constants in {@code Stage1IdentificationService} and the various
     * {@code RegistryClient}s); items with a strong (AI-arbitrated or version-confirmed, 0.95-0.99)
     * identification had zero fabrications among 16 sampled. 0.85 sits in the real gap this
     * codebase's confidence values actually produce — confirmed live against the
     * identified_products table: static/weak matches cluster at exactly 0.4/0.5/0.6, AI
     * disambiguation confidence clusters at 0.95-0.99 with only a handful of outliers in between
     * (0.7, 0.85) — so this cleanly separates "static or weakly-verified guess" from "AI-confirmed
     * or registry-version-confirmed" without needing to be tuned any finer. Below this bar, Stage4
     * is skipped exactly the way every other AI-tier call site here degrades when unavailable (no
     * Claude key / cost budget exhausted): logged, no exception, item simply doesn't get an AI
     * research pass.
     */
    static final BigDecimal STAGE4_MIN_IDENTIFICATION_CONFIDENCE = new BigDecimal("0.85");

    /**
     * Caps how many of one job's items can be submitted to {@code itemProcessingExecutor} (queue
     * capacity 5,000 — see {@code AsyncConfig}) at once, via {@link #processJobAsync}'s in-flight
     * {@link Semaphore}. Without this, a job with more items than the executor's queue can hold
     * submits every item's {@code CompletableFuture.runAsync} up front regardless of how many other
     * jobs are doing the same thing concurrently (up to 8, via {@code researchJobExecutor}) — enough
     * concurrently-large jobs can overrun the shared queue and throw {@code
     * RejectedExecutionException} synchronously out of the submission loop, which is exactly the
     * scenario {@link JobCostBudgetService#endJobBudget}'s tombstoning exists to make safe rather
     * than merely rare. 500 per job leaves comfortable headroom even at 8 concurrent jobs (worst
     * case 4,000 in-flight, versus a queue capacity of 5,000) without meaningfully limiting
     * throughput — items already only run 8-at-a-time regardless, this only bounds how many are
     * queued waiting for a turn.
     */
    static final int MAX_IN_FLIGHT_ITEMS_PER_JOB = 500;

    /**
     * Denominator floor for {@link #computeVersionPlausibilityWarning}: below this many
     * registry-resolved (ecosystem+purl present) items, a low confirmed-rate is too likely to be
     * sampling noise (e.g. one or two unconfirmed versions in a handful of items) to be worth
     * warning about. Calibrated against real job history (senior review): fires for job 30-shaped
     * data (2.3% confirmed, n=864) and correctly stays silent for the tiny desktop jobs 32/33,
     * which never reach this floor at all.
     */
    static final int MIN_REGISTRY_RESOLVED_ITEMS_FOR_VERSION_WARNING = 30;

    /**
     * Confirmed-rate ceiling for {@link #computeVersionPlausibilityWarning}: strictly below this
     * fraction of registry-resolved items having their exact version confirmed as a real published
     * release fires the warning. Calibrated against real job history (senior review): job 30
     * (2.3% confirmed) fires; jobs 31/34-40 (85-97% confirmed) do not.
     */
    static final double MAX_CONFIRMED_RATE_FOR_VERSION_WARNING = 0.5;

    private final ResearchJobRepository researchJobRepository;
    private final ResearchJobItemRepository researchJobItemRepository;
    private final IdentifiedProductRepository identifiedProductRepository;
    private final Stage1IdentificationService stage1IdentificationService;
    private final Stage2VulnerabilityResearchService stage2VulnerabilityResearchService;
    private final Stage4WebSearchResearchService stage4WebSearchResearchService;
    private final BundledComponentResearchService bundledComponentResearchService;
    private final JobCostBudgetService jobCostBudgetService;
    private final NvdRateLimiter nvdRateLimiter;
    private final ExternalRegistryRateLimiter externalRegistryRateLimiter;
    private final GhsaRateLimiter ghsaRateLimiter;
    private final OsvRateLimiter osvRateLimiter;

    @Qualifier("itemProcessingExecutor")
    private final Executor itemProcessingExecutor;

    /**
     * Only processes items still in {@code PENDING} — already-{@code IDENTIFIED}/
     * {@code UNIDENTIFIED} items are left untouched. This isn't just an optimization: it's what
     * makes this method safe to call again for a job that's already {@code PROCESSING} (see
     * {@link StuckJobResumer}), e.g. after the app was restarted mid-job (a redeploy killing the
     * in-flight thread — a real, observed operational gap, not hypothetical). Re-running a fresh
     * job is unaffected since all its items start out PENDING anyway.
     */
    @Async("researchJobExecutor")
    public void processJobAsync(Long jobId) {
        ResearchJob job = researchJobRepository.findById(jobId).orElse(null);
        if (job == null) {
            log.warn("processJobAsync called for missing job {}", jobId);
            return;
        }

        job.setStatus(ResearchJob.STATUS_PROCESSING);
        researchJobRepository.save(job);

        List<ResearchJobItem> items = researchJobItemRepository.findByJobIdAndStatusOrderById(jobId, ResearchJobItem.STATUS_PENDING);
        jobCostBudgetService.startJobBudget(jobId, items.size());
        // Only started for a job that explicitly opted in (see ResearchJob#bundledComponentCheckEnabled)
        // — JobCostBudgetService#tryReserveBundledComponent fails closed for every other job's id,
        // since this feature's budget must never be silently available to a job that didn't ask for it.
        if (job.isBundledComponentCheckEnabled()) {
            jobCostBudgetService.startBundledComponentBudget(jobId, items.size());
        }
        // High-confidence verification (REVISE item 1, senior review 2026-08-29, round 1) is a single
        // app-wide toggle (app.high-confidence-verification.enabled), not a per-job opt-in field
        // like bundled-component detection above — started unconditionally for every job, same as
        // the always-on MAIN budget. Its cost-cap-per-item-usd defaults to 0 (see
        // JobCostBudgetService#verificationCostCapPerItemUsd), so this is a harmless no-op budget
        // for every job unless an operator has explicitly configured a real cap.
        jobCostBudgetService.startVerificationBudget(jobId, items.size());

        long jobStartNanos = System.nanoTime();
        JobTimings timings = new JobTimings();
        long nvdWaitBaselineMs = nvdRateLimiter.cumulativeWaitMillis();
        long ghsaWaitBaselineMs = ghsaRateLimiter.cumulativeWaitMillis();
        long osvWaitBaselineMs = osvRateLimiter.cumulativeWaitMillis();
        Map<String, Long> registryWaitBaseline = externalRegistryRateLimiter.cumulativeWaitMillisByEcosystem();
        try {
            // Items within this one job are processed concurrently (bounded by
            // itemProcessingExecutor, currently 8 at a time) rather than one at a time — see
            // AsyncConfig's javadoc on itemProcessingExecutor for why this is a separate pool from
            // researchJobExecutor (job-level, 8 concurrent jobs) and registryLookupExecutor
            // (per-item registry fan-out). Every service processItem calls into
            // (Stage1/Stage2/Stage4/JobCostBudgetService, the external-call rate limiters) is a
            // stateless/thread-safe singleton already relied on for concurrent use across different
            // *jobs*, so concurrent items within one job is the same safety story, just a higher
            // degree of it. allOf(...).join() waits for every item to finish (success or already
            // internally-caught failure — see processItem's own per-stage try/catch) before the
            // budget teardown below runs, same ordering guarantee the sequential loop used to give
            // for free.
            //
            // Submission itself is bounded by inFlightPermits (see MAX_IN_FLIGHT_ITEMS_PER_JOB's
            // javadoc) rather than submitting every item up front: acquiring a permit blocks this
            // researchJobExecutor thread (harmless — it's already going to block on allOf().join()
            // below regardless) once this job alone has MAX_IN_FLIGHT_ITEMS_PER_JOB items queued or
            // running, releasing one permit per item as it finishes, so the shared
            // itemProcessingExecutor queue can never be overrun regardless of how many other jobs
            // are concurrently doing the same thing.
            Semaphore inFlightPermits = new Semaphore(MAX_IN_FLIGHT_ITEMS_PER_JOB);
            List<CompletableFuture<Void>> futures = new ArrayList<>(items.size());
            for (ResearchJobItem item : items) {
                inFlightPermits.acquireUninterruptibly();
                CompletableFuture<Void> future = CompletableFuture
                        .runAsync(() -> processItemSafely(item, job.getUserId(), job.isBundledComponentCheckEnabled(), timings),
                                itemProcessingExecutor)
                        .whenComplete((ignoredResult, ignoredEx) -> inFlightPermits.release());
                futures.add(future);
            }
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
        } finally {
            jobCostBudgetService.endJobBudget(jobId);
            if (job.isBundledComponentCheckEnabled()) {
                jobCostBudgetService.endBundledComponentBudget(jobId);
            }
            jobCostBudgetService.endVerificationBudget(jobId);
        }

        logJobTimings(jobId, items.size(), jobStartNanos, timings, nvdWaitBaselineMs, ghsaWaitBaselineMs,
                osvWaitBaselineMs, registryWaitBaseline);

        job.setStatus(ResearchJob.STATUS_COMPLETED);
        job.setCompletedAt(OffsetDateTime.now());
        job.setVersionPlausibilityWarning(computeVersionPlausibilityWarning(jobId));
        researchJobRepository.save(job);
    }

    /**
     * True when this job's uploaded CSV's version values look implausible enough to warn about:
     * at least {@link #MIN_REGISTRY_RESOLVED_ITEMS_FOR_VERSION_WARNING} of its items resolved to a
     * registry (both {@code ecosystem} and {@code purl} set — i.e. actually checkable against a
     * real package index, not a CPE-only or hint-only match) AND fewer than {@link
     * #MAX_CONFIRMED_RATE_FOR_VERSION_WARNING} of those had {@code versionConfirmed=true}. Re-reads
     * every item for the job (not just this invocation's freshly-processed batch — see {@link
     * #processJobAsync}'s own javadoc on why a resumed job's {@code items} list can be a strict
     * subset) so the check reflects the job's full, current result set regardless of how many
     * processing passes it took. Purely informational — see {@link ResearchJob
     * #versionPlausibilityWarning}'s javadoc; never affects job status or blocks completion.
     */
    private boolean computeVersionPlausibilityWarning(Long jobId) {
        List<Long> allItemIds = researchJobItemRepository.findByJobIdOrderById(jobId).stream()
                .map(ResearchJobItem::getId)
                .toList();
        List<IdentifiedProduct> registryResolved = identifiedProductRepository.findByJobItemIdIn(allItemIds).stream()
                .filter(p -> p.getEcosystem() != null && p.getPurl() != null)
                .toList();
        if (registryResolved.size() < MIN_REGISTRY_RESOLVED_ITEMS_FOR_VERSION_WARNING) {
            return false;
        }
        long confirmedCount = registryResolved.stream().filter(p -> Boolean.TRUE.equals(p.getVersionConfirmed())).count();
        double confirmedRate = (double) confirmedCount / registryResolved.size();
        return confirmedRate < MAX_CONFIRMED_RATE_FOR_VERSION_WARNING;
    }

    /**
     * Per-job accumulators for {@link #logJobTimings}: cumulative wall time actually spent inside
     * each pipeline stage across every item of one job, summed across however many items ran
     * concurrently — not a wall-clock span, since concurrent items' stage calls overlap in real
     * time. One instance per {@link #processJobAsync} invocation (never shared across jobs, unlike
     * the process-wide rate limiters), mutated concurrently from {@code itemProcessingExecutor}
     * threads, hence the atomics.
     */
    private static final class JobTimings {
        private final AtomicLong stage1Nanos = new AtomicLong();
        private final AtomicLong stage2Nanos = new AtomicLong();
        private final AtomicLong stage4Nanos = new AtomicLong();
        private final AtomicLong bundledComponentNanos = new AtomicLong();
    }

    /**
     * App-log instrumentation only (not a permanent metrics system — see the task this was added
     * for): one INFO line per completed job with wall-clock stage timings and, since the rate
     * limiters are shared process-wide rather than per-job, a <em>delta</em> of their cumulative
     * wait counters across this job's processing window (not perfectly attributable if another job
     * ran concurrently and used the same limiter, but good enough for the debugging/validation pass
     * this exists for — see {@code NvdRateLimiter}/{@code ExternalRegistryRateLimiter}/{@code
     * GhsaRateLimiter}/{@code OsvRateLimiter}'s own {@code cumulativeWait*} javadocs).
     */
    private void logJobTimings(Long jobId, int itemCount, long jobStartNanos, JobTimings timings,
            long nvdWaitBaselineMs, long ghsaWaitBaselineMs, long osvWaitBaselineMs,
            Map<String, Long> registryWaitBaseline) {
        long wallMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - jobStartNanos);
        log.info("Job {} timings: items={} wallMs={} stage1SumMs={} stage2SumMs={} stage4SumMs={} bundledComponentSumMs={} "
                        + "rateLimiterWaitDeltaMs=[nvd={} ghsa={} osv={} registry={}]",
                jobId, itemCount, wallMs,
                TimeUnit.NANOSECONDS.toMillis(timings.stage1Nanos.get()),
                TimeUnit.NANOSECONDS.toMillis(timings.stage2Nanos.get()),
                TimeUnit.NANOSECONDS.toMillis(timings.stage4Nanos.get()),
                TimeUnit.NANOSECONDS.toMillis(timings.bundledComponentNanos.get()),
                nvdRateLimiter.cumulativeWaitMillis() - nvdWaitBaselineMs,
                ghsaRateLimiter.cumulativeWaitMillis() - ghsaWaitBaselineMs,
                osvRateLimiter.cumulativeWaitMillis() - osvWaitBaselineMs,
                waitDelta(registryWaitBaseline, externalRegistryRateLimiter.cumulativeWaitMillisByEcosystem()));
    }

    /** Per-ecosystem (after - before) of two {@code cumulativeWaitMillisByEcosystem()} snapshots,
     *  over the union of ecosystems present in either — an ecosystem with no calls in the window
     *  simply doesn't appear in {@code after} and is treated as 0. */
    private Map<String, Long> waitDelta(Map<String, Long> before, Map<String, Long> after) {
        Map<String, Long> delta = new LinkedHashMap<>();
        Set<String> ecosystems = new TreeSet<>();
        ecosystems.addAll(before.keySet());
        ecosystems.addAll(after.keySet());
        for (String ecosystem : ecosystems) {
            delta.put(ecosystem, after.getOrDefault(ecosystem, 0L) - before.getOrDefault(ecosystem, 0L));
        }
        return delta;
    }

    /**
     * Wraps {@link #processItem} for concurrent dispatch from {@link #processJobAsync}: every
     * per-stage failure inside {@code processItem} is already caught there, so this is
     * belt-and-suspenders for a genuinely unexpected exception (e.g. a repository call throwing) —
     * same rationale as {@code Stage2VulnerabilityResearchService.safeFind}. Without this, an
     * uncaught exception on one item's {@link CompletableFuture} would surface only when {@code
     * allOf(...).join()} rethrows it, aborting the job's status update while sibling items' futures
     * are still running unobserved in the background.
     */
    private void processItemSafely(ResearchJobItem item, Long userId, boolean bundledComponentCheckEnabled, JobTimings timings) {
        try {
            processItem(item, userId, bundledComponentCheckEnabled, timings);
        } catch (Exception e) {
            log.error("Unexpected error processing item {} (every per-stage failure should already be caught inside processItem)",
                    item.getId(), e);
        }
    }

    /**
     * Not wrapped in a single @Transactional boundary on purpose: this is called via plain
     * self-invocation from {@link #processJobAsync}, which would silently bypass the proxy (and
     * thus the transaction) anyway. Each repository call below is transactional on its own,
     * which is enough here — Stage1 tolerates the rare case where an IdentifiedProduct row is
     * saved but the item's status update fails, since Stage2+ join on job_item_id regardless.
     */
    private void processItem(ResearchJobItem item, Long userId, boolean bundledComponentCheckEnabled, JobTimings timings) {
        Optional<IdentifiedProduct> identifiedProduct;
        long stage1Start = System.nanoTime();
        try {
            identifiedProduct = stage1IdentificationService.identify(item, userId);
        } catch (Exception e) {
            log.error("Stage1 identification failed for item {}", item.getId(), e);
            identifiedProduct = Optional.empty();
        } finally {
            timings.stage1Nanos.addAndGet(System.nanoTime() - stage1Start);
        }
        item.setStatus(identifiedProduct.isPresent() ? ResearchJobItem.STATUS_IDENTIFIED : ResearchJobItem.STATUS_UNIDENTIFIED);
        researchJobItemRepository.save(item);

        if (identifiedProduct.isEmpty()) {
            if (item.getHintIdentifier() != null) {
                long stage4Start = System.nanoTime();
                try {
                    stage4WebSearchResearchService.research(item, item.getHintPlatform(), item.getHintIdentifier(), userId);
                } catch (Exception e) {
                    log.error("Stage4 hint-based vulnerability research failed for item {}", item.getId(), e);
                } finally {
                    timings.stage4Nanos.addAndGet(System.nanoTime() - stage4Start);
                }
            }
            return;
        }

        // Defaults to anySourceSucceeded=false: if Stage2 itself throws (every per-source failure
        // is already caught inside it, so this would mean an unexpected bug there), that's the
        // same "we don't actually have a signal" situation as every individual source failing —
        // see the firing condition below.
        Stage2VulnerabilityResearchService.Stage2Result stage2Result = new Stage2VulnerabilityResearchService.Stage2Result(0, false);
        long stage2Start = System.nanoTime();
        try {
            stage2Result = stage2VulnerabilityResearchService.research(item, identifiedProduct.get(), userId);
        } catch (Exception e) {
            log.error("Stage2 vulnerability research failed for item {}", item.getId(), e);
        } finally {
            timings.stage2Nanos.addAndGet(System.nanoTime() - stage2Start);
        }

        // Persisted so the job results view can visibly distinguish "checked, genuinely nothing
        // found" from "every source failed, nothing was actually checked" (see
        // ResearchJobItem#INCOMPLETE_REASON_SOURCES_FAILED's javadoc) — without this, both cases
        // collapsed into the same "0 findings" row, which read as a clean result even though it
        // could mean the item was never actually checked (a false-negative security report). May be
        // overwritten below with INCOMPLETE_REASON_IDENTIFICATION_TOO_WEAK if Stage4 also ends up
        // skipped for this item.
        item.setResearchIncompleteReason(
                stage2Result.anySourceSucceeded() ? null : ResearchJobItem.INCOMPLETE_REASON_SOURCES_FAILED);
        researchJobItemRepository.save(item);

        // Stage4 (paid AI web-search) only fires on a genuine zero-findings result — i.e. at
        // least one source actually completed its query and found nothing. If every source
        // failed/errored (e.g. GHSA rate-limited into 403s across an entire job), findingCount is
        // also 0 but there's no real "nothing found" signal to act on, so Stage4 is suppressed
        // rather than spending on an AI search to paper over an infrastructure failure. If some
        // sources failed but at least one succeeded, the successful source's zero result is still
        // a meaningful signal, so Stage4 still fires.
        if (stage2Result.findingCount() == 0 && stage2Result.anySourceSucceeded()) {
            BigDecimal confidence = identifiedProduct.get().getConfidence();
            if (confidence == null || confidence.compareTo(STAGE4_MIN_IDENTIFICATION_CONFIDENCE) <= 0) {
                // Weak/static-only identification (unconfirmed registry hit, CPE-only match, etc.)
                // — see STAGE4_MIN_IDENTIFICATION_CONFIDENCE's javadoc for why this is where
                // fabricated findings were actually observed. Degrades the same way every other
                // AI-tier skip in this class does: logged, no exception, item just doesn't get a
                // Stage4 pass. Also recorded on the item itself (distinct from
                // INCOMPLETE_REASON_SOURCES_FAILED — this is a deliberate precision tradeoff, not an
                // infrastructure failure) so the job results view doesn't render this identically to
                // a genuine, fully-verified all-clear — see ResearchJobItem
                // #INCOMPLETE_REASON_IDENTIFICATION_TOO_WEAK's javadoc for the bug this prevents.
                log.info("Stage4 skipped for item {}: identification confidence {} is at or below the {} threshold "
                                + "(weak/static-only product match)",
                        item.getId(), confidence, STAGE4_MIN_IDENTIFICATION_CONFIDENCE);
                item.setResearchIncompleteReason(ResearchJobItem.INCOMPLETE_REASON_IDENTIFICATION_TOO_WEAK);
                researchJobItemRepository.save(item);
            } else {
                Stage4WebSearchResearchService.Stage4ResearchResult stage4Result = null;
                boolean stage4Threw = false;
                long stage4Start = System.nanoTime();
                try {
                    stage4Result = stage4WebSearchResearchService.research(
                            item, identifiedProduct.get().getEcosystem(), identifiedProduct.get().getPackageName(), userId);
                } catch (Exception e) {
                    log.error("Stage4 web-search vulnerability research failed for item {}", item.getId(), e);
                    stage4Threw = true;
                } finally {
                    timings.stage4Nanos.addAndGet(System.nanoTime() - stage4Start);
                }

                // Stage4 never actually ran (no Claude key / job budget exhausted) — the item's
                // researchIncompleteReason was set to null above (a genuine Stage2 zero-findings
                // result), which would otherwise render identically to a fully-verified all-clear.
                // Record why, same treatment as INCOMPLETE_REASON_SOURCES_FAILED/
                // INCOMPLETE_REASON_IDENTIFICATION_TOO_WEAK above.
                if (stage4Result != null && stage4Result.incompleteReason() != null) {
                    item.setResearchIncompleteReason(stage4Result.incompleteReason());
                    researchJobItemRepository.save(item);
                } else if (stage4Threw) {
                    // Task backlog item 121 (2026-08-31, REVISE 2026-09-01): LlmServiceClient
                    // #webSearchResearch now reports an LLM-call failure (LLM service down, timeout,
                    // network error, ...) via Optional.empty(), which Stage4WebSearchResearchService
                    // turns into a Stage4ResearchResult carrying INCOMPLETE_REASON_AI_CALL_FAILED —
                    // handled by the branch above, not this one. The reservation for that attempt is
                    // fully refunded by JobCostBudgetService#reconcile inside LlmServiceClient's own
                    // finally block (a failed call's actual cost is treated as $0), not "spent either
                    // way" as this comment previously (incorrectly) claimed. This else branch only
                    // remains reachable for exceptions thrown outside that try/catch — API key
                    // resolution, budget reservation, or finding persistence inside
                    // Stage4WebSearchResearchService#research itself. Without this, such a failure
                    // left researchIncompleteReason at Stage2's null, making an AI-verification
                    // failure indistinguishable from a genuine all-clear. See ResearchJobItem
                    // #INCOMPLETE_REASON_AI_CALL_FAILED's javadoc.
                    item.setResearchIncompleteReason(ResearchJobItem.INCOMPLETE_REASON_AI_CALL_FAILED);
                    researchJobItemRepository.save(item);
                }

                // Bundled-package detection: same firing condition as Stage4 above (Stage2 found
                // zero findings, identification confident enough) plus the job's own opt-in flag —
                // see BundledComponentResearchService's javadoc and the plan's §5. Fires independently
                // of whatever Stage4 itself found, not conditioned on it — a product's own
                // vulnerability status (what Stage4 checks) and a bundled component's are unrelated
                // attack surfaces (plan's §5, option (B)'s rationale).
                if (bundledComponentCheckEnabled) {
                    long bundledComponentStart = System.nanoTime();
                    try {
                        bundledComponentResearchService.research(item, userId);
                    } catch (Exception e) {
                        log.error("Bundled-component vulnerability research failed for item {}", item.getId(), e);
                    } finally {
                        timings.bundledComponentNanos.addAndGet(System.nanoTime() - bundledComponentStart);
                    }
                }
            }
        }
    }
}
