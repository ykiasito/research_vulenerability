package com.vulncheck.app.service;

import com.vulncheck.app.entity.JobCostLedgerEntry;
import com.vulncheck.app.repository.JobCostLedgerRepository;
import jakarta.annotation.PostConstruct;
import java.math.BigDecimal;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * In-memory, per-job hard cap on estimated Claude API spend, enforced across every AI call site
 * (Tier2 CPE/registry disambiguation, Tier3 web-search identify, Stage4 web-search research).
 * Target: keep expected cost at or under $5 per 1,000 items — {@link #costCapPerItemUsd}
 * ($0.005/item by default) is exactly that ratio, scaled to each job's own item count so it holds
 * regardless of job size. (Retuned 2026-08-25 from an earlier $20/1,000-item, $0.02/item cap per the
 * senior-engineer cost review — see {@link #TIER3_WEB_SEARCH_IDENTIFY_COST_USD}/{@link
 * #STAGE4_WEB_SEARCH_RESEARCH_COST_USD}'s own comment for why their reservation estimates had to
 * be recomputed in the same change, not left at the old, now-too-high figures.)
 *
 * <p>{@link #tryReserve} is a pre-flight admission check using conservative worst-case per-call
 * estimates (real usage isn't known until the Claude API responds). {@link #reconcile} is called
 * once the call site has an actual result — it replaces the reserved estimate with the real cost
 * computed from {@link #computeActualCost}, so a job's tracked spend converges on true dollars
 * rather than staying pinned to worst-case guesses. This also means a failed/errored AI call
 * (reconciled with {@link BigDecimal#ZERO} actual cost, since no billable Claude response was
 * ever parsed) refunds its reservation instead of permanently burning part of the job's budget on
 * nothing — see {@link com.vulncheck.app.service.llm.LlmServiceClient}.
 *
 * <p>The admission-check maps below ({@link #capByJobId}/{@link #spentByJobId} and their bundled-
 * component counterparts) remain in-memory only — that state genuinely only needs to live for one
 * job's processing pass, and a job resumed after a crash/redeploy (see {@link StuckJobResumer})
 * starting a fresh budget scaled to its remaining item count is an accepted, unchanged edge case.
 * {@link #reconcile}/{@link #reconcileBundledComponent}, however, additionally persist one {@link
 * JobCostLedgerEntry} row per call via {@link JobCostLedgerRepository} — this is realized spend
 * that must survive past this process's lifetime so a completed job's actual $/item cost can be
 * queried after the fact (docs/spec/infra-rollout-plan.md item 5), which in-memory-only state
 * could never support. Persistence happens unconditionally, even for a job whose in-memory budget
 * has already been torn down by {@link #endJobBudget} (see that method's javadoc on orphaned
 * in-flight calls) — real dollars were spent either way, and undercounting them here would defeat
 * the point of persisting at all.
 *
 * <p>REVISE item 10 (senior review 2026-08-26): the always-on budget above and the bundled-
 * package-detection budget below ({@link #bundledCapByJobId} et al.) live in this one class,
 * as two genuinely separate ledgers, rather than as two separate {@code @Service} beans. The
 * reason is reuse of the shared pricing constants and {@link #computeActualCost} — both ledgers
 * reconcile against the same Claude Haiku token/web-search pricing, and duplicating that (and
 * having to keep two copies in sync whenever pricing changes) across two classes wasn't worth it
 * for a second ledger that's otherwise a straight structural copy of the first. This is NOT about
 * {@code synchronized}/thread-safety: {@link com.vulncheck.app.service.ResearchJobProcessingService}
 * already makes two separate {@code endJobBudget}/{@code endBundledComponentBudget} calls in its
 * own {@code finally} block regardless of whether this is one class or two, so splitting this
 * class in two would not introduce any synchronization concern that doesn't already exist today.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class JobCostBudgetService {

    private final JobCostLedgerRepository jobCostLedgerRepository;

    /**
     * Configurable (default unchanged at $0.005/item, matching the $5/1,000-item target) so a
     * throwaway diagnostic job can safely raise its own job's cap via a Spring property override
     * (e.g. {@code @TestPropertySource}) instead of the previous convention of padding a CSV with
     * "should be free" rows to inflate {@code itemCount} — see {@code
     * HighConfidenceVerificationRealAiJobCreator}'s own javadoc for why: {@code
     * Stage4DiagnosticJobCreator}'s padding rows unexpectedly still billed Tier2 43/43 times (see
     * that class's own javadoc), so padding is not actually a reliable zero-cost lever. A property
     * override gives an exact, predictable cap instead.
     */
    /** Matches the {@code @Value} default immediately below — kept as its own constant purely so
     *  {@link #warnIfCostCapOverridden} can compare the resolved property value against "the
     *  well-known default" without hardcoding the literal twice. */
    private static final BigDecimal DEFAULT_COST_CAP_PER_ITEM_USD = new BigDecimal("0.005");

    @Value("${app.cost-cap-per-item-usd:0.005}")
    private BigDecimal costCapPerItemUsd;

    /**
     * REVISE item 7 (senior review 2026-08-29): a non-default {@code app.cost-cap-per-item-usd} is
     * exactly the kind of environment override that's easy to leave in place by accident after a
     * throwaway diagnostic job (see {@link #costCapPerItemUsd}'s own javadoc on that convention) —
     * logging it once at startup makes a silently-raised/lowered cost cap visible in the ordinary
     * startup log instead of only discoverable by reading application.yml/docker-compose.yml.
     */
    @PostConstruct
    void warnIfCostCapOverridden() {
        if (costCapPerItemUsd.compareTo(DEFAULT_COST_CAP_PER_ITEM_USD) != 0) {
            log.warn("app.cost-cap-per-item-usd is overridden to {} (default {}) — every job's AI "
                            + "spend cap will use this non-default value until it is changed back",
                    costCapPerItemUsd, DEFAULT_COST_CAP_PER_ITEM_USD);
        }
    }

    // Claude Haiku 4.5 list pricing ($1.00 / $5.00 per MTok input/output) and the Claude API web
    // search server tool ($10.00 per 1,000 calls) — used by computeActualCost to reconcile real
    // spend. Re-derive these (and the worst-case constants below) if Anthropic's pricing changes.
    private static final BigDecimal INPUT_PRICE_PER_TOKEN_USD = new BigDecimal("0.000001");
    private static final BigDecimal OUTPUT_PRICE_PER_TOKEN_USD = new BigDecimal("0.000005");
    private static final BigDecimal WEB_SEARCH_PRICE_PER_CALL_USD = new BigDecimal("0.01");

    // Admission-check estimates per AI call. As of 2026-08-29 these are retuned from *measured*
    // p95 real spend (job_cost_ledger), not derived from a worst-case token/search arithmetic
    // model — the earlier arithmetic-model estimates below were found, in the job 185 cost test
    // (150 real items, 2026-08-29), to be unreliable predictors of real spend in both directions:
    // Stage4's real p95 exceeded its old estimate even after correcting a measurement bug (see
    // llm-service/main.py's _count_web_searches javadoc — the raw job 185 numbers were inflated
    // ~2.57x by that bug; corrected they were still ~1.55x over the old $0.015 estimate), while
    // Tier3's real p95/worst-case were already close to its old estimate but on the wrong side of
    // it (a real under-estimate, not an over-estimate).
    //
    // Standing basis for re-deriving these going forward: re-derive from job_cost_ledger's p95
    // actual_cost_usd (or, since V27, the raw input_tokens/output_tokens/web_search_requests
    // breakdown, filtered by call_site) for the call site in question, not from a fresh token-count
    // guess. Re-derivation query shape (V27 columns):
    //   SELECT call_site,
    //          percentile_cont(0.95) WITHIN GROUP (ORDER BY actual_cost_usd) AS p95_cost_usd,
    //          percentile_cont(0.95) WITHIN GROUP (ORDER BY input_tokens) AS p95_input_tokens,
    //          percentile_cont(0.95) WITHIN GROUP (ORDER BY output_tokens) AS p95_output_tokens,
    //          percentile_cont(0.95) WITHIN GROUP (ORDER BY web_search_requests) AS p95_web_searches,
    //          count(*) AS n
    //   FROM job_cost_ledger
    //   WHERE call_site = 'STAGE4' -- or 'TIER3' / 'TIER2' / 'BUNDLED_CHANGELOG' / 'BUNDLED_EXTRACT'
    //   GROUP BY call_site;
    // Then set the reservation constant to a safety margin over p95_cost_usd (not the raw p95
    // itself, since reservations are pre-flight and must cover the tail, not just the median) —
    // the two retuned constants below use roughly a 1.5x margin over their job 185 p95, which also
    // happened to keep 8-way concurrent reservations comfortably under a 150-item job's own
    // $0.75 cap (see each constant's own comment for the exact math).
    //
    // CAUTION when re-deriving from job_cost_ledger (added 2026-08-29, senior review REVISE item
    // 2): job 185's 67 rows were written by the llm-service build that still had the
    // _count_web_searches double/triple-counting bug described above, so their actual_cost_usd is
    // inflated and call_site is NULL (V27's call_site/input_tokens/output_tokens/web_search_requests
    // columns didn't exist yet when those rows were written; they were backfilled with call_site
    // left NULL). Any future re-derivation query — and any $/item rollup in general — MUST exclude
    // job 185's contaminated rows, e.g. by adding "AND call_site IS NOT NULL" or "AND job_id > 185"
    // to the WHERE clause above. V27__job_cost_ledger_breakdown.sql's own header comment claims
    // job_cost_ledger had zero rows / no real spend yet at the time it was written; that was true
    // when authored but is no longer accurate (job 185 already had 67 rows by the time it ran).
    // That file cannot be edited to correct this without breaking Flyway's checksum validation, so
    // the correction is recorded here instead.
    //
    // - Tier2 (disambiguate, no web_search): real job 185 p95 was healthy relative to the existing
    //   $0.003 estimate (mean $0.00128, worst observed $0.0016) — left unchanged.
    // - Tier3 (web-search identify, max_uses=2): job 185 mean $0.0346, worst observed $0.0503 —
    //   this one's web_search-count reporting was already accurate (not subject to the
    //   _count_web_searches bug's inflation, since Tier3's real counts matched its real token
    //   growth), so this was a genuine under-estimate, not a measurement artifact. Retuned
    //   $0.03 -> $0.05 to clear the $0.0503 worst case with room to spare.
    // - Stage4 (web-search research, max_uses=1): job 185 mean $0.0233 after correcting the
    //   _count_web_searches double-count (raw/uncorrected mean would have implied a much higher,
    //   spurious figure). Retuned $0.015 -> $0.035 (~1.5x the corrected mean) — at 8-way
    //   concurrent reservation (itemProcessingExecutor's core=max=8), 8 x $0.035 = $0.28 is 37% of
    //   a 150-item job's own $0.75 cap (150 x $0.005), leaving headroom for other concurrently
    //   in-flight Tier2/Tier3 reservations in the same window.
    public static final BigDecimal TIER2_DISAMBIGUATE_COST_USD = new BigDecimal("0.003");
    public static final BigDecimal TIER3_WEB_SEARCH_IDENTIFY_COST_USD = new BigDecimal("0.05");
    public static final BigDecimal STAGE4_WEB_SEARCH_RESEARCH_COST_USD = new BigDecimal("0.035");

    /**
     * High-confidence AI verification backstop ({@code HighConfidenceVerificationService}, 2026-08-29
     * — the fix for the "a registry match's confidence is lent to an independently-derived CPE"
     * known-limitations gap). No real usage data exists yet for this brand-new endpoint, so this is
     * not re-derived from {@code job_cost_ledger} the way the two constants above were — instead it's
     * set conservatively at Stage4's own retuned estimate ($0.035), on the basis that the two calls
     * are the same shape (single Haiku call, {@code web_search_20250305} with {@code max_uses=1},
     * structured JSON output, similarly short prompt) and Stage4's own measured mean/p95
     * ($0.0233/$0.035, see that constant's comment) is therefore the best available reference point.
     * Re-derive this from real {@code job_cost_ledger} data (filter {@code call_site = 'VERIFICATION'})
     * once enough rows accumulate, per this class's standing re-derivation guidance above.
     */
    public static final BigDecimal HIGH_CONFIDENCE_VERIFICATION_COST_USD = new BigDecimal("0.035");

    /**
     * Per-item cap for the high-confidence verification ledger below ({@link
     * #verificationCapByJobId} et al.) — REVISE item 1 (senior review 2026-08-29): job 191 real data
     * found 108/300 items (36%) eligible for verification, whose demand ($3.78 at {@link
     * #HIGH_CONFIDENCE_VERIFICATION_COST_USD} x 108) was 2.5x a 300-item job's own always-on {@link
     * #costCapPerItemUsd} budget ($1.50) — sharing that budget meant enabling this feature could burn
     * through the whole job's AI allowance from the first CSV rows alone, silently starving every
     * later item's Tier2/Tier3 calls. Defaults to {@code 0} (verification effectively never affordable
     * until an operator explicitly sets this alongside {@code
     * app.high-confidence-verification.enabled=true}) rather than mirroring {@link #costCapPerItemUsd}'s
     * $0.005 default, since this is a brand-new, still-being-measured feature — see this class's
     * standing re-derivation guidance above once real {@code call_site = 'VERIFICATION'} rows
     * accumulate.
     */
    @Value("${app.high-confidence-verification.cost-cap-per-item-usd:0}")
    private BigDecimal verificationCostCapPerItemUsd;

    /**
     * Bundled-package (formerly "Stage 3.5") detection cost constants — see
     * {@code docs/spec/bundled-package-detection-plan.md} §4 for the derivation (same web_search
     * max_uses=1 pricing shape as Stage4 for the changelog-discovery call, plus a text-only
     * extraction call — see {@link #BUNDLED_COMPONENT_EXTRACTION_COST_USD}'s own comment for that
     * one's derivation). These are tracked against a completely separate ledger ({@link
     * #bundledCapByJobId}/{@link #bundledSpentByJobId}, below) from every other constant on this
     * class — this feature is opt-in per job (see {@code ResearchJob#bundledComponentCheckEnabled})
     * specifically so it can never silently draw down the always-on {@link #costCapPerItemUsd}
     * budget every other job relies on.
     */
    public static final BigDecimal BUNDLED_COMPONENT_CHANGELOG_DISCOVERY_COST_USD = new BigDecimal("0.015");

    // REVISE item 9 (senior review 2026-08-26): re-derived as an actual worst case, like every other
    // constant on this class, rather than a guess — the extract endpoint (llm-service's
    // bundled_extract_components) sets max_tokens=1536, so output alone is worst-case
    // 1536 * $0.000005/token = $0.00768. Input worst case: system prompt (~150 tokens) + product
    // name/version (~20 tokens) + changelog text, which this endpoint doesn't cap on its own —
    // conservatively assuming a long changelog excerpt (~2000 tokens) puts input around ~2170
    // tokens -> 2170 * $0.000001/token = $0.00217. Total worst case ~$0.0099 (output dominates);
    // rounded up to $0.01 — the previous $0.005 figure was roughly half this endpoint's own actual
    // worst case.
    public static final BigDecimal BUNDLED_COMPONENT_EXTRACTION_COST_USD = new BigDecimal("0.01");
    private static final BigDecimal BUNDLED_COMPONENT_COST_CAP_PER_ITEM_USD = new BigDecimal("0.02");

    private final Map<Long, BigDecimal> capByJobId = new ConcurrentHashMap<>();
    private final Map<Long, BigDecimal> spentByJobId = new ConcurrentHashMap<>();

    // Job ids whose budget was explicitly ended via endJobBudget — distinct from "never started"
    // (see tryReserve's javadoc). One entry per job that has ever finished processing, for the life
    // of this process; at this app's scale (batch CSV-import jobs, not a high-frequency workload)
    // that never grows large enough to be worth adding eviction machinery for.
    private final Set<Long> endedJobIds = ConcurrentHashMap.newKeySet();

    // Second, independent ledger for bundled-package detection's own budget (see the constants'
    // javadoc above) — deliberately separate maps, not an extra dimension folded into capByJobId/
    // spentByJobId, so this feature's spend can never be commingled with or silently borrow from the
    // always-on per-item budget every job (opted in or not) already relies on.
    private final Map<Long, BigDecimal> bundledCapByJobId = new ConcurrentHashMap<>();
    private final Map<Long, BigDecimal> bundledSpentByJobId = new ConcurrentHashMap<>();
    private final Set<Long> bundledEndedJobIds = ConcurrentHashMap.newKeySet();

    // Third, independent ledger for the high-confidence verification backstop's own budget (see
    // #verificationCostCapPerItemUsd's javadoc above) — same reasoning as the bundled-component
    // ledger's own comment: a separate set of maps so this feature's spend can never be commingled
    // with, or silently borrow from, the always-on per-item budget every job already relies on.
    private final Map<Long, BigDecimal> verificationCapByJobId = new ConcurrentHashMap<>();
    private final Map<Long, BigDecimal> verificationSpentByJobId = new ConcurrentHashMap<>();
    private final Set<Long> verificationEndedJobIds = ConcurrentHashMap.newKeySet();

    public void startJobBudget(Long jobId, int itemCount) {
        // A job id can legitimately be started again after having previously ended (e.g.
        // StuckJobResumer re-running processJobAsync for a job resumed after a crash/redeploy) —
        // clear any stale tombstone so this fresh budget isn't immediately treated as ended.
        endedJobIds.remove(jobId);
        capByJobId.put(jobId, costCapPerItemUsd.multiply(BigDecimal.valueOf(itemCount)));
        spentByJobId.put(jobId, BigDecimal.ZERO);
    }

    /**
     * Tears down a job's budget and tombstones its id so any AI call that is still in flight for
     * this job after this point (e.g. an item task submitted to {@code itemProcessingExecutor}
     * that hadn't finished when {@code processJobAsync}'s {@code finally} block ran) is rejected by
     * {@link #tryReserve} rather than silently spending unbounded/uncapped — see that method's
     * javadoc for why removing the cap alone (the previous behavior) made that scenario fail open
     * instead.
     */
    public void endJobBudget(Long jobId) {
        capByJobId.remove(jobId);
        spentByJobId.remove(jobId);
        endedJobIds.add(jobId);
    }

    /**
     * Reserves {@code estimatedCostUsd} against the job's remaining budget. Returns {@code false}
     * (reserving nothing) if that would exceed the cap — the caller must then skip the AI call
     * and fall back to its non-AI behavior, same as it would with no Claude key configured.
     *
     * <p>Two distinct "no cap entry" states are handled differently, not collapsed into one:
     * <ul>
     *   <li>A job id that was <b>never started</b> (no {@link #startJobBudget} call at all —
     *       shouldn't happen in normal flow) fails <b>open</b> (returns {@code true}, unlimited),
     *       rather than blocking every AI call, so a missing {@code startJobBudget} call doesn't
     *       wedge every AI-tier call site.</li>
     *   <li>A job id whose budget was <b>explicitly ended</b> via {@link #endJobBudget} fails
     *       <b>closed</b> (returns {@code false}) — this is the fix for a real gap: with
     *       item-level parallelism inside one job ({@code itemProcessingExecutor}), items can
     *       still be mid-flight when {@code processJobAsync}'s {@code finally} block calls {@code
     *       endJobBudget} (e.g. after a {@code RejectedExecutionException} aborts the submission
     *       loop early). Before this tombstone existed, {@code endJobBudget} simply removed the
     *       cap entry, which was indistinguishable from "never started" and made every orphaned
     *       in-flight item's {@code tryReserve} call fail open — unlimited Claude API spend with
     *       no cap for however many items were still running.</li>
     * </ul>
     *
     * <p><b>Known limitation, not fixed in this pass:</b> reservations are first-come-first-served
     * over a whole job's budget purely by arrival order — there is no prioritization or expected-
     * value ranking of which items get the AI tiers before the budget runs out. At the current
     * tighter cap, a large job (e.g. 1,000+ items) can exhaust its budget partway through, which
     * silently degrades every later item in the CSV to static-only identification/research —
     * correlated with row position in the source file, not with which items would have benefited
     * most from an AI call. A pacing/EV-ranking admission policy would fix this properly; that's a
     * separate, larger piece of work and is intentionally not attempted here.
     */
    public synchronized boolean tryReserve(Long jobId, BigDecimal estimatedCostUsd) {
        if (endedJobIds.contains(jobId)) {
            return false;
        }
        BigDecimal cap = capByJobId.get(jobId);
        if (cap == null) {
            return true;
        }
        BigDecimal spent = spentByJobId.getOrDefault(jobId, BigDecimal.ZERO);
        if (spent.add(estimatedCostUsd).compareTo(cap) > 0) {
            return false;
        }
        spentByJobId.put(jobId, spent.add(estimatedCostUsd));
        return true;
    }

    /**
     * Computes actual Claude API cost from real usage figures reported by the LLM microservice,
     * using the same per-token/per-search pricing the worst-case constants above are derived from.
     */
    public BigDecimal computeActualCost(int inputTokens, int outputTokens, int webSearchRequests) {
        return INPUT_PRICE_PER_TOKEN_USD.multiply(BigDecimal.valueOf(inputTokens))
                .add(OUTPUT_PRICE_PER_TOKEN_USD.multiply(BigDecimal.valueOf(outputTokens)))
                .add(WEB_SEARCH_PRICE_PER_CALL_USD.multiply(BigDecimal.valueOf(webSearchRequests)));
    }

    /**
     * Replaces a previously-reserved worst-case estimate with the real cost of the call that
     * estimate paid for, so the job's tracked spend tracks actual dollars rather than staying
     * pinned at the conservative admission-check figure. Pass {@link BigDecimal#ZERO} as
     * {@code actualCostUsd} for a failed/errored call — no billable response was parsed, so the
     * reservation is simply refunded. No-op for the in-memory admission-check state when the job
     * has no budget initialized, matching {@link #tryReserve}'s fail-open behavior (this also
     * covers a tombstoned/ended job id, since {@code endJobBudget} removes its cap entry too) — but
     * the {@link JobCostLedgerEntry} row is still persisted regardless (see this class's javadoc).
     *
     * @param jobItemId the item this AI call was made for, recorded on the persisted ledger row so
     *     actual spend can later be joined/aggregated per item as well as per job; may be
     *     {@code null} if the caller has no item to attribute the call to.
     */
    public synchronized void reconcile(
            Long jobId, Long jobItemId, BigDecimal reservedEstimateUsd, BigDecimal actualCostUsd) {
        reconcile(jobId, jobItemId, null, reservedEstimateUsd, actualCostUsd, null, null, null);
    }

    /**
     * Same as {@link #reconcile(Long, Long, BigDecimal, BigDecimal)}, additionally recording the
     * raw usage breakdown (V27) behind {@code actualCostUsd} on the persisted ledger row, so the
     * per-tier reservation constants above can be re-derived straight from SQL later instead of
     * grepping llm-service log files (see V27's migration comment for why that mattered in the job
     * 185 cost investigation, 2026-08-29). {@code callSite}/{@code inputTokens}/{@code
     * outputTokens}/{@code webSearchRequests} may all be {@code null} for a failed call that never
     * produced a parsed {@code UsageDto} — see {@link com.vulncheck.app.service.llm.LlmServiceClient}.
     */
    public synchronized void reconcile(
            Long jobId,
            Long jobItemId,
            String callSite,
            BigDecimal reservedEstimateUsd,
            BigDecimal actualCostUsd,
            Integer inputTokens,
            Integer outputTokens,
            Integer webSearchRequests) {
        // REVISE (senior review 2026-08-28): the in-memory refund is applied BEFORE the ledger is
        // persisted, and persistLedgerEntry never throws (see its own javadoc) — so a DB failure
        // here can never swallow the in-memory reservation refund, and can never propagate up
        // through LlmServiceClient's callers and clobber an already-paid-for Claude response.
        if (capByJobId.containsKey(jobId)) {
            BigDecimal spent = spentByJobId.getOrDefault(jobId, BigDecimal.ZERO);
            BigDecimal adjusted = spent.subtract(reservedEstimateUsd).add(actualCostUsd);
            spentByJobId.put(jobId, adjusted.max(BigDecimal.ZERO));
        }
        persistLedgerEntry(
                jobId,
                jobItemId,
                JobCostLedgerEntry.LEDGER_MAIN,
                callSite,
                reservedEstimateUsd,
                actualCostUsd,
                inputTokens,
                outputTokens,
                webSearchRequests);
    }

    /**
     * Persists one realized-spend row per {@link #reconcile}/{@link #reconcileBundledComponent}
     * call — see this class's javadoc for why this happens unconditionally, independent of the
     * in-memory admission-check state above.
     *
     * <p>REVISE (senior review 2026-08-28): failures here are caught and logged, never rethrown.
     * This method runs after the in-memory refund has already been applied (see {@link #reconcile}/
     * {@link #reconcileBundledComponent}), and every caller of {@code reconcile}/{@code
     * reconcileBundledComponent} sits behind {@link
     * com.vulncheck.app.service.llm.LlmServiceClient}'s {@code finally} block — letting a transient
     * {@code DataAccessException} propagate from here would blow past that {@code finally} and up
     * into {@code Stage1IdentificationService}/{@code Stage4WebSearchResearchService}'s own {@code
     * catch (Exception)}, silently discarding an already-billed Claude response along with it. A
     * lost ledger row (best-effort audit trail) is an acceptable trade-off for never doing that.
     */
    private void persistLedgerEntry(
            Long jobId,
            Long jobItemId,
            String ledger,
            String callSite,
            BigDecimal reservedCostUsd,
            BigDecimal actualCostUsd,
            Integer inputTokens,
            Integer outputTokens,
            Integer webSearchRequests) {
        try {
            JobCostLedgerEntry entry = new JobCostLedgerEntry();
            entry.setJobId(jobId);
            entry.setJobItemId(jobItemId);
            entry.setLedger(ledger);
            entry.setCallSite(callSite);
            entry.setReservedCostUsd(reservedCostUsd);
            entry.setActualCostUsd(actualCostUsd);
            entry.setInputTokens(inputTokens);
            entry.setOutputTokens(outputTokens);
            entry.setWebSearchRequests(webSearchRequests);
            jobCostLedgerRepository.save(entry);
        } catch (Exception e) {
            log.error(
                    "Failed to persist job cost ledger entry (jobId={}, jobItemId={}, ledger={}, callSite={}); "
                            + "in-memory budget was already reconciled, only the audit trail row is lost",
                    jobId,
                    jobItemId,
                    ledger,
                    callSite,
                    e);
        }
    }

    // --- Bundled-package detection's own budget ledger (see the constants' javadoc above) --------

    /**
     * Starts the bundled-component budget for a job that opted in ({@code ResearchJob
     * #bundledComponentCheckEnabled}) — mirrors {@link #startJobBudget}, just against the separate
     * {@link #bundledCapByJobId} ledger. Callers must only invoke this for an opted-in job; a job
     * that never opts in must never have this called, so {@link #tryReserveBundledComponent} fails
     * closed for it below (unlike {@link #tryReserve}'s deliberate fail-open for a never-started
     * id — there is no legitimate "forgot to call start" scenario for this budget the way there is
     * for the always-on one, so failing closed is the safer default here).
     */
    public void startBundledComponentBudget(Long jobId, int itemCount) {
        bundledEndedJobIds.remove(jobId);
        bundledCapByJobId.put(jobId, BUNDLED_COMPONENT_COST_CAP_PER_ITEM_USD.multiply(BigDecimal.valueOf(itemCount)));
        bundledSpentByJobId.put(jobId, BigDecimal.ZERO);
    }

    /** Mirrors {@link #endJobBudget}, against the separate bundled-component ledger — tombstones
     *  the job id so any bundled-component call still in flight after this point is rejected rather
     *  than spending against a torn-down budget. Safe to call even for a job that never opted in
     *  (never had {@link #startBundledComponentBudget} called): removing absent map entries and
     *  tombstoning an id that was never eligible anyway is a harmless no-op. */
    public void endBundledComponentBudget(Long jobId) {
        bundledCapByJobId.remove(jobId);
        bundledSpentByJobId.remove(jobId);
        bundledEndedJobIds.add(jobId);
    }

    /**
     * Same admission-check shape as {@link #tryReserve}, against the separate bundled-component
     * ledger — <em>except</em> a job id with no cap entry at all (never started, i.e. never opted
     * in) fails <b>closed</b> here rather than open, since {@link #startBundledComponentBudget}'s
     * javadoc requires callers to only start this budget for an opted-in job in the first place.
     */
    public synchronized boolean tryReserveBundledComponent(Long jobId, BigDecimal estimatedCostUsd) {
        if (bundledEndedJobIds.contains(jobId)) {
            return false;
        }
        BigDecimal cap = bundledCapByJobId.get(jobId);
        if (cap == null) {
            return false;
        }
        BigDecimal spent = bundledSpentByJobId.getOrDefault(jobId, BigDecimal.ZERO);
        if (spent.add(estimatedCostUsd).compareTo(cap) > 0) {
            return false;
        }
        bundledSpentByJobId.put(jobId, spent.add(estimatedCostUsd));
        return true;
    }

    /** Mirrors {@link #reconcile}, against the separate bundled-component ledger — including
     *  persisting its {@link JobCostLedgerEntry} row unconditionally, tagged {@link
     *  JobCostLedgerEntry#LEDGER_BUNDLED_COMPONENT} so it stays distinguishable from the always-on
     *  ledger's rows. */
    public synchronized void reconcileBundledComponent(
            Long jobId, Long jobItemId, BigDecimal reservedEstimateUsd, BigDecimal actualCostUsd) {
        reconcileBundledComponent(jobId, jobItemId, null, reservedEstimateUsd, actualCostUsd, null, null, null);
    }

    /** Same as {@link #reconcileBundledComponent(Long, Long, BigDecimal, BigDecimal)}, additionally
     *  recording the raw usage breakdown (V27) — see {@link #reconcile(Long, Long, String,
     *  BigDecimal, BigDecimal, Integer, Integer, Integer)}'s javadoc for why. */
    public synchronized void reconcileBundledComponent(
            Long jobId,
            Long jobItemId,
            String callSite,
            BigDecimal reservedEstimateUsd,
            BigDecimal actualCostUsd,
            Integer inputTokens,
            Integer outputTokens,
            Integer webSearchRequests) {
        // REVISE (senior review 2026-08-28): same ordering fix as reconcile() above — refund the
        // in-memory reservation first, persist the ledger row second.
        if (bundledCapByJobId.containsKey(jobId)) {
            BigDecimal spent = bundledSpentByJobId.getOrDefault(jobId, BigDecimal.ZERO);
            BigDecimal adjusted = spent.subtract(reservedEstimateUsd).add(actualCostUsd);
            bundledSpentByJobId.put(jobId, adjusted.max(BigDecimal.ZERO));
        }
        persistLedgerEntry(
                jobId,
                jobItemId,
                JobCostLedgerEntry.LEDGER_BUNDLED_COMPONENT,
                callSite,
                reservedEstimateUsd,
                actualCostUsd,
                inputTokens,
                outputTokens,
                webSearchRequests);
    }

    // --- High-confidence verification's own budget ledger (REVISE item 1, senior review 2026-08-29,
    // see #verificationCostCapPerItemUsd's javadoc above) -----------------------------------------

    /** Mirrors {@link #startBundledComponentBudget}, against the separate {@link
     *  #verificationCapByJobId} ledger. Unlike the bundled-component budget (opt-in per job via
     *  {@code ResearchJob#bundledComponentCheckEnabled}), the verification feature is a single
     *  app-wide toggle ({@code app.high-confidence-verification.enabled}), not a per-job field —
     *  callers therefore start this budget unconditionally for every job, same as {@link
     *  #startJobBudget}; the {@code cost-cap-per-item-usd} default of {@code 0} (see {@link
     *  #verificationCostCapPerItemUsd}) is what actually keeps this a no-op for every job when the
     *  operator hasn't explicitly configured a real cap. */
    public void startVerificationBudget(Long jobId, int itemCount) {
        verificationEndedJobIds.remove(jobId);
        verificationCapByJobId.put(jobId, verificationCostCapPerItemUsd.multiply(BigDecimal.valueOf(itemCount)));
        verificationSpentByJobId.put(jobId, BigDecimal.ZERO);
    }

    /** Mirrors {@link #endBundledComponentBudget}, against the separate verification ledger. */
    public void endVerificationBudget(Long jobId) {
        verificationCapByJobId.remove(jobId);
        verificationSpentByJobId.remove(jobId);
        verificationEndedJobIds.add(jobId);
    }

    /** Same admission-check shape as {@link #tryReserveBundledComponent} — fails <b>closed</b> for a
     *  job id with no cap entry at all, same reasoning as that method (this ledger's budget must
     *  never be silently unlimited just because a caller forgot to start it). */
    public synchronized boolean tryReserveVerification(Long jobId, BigDecimal estimatedCostUsd) {
        if (verificationEndedJobIds.contains(jobId)) {
            return false;
        }
        BigDecimal cap = verificationCapByJobId.get(jobId);
        if (cap == null) {
            return false;
        }
        BigDecimal spent = verificationSpentByJobId.getOrDefault(jobId, BigDecimal.ZERO);
        if (spent.add(estimatedCostUsd).compareTo(cap) > 0) {
            return false;
        }
        verificationSpentByJobId.put(jobId, spent.add(estimatedCostUsd));
        return true;
    }

    /** Mirrors {@link #reconcileBundledComponent}, against the separate verification ledger —
     *  including persisting its {@link JobCostLedgerEntry} row unconditionally, tagged {@link
     *  JobCostLedgerEntry#LEDGER_VERIFICATION} so it stays distinguishable from the always-on and
     *  bundled-component ledgers' rows. */
    public synchronized void reconcileVerification(
            Long jobId, Long jobItemId, BigDecimal reservedEstimateUsd, BigDecimal actualCostUsd) {
        reconcileVerification(jobId, jobItemId, null, reservedEstimateUsd, actualCostUsd, null, null, null);
    }

    /** Same as {@link #reconcileVerification(Long, Long, BigDecimal, BigDecimal)}, additionally
     *  recording the raw usage breakdown (V27) — see {@link #reconcile(Long, Long, String,
     *  BigDecimal, BigDecimal, Integer, Integer, Integer)}'s javadoc for why. */
    public synchronized void reconcileVerification(
            Long jobId,
            Long jobItemId,
            String callSite,
            BigDecimal reservedEstimateUsd,
            BigDecimal actualCostUsd,
            Integer inputTokens,
            Integer outputTokens,
            Integer webSearchRequests) {
        if (verificationCapByJobId.containsKey(jobId)) {
            BigDecimal spent = verificationSpentByJobId.getOrDefault(jobId, BigDecimal.ZERO);
            BigDecimal adjusted = spent.subtract(reservedEstimateUsd).add(actualCostUsd);
            verificationSpentByJobId.put(jobId, adjusted.max(BigDecimal.ZERO));
        }
        persistLedgerEntry(
                jobId,
                jobItemId,
                JobCostLedgerEntry.LEDGER_VERIFICATION,
                callSite,
                reservedEstimateUsd,
                actualCostUsd,
                inputTokens,
                outputTokens,
                webSearchRequests);
    }
}
