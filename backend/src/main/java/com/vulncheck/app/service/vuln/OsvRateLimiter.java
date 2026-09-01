package com.vulncheck.app.service.vuln;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.stereotype.Component;

/**
 * Paces every call {@link OsvLiveQueryClient} makes to {@code api.osv.dev}'s single-query endpoint,
 * process-wide. Same fixed-gap, no-burst approach as {@code
 * com.vulncheck.app.service.nvd.NvdRateLimiter}/{@link GhsaRateLimiter}, not {@code
 * com.vulncheck.app.service.ratelimit.ExternalRegistryRateLimiter}'s per-key map, since there's only
 * ever one caller/endpoint here.
 *
 * <p><b>Confirmed switched for the OSV mirror rollout ({@code docs/spec/osv-mirror-plan.md} §7-2,
 * §9-2): {@code OsvVulnerabilitySource} is now Stage2's actual {@code @Component}, and the old
 * per-item live-API implementation ({@code OsvLiveVulnerabilitySource}) has been deleted.</b>
 * Before that switch, Stage2's own per-item {@code find()} calls shared this exact gate (via {@code
 * OsvLiveVulnerabilitySource} delegating into {@link OsvLiveQueryClient#queryPackage}) — that
 * traffic is gone now, not just "expected to go away": {@code find()} reads the local mirror only
 * (no live call at all), and the sole remaining caller of {@link OsvLiveQueryClient} — and thus the
 * sole remaining caller through this gate — is {@code BundledComponentResearchService#adjudicate},
 * up to {@code MAX_COMPONENTS_PER_ITEM} (10) calls per opted-in item. The throughput reasoning
 * below (the 8-concurrent-jobs/800s-per-job math) was derived against that now-retired combined
 * traffic and is therefore conservative rather than tight for today's actual, much lower, opt-in-
 * only volume — left as-is (a looser-than-necessary interval is a safe direction to be wrong in)
 * rather than re-derived down, since this codebase has no measured opt-in rate for bundled-
 * component research to derive a tighter number from yet.
 *
 * <p>Added 2026-08-27, revised 2026-08-27 after senior review: OSV.dev's own FAQ (<a
 * href="https://google.github.io/osv.dev/faq/">https://google.github.io/osv.dev/faq/</a>,
 * "Infrastructure → Is the API rate limited?") explicitly answers <b>"No. Currently there is not a
 * limit on the API,"</b> and publishes SLOs for {@code POST /v1/query} of P50 &le; 300ms, P90 &le;
 * 500ms, P95 &le; 1s. So this is not the undocumented-API conservative-fallback case — per this
 * codebase's own tiering convention, a service with generous/no published limits sits in the same
 * tier as {@code ExternalRegistryRateLimiter}'s {@code nuget} entry (100ms, "published limits are
 * generous"), not its undocumented-fallback tier. A limiter still exists anyway, for three reasons:
 * the FAQ's "Currently" is an explicit hedge, not a permanent guarantee; Google applies its own
 * abuse protection regardless of published policy, independent of whatever the FAQ says today; and
 * this is a safety net capping a runaway loop, not primarily a compliance mechanism. Until this
 * class existed, both call sites above had zero client-side pacing at all — a real, live-production
 * risk (not hypothetical) given this project has already been burned twice by exactly this gap
 * (GHSA's 60/hour exhaustion, and a crates.io/Maven Central near-incident during a live 1,000-item
 * job).
 *
 * <p><b>Throughput reasoning behind the 100ms figure (don't raise it again without re-deriving
 * this):</b> this is one global gate shared across all 8 {@code itemProcessingExecutor} threads AND
 * all 8 concurrent {@code researchJobExecutor} jobs, and {@code
 * BundledComponentResearchService#adjudicate} (see its own OSV call site) adds up to {@code
 * MAX_COMPONENTS_PER_ITEM} further OSV calls per opted-in item on top of Stage2's own per-item call.
 * At 100ms, 8 concurrent 1,000-item jobs cost roughly 800s of cumulative gate wait per job — about
 * 7% of the 3-hour/1,000-item throughput target. At the previous 500ms figure it was roughly 4,000s
 * per job — about 37% of that same target.
 *
 * <p><b>An {@code OsvResponseCache} would not help here — do not add one under that belief.</b>
 * Unlike {@link NvdResponseCache}, an OSV {@code /v1/query} lookup is version-qualified, and {@link
 * com.vulncheck.app.service.registry.RegistryLookupCache}'s own javadoc records a real measurement
 * of exactly that key shape: jobs 30/31's 1,350 items had ~1,349 distinct (name, version) pairs, a
 * ~0.07% hit rate. The only cacheable alternative would be a version-free package-only query, which
 * would require re-introducing local version-range parsing that this class (and {@code
 * NvdVulnerabilitySource}) deliberately delegate to the server instead of implementing locally —
 * not a small addition, and out of scope here.
 *
 * <p><b>{@code Thread.sleep} deliberately happens outside the synchronized section</b> ({@link
 * #reserveSlot} only computes and books the next allowed slot, then returns) — same monitor-convoy/
 * graceful-shutdown reasoning as {@code NvdRateLimiter}/{@link GhsaRateLimiter}; see their javadocs.
 */
@Component
public class OsvRateLimiter {

    // OSV.dev's FAQ states there is currently no limit on the API; this sits in the same
    // generous-published-limit tier as ExternalRegistryRateLimiter's nuget entry (100ms), not the
    // undocumented-fallback tier (see class javadoc).
    private static final long DEFAULT_MIN_INTERVAL_MS = 100;

    private final long minIntervalMs;
    private long nextAllowedAtMs = 0;

    // Cumulative time every caller has spent actually sleeping in awaitTurn, process-wide, since
    // this instance was created — lightweight app-log instrumentation (see
    // ResearchJobProcessingService's per-job stage/wait logging), not a permanent metrics system.
    private final AtomicLong cumulativeWaitNanos = new AtomicLong();

    public OsvRateLimiter() {
        this(DEFAULT_MIN_INTERVAL_MS);
    }

    private OsvRateLimiter(long minIntervalMs) {
        this.minIntervalMs = minIntervalMs;
    }

    /** Zero-wait instance for unit tests — mirrors {@code GhsaRateLimiter.disabledForTesting()}. */
    public static OsvRateLimiter disabledForTesting() {
        return new OsvRateLimiter(0L);
    }

    /** Blocks the calling thread only as long as needed to keep OSV calls, process-wide, within the
     *  conservative interval above; safe to call from multiple concurrent threads. {@code
     *  Thread.sleep} happens outside the synchronized slot-reservation ({@link #reserveSlot}) for
     *  the same monitor-convoy/graceful-shutdown reasons as {@code NvdRateLimiter}/{@code
     *  ExternalRegistryRateLimiter}/{@link GhsaRateLimiter} — see their javadocs. */
    public void awaitTurn() {
        long waitMs = reserveSlot();
        if (waitMs > 0) {
            cumulativeWaitNanos.addAndGet(TimeUnit.MILLISECONDS.toNanos(waitMs));
            try {
                Thread.sleep(waitMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private synchronized long reserveSlot() {
        if (minIntervalMs <= 0) {
            return 0;
        }
        long now = System.currentTimeMillis();
        long waitMs = nextAllowedAtMs - now;
        nextAllowedAtMs = Math.max(now, nextAllowedAtMs) + minIntervalMs;
        return waitMs;
    }

    /** Cumulative wall-clock time spent sleeping in {@link #awaitTurn} since this instance was
     *  created — meant to be diffed across two points in time (e.g. before/after a job) by the
     *  caller, same as {@code NvdRateLimiter#cumulativeWaitMillis()}. */
    public long cumulativeWaitMillis() {
        return TimeUnit.NANOSECONDS.toMillis(cumulativeWaitNanos.get());
    }
}
