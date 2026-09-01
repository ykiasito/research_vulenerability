package com.vulncheck.app.service.vuln;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.stereotype.Component;

/**
 * Paces calls against GitHub's published unauthenticated {@code api.github.com} rate limit — 60
 * requests/hour, no token, a single IP-wide budget shared across every {@code api.github.com}
 * endpoint (not per-endpoint — confirmed live 2026-08-27, see {@code
 * docs/spec/ghsa-mirror-plan.md} §5-2). Same fixed-gap, no-burst approach as {@code
 * com.vulncheck.app.service.nvd.NvdRateLimiter}, not {@code
 * com.vulncheck.app.service.ratelimit.ExternalRegistryRateLimiter}'s per-key map, since there's
 * only ever one caller/limit here — no per-ecosystem GHSA endpoint to multiplex across.
 *
 * <p><b>Originally added 2026-08-25</b> to pace {@code GhsaVulnerabilitySource}'s old per-item live
 * {@code api.github.com/advisories} calls — without it, a large job burned through the 60/hour
 * budget within the first minute or two, then every subsequent GHSA call got HTTP 403, previously
 * swallowed as a plain empty result indistinguishable from "this package genuinely has no
 * advisories", silently triggering a paid Stage4 AI search per item as if GHSA had legitimately
 * found nothing.
 *
 * <p><b>As of the GHSA mirror (plan §5-3/§7), {@code GhsaVulnerabilitySource} no longer uses this
 * class at all</b> — it queries the local mirror only, no live API calls, so nothing to pace. The
 * sole remaining consumer is {@code com.vulncheck.app.service.ghsa.GhsaSyncService}'s background
 * baseline/delta sync, which deliberately uses its own separate instance of this class (via the
 * public no-arg constructor, not the {@code @Component}-managed bean below) rather than sharing it
 * with any future *repo-scoped* {@code GhsaVulnerabilitySource} use this class was originally kept
 * around for (plan §5-3: sharing one instance across a background job and per-job instrumentation
 * would misattribute the sync's sleep time to whichever user job happens to run concurrently).
 */
@Component
public class GhsaRateLimiter {

    // 60 req/hour = 60,000ms average interval; padded ~8% for safety margin against clock drift.
    private static final long DEFAULT_MIN_INTERVAL_MS = 65_000;

    private final long minIntervalMs;
    private long nextAllowedAtMs = 0;

    // Cumulative time every caller has spent actually sleeping in awaitTurn, process-wide, since
    // this instance was created — lightweight app-log instrumentation (see
    // ResearchJobProcessingService's per-job stage/wait logging), not a permanent metrics system.
    private final AtomicLong cumulativeWaitNanos = new AtomicLong();

    public GhsaRateLimiter() {
        this(DEFAULT_MIN_INTERVAL_MS);
    }

    private GhsaRateLimiter(long minIntervalMs) {
        this.minIntervalMs = minIntervalMs;
    }

    /** Zero-wait instance for unit tests — mirrors {@code ExternalRegistryRateLimiter.disabledForTesting()}. */
    public static GhsaRateLimiter disabledForTesting() {
        return new GhsaRateLimiter(0L);
    }

    /** Blocks the calling thread only as long as needed to keep GHSA calls, process-wide, within
     *  the 60/hour cap; safe to call from multiple concurrent threads. {@code Thread.sleep} happens
     *  outside the synchronized slot-reservation ({@link #reserveSlot}) for the same
     *  monitor-convoy/graceful-shutdown reasons as {@code NvdRateLimiter}/{@code
     *  ExternalRegistryRateLimiter} — see their javadocs. */
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
