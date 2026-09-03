package com.vulncheck.app.service.vuln;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.stereotype.Component;

/**
 * Paces {@code com.vulncheck.app.service.osv.OsvSyncService}'s calls against {@code
 * osv-vulnerabilities.storage.googleapis.com} (both the baseline {@code {ecosystem}/all.zip}
 * downloads and delta's per-document {@code {directory}/{id}.json} fetches) — see {@code
 * docs/spec/osv-mirror-plan.md} §6-4/§9-0 item 3: anonymous GETs against this public GCS bucket
 * were measured live to hit no rate limit or throttling across a dozen-plus requests, so unlike
 * {@link GhsaRateLimiter} (a hard 60/hour published cap) this is a safety net against future
 * behavior changes, not a compliance mechanism for a known limit — same rationale tier as {@code
 * api.osv.dev}'s own documented-no-limit FAQ answer (closed-mode backlog item 264/B4: the
 * per-item live {@code OsvRateLimiter} that used to pace {@code api.osv.dev} query calls at
 * 100ms, cited here only as a comparison figure, has since been deleted along with the live path
 * it paced).
 *
 * <p>The exact interval is not load-bearing: this background sync processes on the order of tens
 * of documents per day (plan §2-2: ~60/day in-scope changes), so even a several-hundred-ms pace has
 * no meaningful effect on sync completion time. 200ms was picked as a middle ground between the
 * now-deleted {@code OsvRateLimiter}'s 100ms (a documented-no-limit, actively-queried-per-item
 * endpoint) and {@link GhsaRateLimiter}'s 65s (a hard published cap) — plan §10-1 item 4 leaves the
 * exact figure as an implementation-time detail.
 *
 * <p>Own separate instance per {@code OsvSyncService}, not the {@code @Component}-managed bean,
 * same reasoning as {@link GhsaRateLimiter}'s own javadoc: a background sync's sleep time must not
 * be misattributed to whichever user job happens to run concurrently.
 */
@Component
public class OsvSyncRateLimiter {

    private static final long DEFAULT_MIN_INTERVAL_MS = 200;

    private final long minIntervalMs;
    private long nextAllowedAtMs = 0;

    private final AtomicLong cumulativeWaitNanos = new AtomicLong();

    public OsvSyncRateLimiter() {
        this(DEFAULT_MIN_INTERVAL_MS);
    }

    private OsvSyncRateLimiter(long minIntervalMs) {
        this.minIntervalMs = minIntervalMs;
    }

    /** Zero-wait instance for unit tests. */
    public static OsvSyncRateLimiter disabledForTesting() {
        return new OsvSyncRateLimiter(0L);
    }

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

    public long cumulativeWaitMillis() {
        return TimeUnit.NANOSECONDS.toMillis(cumulativeWaitNanos.get());
    }
}
