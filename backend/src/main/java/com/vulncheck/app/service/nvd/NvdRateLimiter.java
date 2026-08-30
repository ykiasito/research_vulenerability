package com.vulncheck.app.service.nvd;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.stereotype.Component;

/**
 * Coordinates calls to NVD's endpoints across all threads in this JVM. Without a key NVD allows 5
 * requests / rolling 30s window; with a key that rises to 50 / rolling 30s. Enforces a
 * conservative fixed gap between any two calls process-wide rather than trying to allow bursts,
 * which keeps the logic simple and safely under whichever limit applies.
 *
 * <p>This is one shared, process-wide gate — it does not track quota per API key. When a caller
 * with a key and a caller without one interleave, the gate simply waits the shorter (keyed)
 * interval when a key is present <em>for that specific call</em>; a purist per-key token bucket
 * would be needed for perfect accuracy across mixed keyed/unkeyed traffic, but for this app's
 * scale (occasional background sync + per-item lookups, never a burst) this simplification is
 * good enough and NVD's own server-side enforcement is the real backstop — an occasional 429 is
 * already handled gracefully (caught, logged, treated as an empty result).
 *
 * <p><b>{@code Thread.sleep} deliberately happens outside the synchronized section</b> ({@link
 * #reserveSlot} only computes and books the next allowed slot, then returns): sleeping while
 * holding the lock would serialize every waiting caller into a "monitor convoy" — each thread
 * blocked on the monitor for the full sleep duration of the thread ahead of it, on top of its own
 * wait — and would make a caller's wait non-interruptible in a way that could stall a graceful
 * shutdown. Booking the slot under the lock and sleeping outside it keeps the same effective
 * pacing (the next-allowed-at bookkeeping is still atomic) while letting concurrently-waiting
 * threads actually sleep concurrently for their own (correctly staggered) durations.
 */
@Component
public class NvdRateLimiter {

    private static final long MIN_INTERVAL_MS_NO_KEY = 6500;
    // 50 req / 30s = 600ms average; padded for safety margin.
    private static final long MIN_INTERVAL_MS_WITH_KEY = 700;

    private long nextAllowedAtMs = 0;

    // Cumulative time every caller has spent actually sleeping in awaitTurn, process-wide, since
    // this instance was created — lightweight app-log instrumentation (see
    // ResearchJobProcessingService's per-job stage/wait logging), not a permanent metrics system.
    private final AtomicLong cumulativeWaitNanos = new AtomicLong();

    public void awaitTurn() {
        awaitTurn(false);
    }

    public void awaitTurn(boolean hasApiKey) {
        long waitMs = reserveSlot(hasApiKey);
        if (waitMs > 0) {
            cumulativeWaitNanos.addAndGet(TimeUnit.MILLISECONDS.toNanos(waitMs));
            try {
                Thread.sleep(waitMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /** Atomically books the next allowed slot and returns how long the caller must sleep to honor
     *  it (may be <= 0, meaning no wait needed) — see the class javadoc for why the actual sleep
     *  happens outside this synchronized method. */
    private synchronized long reserveSlot(boolean hasApiKey) {
        long minIntervalMs = hasApiKey ? MIN_INTERVAL_MS_WITH_KEY : MIN_INTERVAL_MS_NO_KEY;
        long now = System.currentTimeMillis();
        long waitMs = nextAllowedAtMs - now;
        nextAllowedAtMs = Math.max(now, nextAllowedAtMs) + minIntervalMs;
        return waitMs;
    }

    /** Cumulative wall-clock time spent sleeping in {@link #awaitTurn} since this instance was
     *  created — a monotonically increasing snapshot, meant to be diffed across two points in time
     *  (e.g. before/after a job) by the caller, not read as a standalone number. */
    public long cumulativeWaitMillis() {
        return TimeUnit.NANOSECONDS.toMillis(cumulativeWaitNanos.get());
    }
}
