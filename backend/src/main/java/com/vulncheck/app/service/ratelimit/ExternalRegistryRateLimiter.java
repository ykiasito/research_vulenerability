package com.vulncheck.app.service.ratelimit;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import org.springframework.stereotype.Component;

/**
 * Paces every registry lookup, process-wide, against each individual public registry's own
 * acceptable-use limit — one independent gate per ecosystem, not a single shared gate, so waiting
 * on one registry never delays a concurrent call to a different one (Stage1's registry fan-out,
 * see {@code registryLookupExecutor}, is deliberately parallel *across* ecosystems; this only
 * serializes repeated calls to the *same* one, including a single client's own internal retries).
 *
 * <p>Added 2026-08-24 after the registry-lookup parallelization (up to 10 concurrent registries
 * per item, no per-item pacing across an entire job) turned out to have no rate limiting at all
 * against these free public services — a real risk once running at 1,000-item-job scale, not
 * merely theoretical: crates.io publishes a hard rule (max 1 request/second, see
 * https://crates.io/data-access) that this app's own {@code CratesIoRegistryClient} could easily
 * have burst past, and Maven Central has begun actively rate-limiting/temporarily-blocking
 * high-volume/bot-like traffic patterns (https://central.sonatype.org/faq/429-error/) — exactly
 * the shape of traffic {@code MavenCentralRegistryClient} can produce on a single pathological
 * item (up to 31 requests) with zero pacing between them. The remaining registries have no
 * published number as of 2026-08 (Hex.pm documents 100 req/min/IP; npm/PyPI/NuGet/RubyGems/
 * Packagist/pub.dev/the Go proxy don't publish a fixed one) — a conservative default is used for
 * those rather than assuming unlimited.
 *
 * <p><b>{@code Thread.sleep} deliberately happens outside each ecosystem's lock</b> ({@link
 * #reserveSlot} only books the next-allowed slot under the lock, then returns) — sleeping while
 * holding the lock would serialize every thread waiting on the same ecosystem into a "monitor
 * convoy" (each one blocked on the lock for the full sleep duration of whichever thread grabbed it
 * first, on top of its own wait) and make the wait non-interruptible in a way that could stall a
 * graceful shutdown. Booking the slot under the lock keeps the pacing guarantee exact (the
 * next-allowed-at bookkeeping is still atomic per ecosystem) while letting concurrently-waiting
 * threads actually sleep concurrently for their own, correctly staggered durations.
 */
@Component
public class ExternalRegistryRateLimiter {

    // Map.ofEntries rather than Map.of: the latter tops out at 10 key-value pairs, and this map
    // has 11.
    private static final Map<String, Long> DEFAULT_MIN_INTERVALS_MS = Map.ofEntries(
            Map.entry("crates.io", 1100L),   // hard published rule: max 1 req/sec
            Map.entry("maven", 1000L),       // actively rate-limits high-volume/bot-like consumers
            Map.entry("hex", 700L),          // published: 100 req/min/IP -> 600ms avg, padded
            Map.entry("npm", 300L),
            Map.entry("pypi", 200L),
            Map.entry("rubygems", 300L),
            Map.entry("packagist", 500L),
            Map.entry("pub", 500L),
            Map.entry("go", 500L),
            Map.entry("nuget", 100L),        // published limits are generous (1,000-20,000 req/min)
            Map.entry("siemens_csaf", 500L), // no published limit (docs/spec/csaf-vendor-advisory-plan.md
                                              // §5-1) — same conservative default the fallback below would
                                              // already apply, made an explicit entry per §5-4/§5-5 so the
                                              // pacing this vendor gets is visible here rather than implicit
            Map.entry("redhat_csaf", 500L)); // no published limit either (plan §5-2) — same conservative
                                              // default, same rationale as siemens_csaf above. Applied to
                                              // the changes.csv/deletions.csv delta fetches and the
                                              // archive download's initial request (RedHatCsafSyncService);
                                              // the archive body streaming itself is one download, not
                                              // paced per-request (see that class's javadoc).
    private static final long DEFAULT_FALLBACK_INTERVAL_MS = 500L;

    private final Map<String, Long> minIntervalMsByEcosystem;
    private final long fallbackIntervalMs;
    private final Map<String, Lock> locks = new ConcurrentHashMap<>();
    private final Map<String, Long> nextAllowedAtMs = new ConcurrentHashMap<>();

    // Cumulative time every caller has spent actually sleeping in awaitTurn, per ecosystem,
    // process-wide, since this instance was created — lightweight app-log instrumentation (see
    // ResearchJobProcessingService's per-job stage/wait logging), not a permanent metrics system.
    private final Map<String, AtomicLong> cumulativeWaitNanosByEcosystem = new ConcurrentHashMap<>();

    public ExternalRegistryRateLimiter() {
        this(DEFAULT_MIN_INTERVALS_MS, DEFAULT_FALLBACK_INTERVAL_MS);
    }

    private ExternalRegistryRateLimiter(Map<String, Long> minIntervalMsByEcosystem, long fallbackIntervalMs) {
        this.minIntervalMsByEcosystem = minIntervalMsByEcosystem;
        this.fallbackIntervalMs = fallbackIntervalMs;
    }

    /** Zero-wait instance for unit tests — the pacing behavior itself has its own dedicated test;
     *  a real per-call sleep here would just slow down every other registry client's test suite
     *  for no benefit. */
    public static ExternalRegistryRateLimiter disabledForTesting() {
        return new ExternalRegistryRateLimiter(Map.of(), 0L);
    }

    /** Blocks the calling thread only as long as needed to keep this ecosystem's own call rate
     *  within its limit; safe to call from multiple concurrent threads (e.g. this app's parallel
     *  registry fan-out) since each ecosystem's turn-taking is independently locked. */
    public void awaitTurn(String ecosystem) {
        long minIntervalMs = minIntervalMsByEcosystem.getOrDefault(ecosystem, fallbackIntervalMs);
        if (minIntervalMs <= 0) {
            return;
        }
        long waitMs = reserveSlot(ecosystem, minIntervalMs);
        if (waitMs > 0) {
            cumulativeWaitNanosByEcosystem.computeIfAbsent(ecosystem, k -> new AtomicLong())
                    .addAndGet(TimeUnit.MILLISECONDS.toNanos(waitMs));
            try {
                Thread.sleep(waitMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /** Atomically books the next allowed slot for this ecosystem and returns how long the caller
     *  must sleep to honor it (may be <= 0, meaning no wait needed) — see the class javadoc for why
     *  the actual sleep happens outside this method's lock. */
    private long reserveSlot(String ecosystem, long minIntervalMs) {
        Lock lock = locks.computeIfAbsent(ecosystem, k -> new ReentrantLock());
        lock.lock();
        try {
            long now = System.currentTimeMillis();
            long nextAllowed = nextAllowedAtMs.getOrDefault(ecosystem, 0L);
            long waitMs = nextAllowed - now;
            nextAllowedAtMs.put(ecosystem, Math.max(now, nextAllowed) + minIntervalMs);
            return waitMs;
        } finally {
            lock.unlock();
        }
    }

    /** Snapshot of cumulative wait time spent pacing calls, per ecosystem, since this instance was
     *  created — meant to be diffed across two points in time (e.g. before/after a job) by the
     *  caller, same as {@link com.vulncheck.app.service.nvd.NvdRateLimiter#cumulativeWaitMillis()}. */
    public Map<String, Long> cumulativeWaitMillisByEcosystem() {
        Map<String, Long> snapshot = new LinkedHashMap<>();
        cumulativeWaitNanosByEcosystem.forEach((ecosystem, nanos) ->
                snapshot.put(ecosystem, TimeUnit.NANOSECONDS.toMillis(nanos.get())));
        return snapshot;
    }
}
