package com.vulncheck.app.service.registry;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

class ExternalRegistryRateLimiterTest {

    @Test
    void pacesSuccessiveCallsToTheSameEcosystemByAtLeastItsMinimumInterval() {
        // crates.io's published hard rule: max 1 request/second.
        ExternalRegistryRateLimiter limiter = new ExternalRegistryRateLimiter();

        long start = System.currentTimeMillis();
        limiter.awaitTurn("crates.io");
        limiter.awaitTurn("crates.io");
        long elapsed = System.currentTimeMillis() - start;

        assertThat(elapsed).isGreaterThanOrEqualTo(1000L);
    }

    @Test
    void doesNotPaceCallsToDifferentEcosystemsAgainstEachOther() {
        ExternalRegistryRateLimiter limiter = new ExternalRegistryRateLimiter();
        limiter.awaitTurn("crates.io"); // primes crates.io's next-allowed time ~1.1s out

        long start = System.currentTimeMillis();
        limiter.awaitTurn("npm"); // independent gate, should not wait for crates.io's turn
        long elapsed = System.currentTimeMillis() - start;

        assertThat(elapsed).isLessThan(500L);
    }

    @Test
    void pacingGuaranteeHoldsUnderConcurrentCallersEvenThoughTheLockIsReleasedBeforeSleeping() throws Exception {
        // Regression guard for moving Thread.sleep outside the per-ecosystem lock: releasing the
        // lock before sleeping must not let two threads slip through with less than the minimum
        // interval between their slots — each caller's completion time must still land on its own,
        // correctly staggered slot.
        ExternalRegistryRateLimiter limiter = new ExternalRegistryRateLimiter();
        int callers = 5;
        // npm's own default interval (300ms) so this test isn't tied to crates.io's 1.1s pacing.
        long minIntervalMs = 300L;

        ExecutorService pool = Executors.newFixedThreadPool(callers);
        CountDownLatch ready = new CountDownLatch(callers);
        CountDownLatch go = new CountDownLatch(1);
        List<Long> completionTimestamps = new CopyOnWriteArrayList<>();
        long start = System.currentTimeMillis();

        try {
            for (int i = 0; i < callers; i++) {
                pool.submit(() -> {
                    ready.countDown();
                    try {
                        go.await();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    limiter.awaitTurn("npm");
                    completionTimestamps.add(System.currentTimeMillis());
                });
            }
            assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue();
            go.countDown();
            pool.shutdown();
            assertThat(pool.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
        } finally {
            pool.shutdownNow();
        }

        assertThat(completionTimestamps).hasSize(callers);
        List<Long> sorted = completionTimestamps.stream().sorted().toList();
        // Every consecutive pair of callers must be spaced at least minIntervalMs apart — a small
        // negative tolerance absorbs System.currentTimeMillis() granularity, not a real violation.
        for (int i = 1; i < sorted.size(); i++) {
            long gap = sorted.get(i) - sorted.get(i - 1);
            assertThat(gap).isGreaterThanOrEqualTo(minIntervalMs - 5);
        }
        // And the whole batch must span at least (callers - 1) intervals from the start — proves
        // the calls were genuinely staggered end-to-end, not just individually spaced by luck.
        long lastElapsed = sorted.get(sorted.size() - 1) - start;
        assertThat(lastElapsed).isGreaterThanOrEqualTo((callers - 1) * minIntervalMs - 5);
    }

    @Test
    void disabledForTestingNeverWaits() {
        ExternalRegistryRateLimiter limiter = ExternalRegistryRateLimiter.disabledForTesting();

        long start = System.currentTimeMillis();
        limiter.awaitTurn("crates.io");
        limiter.awaitTurn("crates.io");
        limiter.awaitTurn("maven");
        long elapsed = System.currentTimeMillis() - start;

        assertThat(elapsed).isLessThan(50L);
    }
}
