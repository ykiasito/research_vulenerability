package com.vulncheck.app.service.nvd;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

class NvdRateLimiterTest {

    @Test
    void pacesSuccessiveKeyedCallsByAtLeastTheKeyedMinimumInterval() {
        NvdRateLimiter limiter = new NvdRateLimiter();

        long start = System.currentTimeMillis();
        limiter.awaitTurn(true);
        limiter.awaitTurn(true);
        long elapsed = System.currentTimeMillis() - start;

        assertThat(elapsed).isGreaterThanOrEqualTo(700L);
    }

    @Test
    void tracksCumulativeWaitTimeAcrossCalls() {
        NvdRateLimiter limiter = new NvdRateLimiter();
        assertThat(limiter.cumulativeWaitMillis()).isZero();

        limiter.awaitTurn(true); // first call never waits (nextAllowedAtMs starts at 0)
        limiter.awaitTurn(true); // second call must wait ~700ms

        assertThat(limiter.cumulativeWaitMillis()).isGreaterThanOrEqualTo(700L);
    }

    @Test
    void pacingGuaranteeHoldsUnderConcurrentCallersEvenThoughTheLockIsReleasedBeforeSleeping() throws Exception {
        // Regression guard for moving Thread.sleep outside the synchronized slot-reservation:
        // releasing the lock before sleeping must not let two threads slip through with less than
        // the minimum interval between their slots.
        NvdRateLimiter limiter = new NvdRateLimiter();
        int callers = 5;
        long minIntervalMs = 700L; // keyed interval

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
                    limiter.awaitTurn(true);
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
        for (int i = 1; i < sorted.size(); i++) {
            long gap = sorted.get(i) - sorted.get(i - 1);
            assertThat(gap).isGreaterThanOrEqualTo(minIntervalMs - 5);
        }
        long lastElapsed = sorted.get(sorted.size() - 1) - start;
        assertThat(lastElapsed).isGreaterThanOrEqualTo((callers - 1) * minIntervalMs - 5);
    }
}
