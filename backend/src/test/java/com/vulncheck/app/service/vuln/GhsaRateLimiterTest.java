package com.vulncheck.app.service.vuln;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * Unlike {@code ExternalRegistryRateLimiterTest}, this doesn't assert the real pacing interval
 * via an actual sleep — GHSA's 60/hour cap means a real wait is ~65s, too slow for a unit test to
 * sleep through. {@link GhsaRateLimiter#awaitTurn()}'s wait/no-wait math is the same fixed-gap
 * shape as {@code NvdRateLimiter} (also untested by real sleep, for the same reason), so only the
 * test-disabling path — the one every other test in this codebase actually relies on — is
 * covered here.
 */
class GhsaRateLimiterTest {

    @Test
    void disabledForTestingNeverWaits() {
        GhsaRateLimiter limiter = GhsaRateLimiter.disabledForTesting();

        long start = System.currentTimeMillis();
        limiter.awaitTurn();
        limiter.awaitTurn();
        limiter.awaitTurn();
        long elapsed = System.currentTimeMillis() - start;

        assertThat(elapsed).isLessThan(50L);
    }
}
