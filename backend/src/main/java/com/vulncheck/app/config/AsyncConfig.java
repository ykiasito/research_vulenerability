package com.vulncheck.app.config;

import java.util.concurrent.Executor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

@Configuration
@EnableAsync
public class AsyncConfig {

    /**
     * Sized for I/O-wait (external registry/NVD API calls), not CPU work — see the plan's
     * rationale for picking Spring's built-in @Async over a separate queue for this workload.
     *
     * <p>{@code setWaitForTasksToCompleteOnShutdown} + a modest await window lets an in-flight
     * item finish (and its DB write land) instead of being cut off mid-write on a graceful
     * `docker stop`/redeploy — real jobs run far longer than this window, so this alone doesn't
     * prevent a redeploy from interrupting a job; {@link com.vulncheck.app.service.StuckJobResumer}
     * is what makes that safe to recover from (resumes from the next still-PENDING item on
     * startup). Keeping this short also means `docker stop` isn't made to hang noticeably longer
     * than before on the common case (no job running, or between items).
     */
    @Bean(name = "researchJobExecutor")
    public Executor researchJobExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(4);
        executor.setMaxPoolSize(8);
        executor.setQueueCapacity(100);
        executor.setThreadNamePrefix("research-job-");
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(20);
        executor.initialize();
        return executor;
    }

    /**
     * Fans out Stage1 Tier1's per-item registry lookups (up to 10 registries) concurrently instead
     * of one at a time. Measured live 2026-08-24: sequential fan-out cost 40-80s/item on a cold
     * local CPE cache (each registry has its own several-second network round trip; a slow one
     * like Maven Central/crates.io/NuGet serializes behind every other), which alone blew past a
     * 100-items/1h (~36s/item) throughput target. Pool sized to the current registry count (10) so
     * a single item's full fan-out can run genuinely in parallel, capping per-item registry time at
     * roughly the slowest single registry's latency instead of the sum of all of them.
     */
    @Bean(name = "registryLookupExecutor")
    public Executor registryLookupExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(10);
        executor.setMaxPoolSize(20);
        executor.setQueueCapacity(200);
        executor.setThreadNamePrefix("registry-lookup-");
        executor.initialize();
        return executor;
    }

    /**
     * Fans out item processing *within* a single job — added 2026-08-25 after a strategy review
     * found {@link com.vulncheck.app.service.ResearchJobProcessingService#processJobAsync} looped
     * over a job's items one at a time; {@code researchJobExecutor} above only buys 8 concurrent
     * *jobs*, so a single large job was fully sequential regardless of that pool. A deliberately
     * separate pool from {@code registryLookupExecutor}, not a reuse of it: {@link
     * com.vulncheck.app.service.Stage1IdentificationService} submits its own registry fan-out
     * tasks to {@code registryLookupExecutor} and blocks (via {@code CompletableFuture.join}) on
     * the calling thread until they finish — if that calling thread were itself a
     * {@code registryLookupExecutor} thread (i.e. item-level work shared the same pool), a job
     * with enough concurrently-in-flight items could starve the pool with blocked outer tasks and
     * deadlock, since there'd be no free thread left to run the inner registry-lookup tasks they're
     * waiting on.
     *
     * <p>Sized at 8 by default (matching {@code researchJobExecutor}'s own max pool size) rather
     * than higher: each concurrent item can itself fan out up to 10 registry lookups onto the
     * shared {@code registryLookupExecutor} (max 20 threads), so 8 concurrent items already means
     * up to 80 registry calls contending for that pool at once — a reasonable degree of
     * oversubscription (queued, not rejected — {@code registryLookupExecutor}'s queue capacity is
     * 200), not worth pushing further and diluting the per-item registry fan-out's own parallelism
     * benefit. A large queue capacity (this pool's own core=max, so nothing ever runs beyond the
     * configured size at a time) absorbs the rest of a large job's items while they wait their
     * turn.
     *
     * <p>Externalized (item 167, 2026-09-01, {@code docs/spec/closed-mode-plan.md} §3-3 A4/§7 P4)
     * so a closed-mode deployment can raise it later — this "8" rationale (avoiding registry
     * fan-out oversubscription) evaporates once the registry clients themselves are gone, and the
     * only remaining constraint becomes Postgres/HikariCP (see {@code
     * spring.datasource.hikari.maximum-pool-size} in {@code application.yml}, sized to stay ahead
     * of this pool). The default (8) is unchanged for now; do not raise it without first measuring
     * HikariCP connection-acquire p95 under load (§7 P2/P3) — this pool's javadoc will go stale if
     * that measurement doesn't happen before the size is bumped.
     */
    @Bean(name = "itemProcessingExecutor")
    public Executor itemProcessingExecutor(
            @Value("${app.item-processing-pool-size:8}") int poolSize) {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(poolSize);
        executor.setMaxPoolSize(poolSize);
        executor.setQueueCapacity(5000);
        executor.setThreadNamePrefix("item-processing-");
        executor.initialize();
        return executor;
    }

    /**
     * Fans out {@link com.vulncheck.app.service.registry.RegistryMirrorSyncService}'s 9 per-
     * ecosystem mirror syncs concurrently (closed-mode backlog item 186) instead of one after
     * another — each ecosystem's own {@link
     * com.vulncheck.app.service.ratelimit.ExternalRegistryRateLimiter} pacing is already an
     * independent gate keyed by ecosystem (see that class's javadoc), so running all 9 at once
     * doesn't make any single ecosystem's own requests any less paced; it only stops one slow
     * ecosystem's run from serializing behind the other 8. A deliberately separate pool from
     * {@code registryLookupExecutor} above rather than a reuse of it: that pool exists to bound
     * a single CSV item's interactive registry fan-out during job processing (sized/tuned for
     * that request-latency-sensitive workload), while this one only ever runs 9 long-running
     * background tasks at a time (admin-triggered or the weekly schedule) — sharing the pool
     * would let an off-hours full mirror sync contend with, and add latency to, in-flight job
     * processing for no benefit either workload needs. Sized to exactly the ecosystem count (9,
     * see {@code RegistryMirrorSyncService#KNOWN_ECOSYSTEMS}) since {@code syncAll} never submits
     * more than 9 tasks to it at once; core == max, so no thread churn between runs.
     *
     * <p>This pool's 9 threads are the "9 concurrently-running sync workers" referenced by {@code
     * spring.datasource.hikari.maximum-pool-size}'s comment in {@code application.yml} (senior
     * review, PR #145 REVISE) — see that comment for why they are not simply added on top of
     * {@code app.item-processing-pool-size} when sizing the HikariCP pool: each worker holds a DB
     * connection only for a short per-chunk batch upsert, never while making its rate-limited HTTP
     * calls, so the 9 of them don't need 9 concurrently-held connections' worth of headroom.
     */
    @Bean(name = "registryMirrorSyncExecutor")
    public Executor registryMirrorSyncExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(9);
        executor.setMaxPoolSize(9);
        executor.setQueueCapacity(9);
        executor.setThreadNamePrefix("registry-mirror-sync-");
        executor.initialize();
        return executor;
    }
}
