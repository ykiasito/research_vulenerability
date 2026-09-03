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
     * Fans out item processing *within* a single job — added 2026-08-25 after a strategy review
     * found {@link com.vulncheck.app.service.ResearchJobProcessingService#processJobAsync} looped
     * over a job's items one at a time; {@code researchJobExecutor} above only buys 8 concurrent
     * *jobs*, so a single large job was fully sequential regardless of that pool.
     *
     * <p>Closed-mode backlog item 193 (B3, {@code docs/spec/closed-mode-plan.md} §7 P1/P4): this
     * pool used to be sized at 8 specifically to avoid oversubscribing a separate {@code
     * registryLookupExecutor} pool that fanned out each item's live registry HTTP calls — that
     * pool, and the live registry clients it served, are gone now (see {@link
     * com.vulncheck.app.service.Stage1IdentificationService}/{@link
     * com.vulncheck.app.service.Stage1RegistryIdentification}, both of which now do their registry
     * work — a local mirror DB read, not a network call — synchronously on the calling thread). The
     * remaining constraint is Postgres/HikariCP (see {@code
     * spring.datasource.hikari.maximum-pool-size} in {@code application.yml}, sized to stay ahead
     * of this pool). The default (8) is left unchanged here; raising it is a separate, deliberate
     * follow-up (do not raise it without first measuring HikariCP connection-acquire p95 under
     * load, §7 P2/P3).
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
