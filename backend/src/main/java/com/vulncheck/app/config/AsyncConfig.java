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
}
