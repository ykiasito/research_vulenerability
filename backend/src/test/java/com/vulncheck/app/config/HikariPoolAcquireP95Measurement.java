package com.vulncheck.app.config;

import com.vulncheck.app.entity.ResearchJob;
import com.vulncheck.app.repository.ResearchJobRepository;
import com.vulncheck.app.service.ColumnMapping;
import com.vulncheck.app.service.ResearchJobProcessingService;
import com.vulncheck.app.service.ResearchJobService;
import com.vulncheck.app.service.registry.RegistryMirrorSyncService;
import com.zaxxer.hikari.HikariDataSource;
import com.zaxxer.hikari.metrics.IMetricsTracker;
import com.zaxxer.hikari.metrics.MetricsTrackerFactory;
import com.zaxxer.hikari.metrics.PoolStats;
import java.io.InputStream;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import javax.sql.DataSource;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

/**
 * One-off, task-directed measurement for closed-mode backlog item 198 ({@code
 * docs/spec/closed-mode-plan.md} §7 P2): runs a real, DB-heavy static item-processing job (Stage1
 * trigram search + Stage2's 4 local mirror sources, no AI — same {@code REAL_USER_ID}/{@code
 * real-1000.csv} convention as {@link com.vulncheck.app.service.Real1000ThroughputJobCreator})
 * concurrently with one real {@link RegistryMirrorSyncService#syncAllAndRelease} run (same
 * background-thread shape {@code AdminController#startRegistryMirrorSyncWorker} uses in
 * production), against the REAL dev database ({@code vulncheck}) — same {@link TestPropertySource}
 * override convention as {@code OsvBaselineSyncRealDevDbJobCreator}, plus an explicit {@code
 * spring.datasource.hikari.maximum-pool-size=20} so this measurement exercises the §7 P2
 * recommended value regardless of whatever default {@code application.yml} currently ships.
 *
 * <p>Captures every {@code connections.acquire} sample HikariCP records via a hand-rolled {@link
 * MetricsTrackerFactory} (part of {@code hikari-core} itself, no Micrometer/Actuator dependency
 * needed — this app has neither on its classpath) attached to the test context's own {@link
 * HikariDataSource} bean, then reports p50/p95/p99/max acquire latency once both the job and the
 * sync finish. {@code app.item-processing-pool-size} is left at its unchanged default (8) — only
 * the pool size is being validated here, per this task's own scope.
 *
 * <p>Throwaway; not part of the permanent suite (same convention as the other {@code *JobCreator}/
 * {@code *Measurement} classes in this package's sibling packages — kept, not deleted, as a
 * documented one-off; re-run by hand if the pool size is revisited later). Disabled by default —
 * a live job-creating, real-network-calling {@code @SpringBootTest} left enabled would silently
 * create another 1,000-item job and kick off a real 9-ecosystem registry sync against the real dev
 * DB on every {@code mvn test} run. Re-enable deliberately (remove the annotation, run once by
 * hand, re-add it) rather than leaving it on.
 *
 * <p>To run: temporarily remove the {@code @Disabled} annotation, then invoke {@code mvn test
 * -Dtest=HikariPoolAcquireP95Measurement} with {@code POSTGRES_PASSWORD} set in the environment
 * (see the {@code @TestPropertySource} password entry below).
 */
@SpringBootTest
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:postgresql://postgres:5432/vulncheck",
        "spring.datasource.username=vulncheck",
        // Resolved from the real POSTGRES_PASSWORD env var passed to this docker run invocation
        // (e.g. `docker run --env-file .env ...`) rather than a literal value checked into source.
        "spring.datasource.password=${POSTGRES_PASSWORD}",
        "spring.datasource.hikari.maximum-pool-size=20"
})
@Disabled("Live job-creating, real-network @SpringBootTest that would create another 1,000-item "
        + "job and trigger a real registry mirror sync against the real dev DB on every mvn test "
        + "invocation. Re-enable deliberately, by hand, never left on — see class javadoc. Requires "
        + "POSTGRES_PASSWORD to be passed in the environment (e.g. via --env-file) when run.")
class HikariPoolAcquireP95Measurement {

    private static final Long REAL_USER_ID = 5L;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private ResearchJobService researchJobService;

    @Autowired
    private ResearchJobProcessingService researchJobProcessingService;

    @Autowired
    private ResearchJobRepository researchJobRepository;

    @Autowired
    private RegistryMirrorSyncService registryMirrorSyncService;

    @Test
    void measureAcquireP95UnderConcurrentSyncAndItemProcessing() throws Exception {
        ConcurrentLinkedQueue<Long> acquireNanosSamples = new ConcurrentLinkedQueue<>();
        HikariDataSource hikariDataSource = (HikariDataSource) dataSource;
        hikariDataSource.setMetricsTrackerFactory(new MetricsTrackerFactory() {
            @Override
            public IMetricsTracker create(String poolName, PoolStats poolStats) {
                return new IMetricsTracker() {
                    @Override
                    public void recordConnectionAcquiredNanos(long elapsedAcquiredNanos) {
                        acquireNanosSamples.add(elapsedAcquiredNanos);
                    }
                };
            }
        });

        ResearchJob job;
        try (InputStream csv = getClass().getClassLoader().getResourceAsStream("real-1000.csv")) {
            job = researchJobService.createJob(
                    REAL_USER_ID, "real-1000.csv", csv, ColumnMapping.identity(), false);
        }
        Long jobId = job.getId();
        System.out.println("\n=== HIKARI P95 MEASUREMENT: created job " + jobId + " ===\n");

        boolean syncStarted = registryMirrorSyncService.tryBeginFullSync();
        Thread syncThread = null;
        if (syncStarted) {
            syncThread = new Thread(() -> {
                RegistryMirrorSyncService.SyncOutcome outcome = registryMirrorSyncService.syncAllAndRelease();
                System.out.println("\n=== HIKARI P95 MEASUREMENT: registry mirror sync finished: "
                        + outcome + " ===\n");
            }, "hikari-p95-measurement-sync");
            syncThread.start();
        } else {
            System.out.println("\n=== HIKARI P95 MEASUREMENT WARNING: registry mirror sync already "
                    + "running elsewhere — measurement proceeds with item-processing load only ===\n");
        }

        Instant start = Instant.now();
        researchJobProcessingService.processJobAsync(jobId);

        Duration waitTimeout = Duration.ofHours(3);
        String lastStatus = null;
        while (true) {
            ResearchJob current = researchJobRepository.findById(jobId).orElseThrow();
            lastStatus = current.getStatus();
            if (ResearchJob.STATUS_COMPLETED.equals(lastStatus)
                    || ResearchJob.STATUS_FAILED.equals(lastStatus)) {
                break;
            }
            if (Duration.between(start, Instant.now()).compareTo(waitTimeout) > 0) {
                throw new IllegalStateException("Job " + jobId + " did not reach a terminal status "
                        + "within " + waitTimeout + " (current status: " + lastStatus + ")");
            }
            Thread.sleep(2000);
        }
        Duration jobElapsed = Duration.between(start, Instant.now());

        if (syncThread != null) {
            syncThread.join();
        }
        Duration totalElapsed = Duration.between(start, Instant.now());

        List<Long> sortedNanos = new ArrayList<>(acquireNanosSamples);
        Collections.sort(sortedNanos);

        System.out.println("\n=== HIKARI P95 MEASUREMENT RESULT (job " + jobId + ") ===");
        System.out.println("job elapsed: " + jobElapsed);
        System.out.println("total elapsed (incl. registry mirror sync): " + totalElapsed);
        System.out.println("acquire samples: " + sortedNanos.size());
        if (!sortedNanos.isEmpty()) {
            System.out.println("acquire p50 (ms): " + toMillis(percentile(sortedNanos, 0.50)));
            System.out.println("acquire p95 (ms): " + toMillis(percentile(sortedNanos, 0.95)));
            System.out.println("acquire p99 (ms): " + toMillis(percentile(sortedNanos, 0.99)));
            System.out.println("acquire max (ms): " + toMillis(sortedNanos.get(sortedNanos.size() - 1)));
        }
        System.out.println("=== END RESULT ===\n");
    }

    /** Nearest-rank percentile over an already-sorted (ascending) sample list. */
    private static long percentile(List<Long> sortedNanos, double p) {
        int index = (int) Math.ceil(p * sortedNanos.size()) - 1;
        index = Math.max(0, Math.min(index, sortedNanos.size() - 1));
        return sortedNanos.get(index);
    }

    private static double toMillis(long nanos) {
        return nanos / 1_000_000.0;
    }
}
