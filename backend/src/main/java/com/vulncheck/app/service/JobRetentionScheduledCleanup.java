package com.vulncheck.app.service;

import com.vulncheck.app.repository.ResearchJobRepository;
import java.time.OffsetDateTime;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Daily automatic rotation of old research jobs — CSV upload results aren't meant to accumulate
 * forever. Deletes {@code research_jobs} rows older than {@link #retentionDays}; {@code
 * research_job_items}/{@code identified_products}/{@code job_item_vulnerabilities} cascade via
 * the DB-level FK. Configurable via {@code JOB_RETENTION_DAYS} (default 30); set to 0 or negative
 * to disable entirely.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JobRetentionScheduledCleanup {

    private final ResearchJobRepository researchJobRepository;

    @Value("${app.job-retention-days:30}")
    private int retentionDays;

    @Scheduled(cron = "0 0 4 * * *", zone = "UTC")
    public void deleteOldJobs() {
        if (retentionDays <= 0) {
            return;
        }
        OffsetDateTime cutoff = OffsetDateTime.now().minusDays(retentionDays);
        int deleted = researchJobRepository.deleteByCreatedAtBefore(cutoff);
        if (deleted > 0) {
            log.info("Job retention cleanup: deleted {} research jobs older than {} days", deleted, retentionDays);
        }
    }
}
