package com.vulncheck.app.service;

import com.vulncheck.app.entity.ResearchJob;
import com.vulncheck.app.repository.ResearchJobRepository;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/**
 * On startup, resumes any job left in {@code PROCESSING} — the only way that status can still be
 * set at startup is if a previous instance was killed mid-job (e.g. a redeploy destroying the
 * container while its in-flight {@code @Async} thread was still working — a real, observed
 * operational gap: {@code processJobAsync} always eventually sets {@code COMPLETED} on its own,
 * so a job can only be found PROCESSING here if something killed the process out from under it).
 *
 * <p>Safe to just call {@link ResearchJobProcessingService#processJobAsync} again: it only
 * (re-)processes items still {@code PENDING}, so already-{@code IDENTIFIED}/{@code UNIDENTIFIED}
 * items — and any Stage2/4 results already persisted for them — are left untouched. No wasted AI
 * calls or duplicate work on a resume.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class StuckJobResumer implements ApplicationRunner {

    private final ResearchJobRepository researchJobRepository;
    private final ResearchJobProcessingService researchJobProcessingService;

    @Override
    public void run(ApplicationArguments args) {
        List<ResearchJob> stuck = researchJobRepository.findByStatus(ResearchJob.STATUS_PROCESSING);
        for (ResearchJob job : stuck) {
            log.warn("Resuming job {} found stuck in PROCESSING at startup (likely killed mid-run by a previous instance)",
                    job.getId());
            researchJobProcessingService.processJobAsync(job.getId());
        }
    }
}
