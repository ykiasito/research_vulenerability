package com.vulncheck.app.repository;

import com.vulncheck.app.entity.ResearchJobItem;
import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ResearchJobItemRepository extends JpaRepository<ResearchJobItem, Long> {

    List<ResearchJobItem> findByJobIdOrderById(Long jobId);

    /**
     * Paginated counterpart of {@link #findByJobIdOrderById(Long)}, used only by {@link
     * com.vulncheck.app.controller.JobController#detail} (closed-mode backlog item 267) — the
     * unpaginated overload above stays as-is for every other caller ({@code exportCsv}, which must
     * keep exporting every item, plus {@code ResearchJobProcessingService}'s own full-job scans).
     * Paginating here is what actually shrinks {@code JobItemVulnerabilityRepository
     * #findCappedViewsByJobItemIdIn}'s window-function sort down to one page's worth of items'
     * findings instead of the whole job's, since the detail view only ever looks up findings for
     * whichever item ids this page returned.
     */
    Page<ResearchJobItem> findByJobIdOrderById(Long jobId, Pageable pageable);

    List<ResearchJobItem> findByJobIdAndStatusOrderById(Long jobId, String status);
}
