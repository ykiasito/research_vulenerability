package com.vulncheck.app.repository;

import com.vulncheck.app.entity.JobCostLedgerEntry;
import java.math.BigDecimal;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface JobCostLedgerRepository extends JpaRepository<JobCostLedgerEntry, Long> {

    List<JobCostLedgerEntry> findByJobIdOrderByRecordedAt(Long jobId);

    /**
     * Total realized (actual, post-reconcile) spend for a job across both ledgers — the figure
     * needed, together with the job's item count (see {@code ResearchJobItemRepository}), to
     * compute its $/item average for comparison against the $5/1,000-item NFR target. {@code
     * COALESCE} so a job with no ledger rows yet (e.g. never made an AI call) returns zero rather
     * than {@code null}.
     */
    @Query("SELECT COALESCE(SUM(e.actualCostUsd), 0) FROM JobCostLedgerEntry e WHERE e.jobId = :jobId")
    BigDecimal sumActualCostUsdByJobId(@Param("jobId") Long jobId);
}
