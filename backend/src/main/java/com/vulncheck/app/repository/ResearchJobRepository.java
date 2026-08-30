package com.vulncheck.app.repository;

import com.vulncheck.app.entity.ResearchJob;
import java.time.OffsetDateTime;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface ResearchJobRepository extends JpaRepository<ResearchJob, Long> {

    List<ResearchJob> findByUserIdOrderByCreatedAtDesc(Long userId);

    List<ResearchJob> findByStatus(String status);

    /** Bulk delete, not entity-by-entity — {@code research_job_items} (and everything hanging off
     *  it: identified_products, job_item_vulnerabilities) cascades via the DB-level FK regardless
     *  of how the parent row is deleted, so this stays a single statement even for a large batch. */
    @Modifying
    @Transactional
    @Query(value = "DELETE FROM research_jobs WHERE created_at < :cutoff", nativeQuery = true)
    int deleteByCreatedAtBefore(@Param("cutoff") OffsetDateTime cutoff);
}
