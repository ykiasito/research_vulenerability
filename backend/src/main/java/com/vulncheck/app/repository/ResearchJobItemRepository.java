package com.vulncheck.app.repository;

import com.vulncheck.app.entity.ResearchJobItem;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ResearchJobItemRepository extends JpaRepository<ResearchJobItem, Long> {

    List<ResearchJobItem> findByJobIdOrderById(Long jobId);

    List<ResearchJobItem> findByJobIdAndStatusOrderById(Long jobId, String status);
}
