package com.vulncheck.app.repository;

import com.vulncheck.app.entity.IdentifiedProduct;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IdentifiedProductRepository extends JpaRepository<IdentifiedProduct, Long> {

    Optional<IdentifiedProduct> findFirstByJobItemId(Long jobItemId);

    List<IdentifiedProduct> findByJobItemIdIn(List<Long> jobItemIds);
}
