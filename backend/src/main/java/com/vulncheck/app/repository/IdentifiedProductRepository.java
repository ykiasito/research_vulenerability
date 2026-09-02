package com.vulncheck.app.repository;

import com.vulncheck.app.entity.IdentifiedProduct;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface IdentifiedProductRepository extends JpaRepository<IdentifiedProduct, Long> {

    Optional<IdentifiedProduct> findFirstByJobItemId(Long jobItemId);

    List<IdentifiedProduct> findByJobItemIdIn(List<Long> jobItemIds);

    /**
     * Distinct package names this app has previously resolved via a live registry lookup for the
     * given ecosystem (closed-mode backlog item 183) — the seed source {@link
     * com.vulncheck.app.service.registry.RegistryMirrorSyncService} feeds into each ecosystem's
     * {@code *MirrorSyncService#syncPackages}. See that class's own javadoc for why "names this app
     * has actually seen" was chosen over a full-registry crawl.
     */
    @Query("SELECT DISTINCT p.packageName FROM IdentifiedProduct p "
            + "WHERE p.ecosystem = :ecosystem AND p.packageName IS NOT NULL")
    List<String> findDistinctPackageNamesByEcosystem(@Param("ecosystem") String ecosystem);
}
