package com.vulncheck.app.repository;

import com.vulncheck.app.entity.EcosystemRegistry;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Closed-mode backlog item 262 (Phase B6): on the {@code closed-mode} branch, every query here
 * returns an empty result — see {@link EcosystemRegistry}'s own javadoc for why the table is kept
 * permanently stripped rather than this repository/entity pair being deleted outright.
 */
public interface EcosystemRegistryRepository extends JpaRepository<EcosystemRegistry, Long> {

    List<EcosystemRegistry> findByEnabledTrue();
}
