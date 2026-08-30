package com.vulncheck.app.repository;

import com.vulncheck.app.entity.EcosystemRegistry;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EcosystemRegistryRepository extends JpaRepository<EcosystemRegistry, Long> {

    List<EcosystemRegistry> findByEnabledTrue();
}
