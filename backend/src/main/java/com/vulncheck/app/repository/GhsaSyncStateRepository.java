package com.vulncheck.app.repository;

import com.vulncheck.app.entity.GhsaSyncState;
import org.springframework.data.jpa.repository.JpaRepository;

public interface GhsaSyncStateRepository extends JpaRepository<GhsaSyncState, Short> {
}
