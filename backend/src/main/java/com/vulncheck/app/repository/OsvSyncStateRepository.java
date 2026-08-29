package com.vulncheck.app.repository;

import com.vulncheck.app.entity.OsvSyncState;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OsvSyncStateRepository extends JpaRepository<OsvSyncState, Short> {
}
