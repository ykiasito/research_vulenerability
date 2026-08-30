package com.vulncheck.app.repository;

import com.vulncheck.app.entity.CveOrgSyncState;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CveOrgSyncStateRepository extends JpaRepository<CveOrgSyncState, Short> {
}
