package com.vulncheck.app.repository;

import com.vulncheck.app.entity.CsafSyncState;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CsafSyncStateRepository extends JpaRepository<CsafSyncState, String> {
}
