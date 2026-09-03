package com.vulncheck.app.repository;

import com.vulncheck.app.entity.NvdCveSyncState;
import org.springframework.data.jpa.repository.JpaRepository;

public interface NvdCveSyncStateRepository extends JpaRepository<NvdCveSyncState, Short> {
}
