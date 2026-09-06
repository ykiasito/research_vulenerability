package com.vulncheck.app.repository;

import com.vulncheck.app.entity.CpeDictionarySyncState;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CpeDictionarySyncStateRepository extends JpaRepository<CpeDictionarySyncState, Short> {
}
