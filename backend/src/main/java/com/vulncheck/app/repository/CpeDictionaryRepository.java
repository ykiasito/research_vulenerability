package com.vulncheck.app.repository;

import com.vulncheck.app.entity.CpeDictionaryEntry;
import org.springframework.data.jpa.repository.JpaRepository;

// Closed-mode backlog item 273 (B4): the single-row @Query upsert method that used to live here
// (INSERT ... ON CONFLICT, mirroring CpeDictionaryRepositoryImpl#upsertBatch's own "skip a no-op
// rewrite" predicate) was used exclusively by NvdCpeSyncService#syncKeywordSinglePage/
// upsertProduct -- both deleted alongside the live NVD CPE keyword-search fallback they backed.
// With that sole caller gone, this method was fully dead code, so it was removed too rather than
// left as an untested, unreferenced native query. The batch path (CpeDictionaryRepositoryImpl
// #upsertBatch, used by NvdCpeSyncService#sync's bulk/keyword sync) is unaffected.
public interface CpeDictionaryRepository extends JpaRepository<CpeDictionaryEntry, Long>, CpeDictionaryRepositoryCustom {
}
