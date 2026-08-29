package com.vulncheck.app.repository;

import com.vulncheck.app.entity.OsvSyncFailure;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface OsvSyncFailureRepository extends JpaRepository<OsvSyncFailure, String> {

    long countByDeadLetteredAtIsNotNull();

    /** Direct DELETE, not {@link #deleteById} — see {@code GhsaSyncFailureRepository#deleteByGhsaId}'s
     *  javadoc for why (avoids an unnecessary SELECT-then-DELETE round trip on a mostly-empty table). */
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Transactional
    @Query("DELETE FROM OsvSyncFailure f WHERE f.osvId = :osvId")
    void deleteByOsvId(@Param("osvId") String osvId);
}
