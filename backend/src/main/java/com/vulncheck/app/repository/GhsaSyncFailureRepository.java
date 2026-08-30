package com.vulncheck.app.repository;

import com.vulncheck.app.entity.GhsaSyncFailure;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface GhsaSyncFailureRepository extends JpaRepository<GhsaSyncFailure, String> {

    long countByDeadLetteredAtIsNotNull();

    /** A direct {@code DELETE}, not {@link #deleteById}, which internally does a {@code
     *  findById(...).ifPresent(this::delete)} — an unnecessary SELECT-then-DELETE round trip for
     *  what's normally a no-op on a mostly-empty table (baseline sync calls this once per
     *  successfully-upserted document, ~34,768 times/run — senior review item 13). {@code
     *  flushAutomatically}: bulk JPQL update/delete statements bypass the persistence context by
     *  design (JPA spec) — without this, a same-transaction {@code save(...)} of a {@link
     *  GhsaSyncFailure} row that hasn't been flushed to the DB yet (e.g. a prior consecutive-failure
     *  recorded earlier in the same delta run) could be invisible to this DELETE. {@code
     *  clearAutomatically} drops the now-stale managed instance from the persistence context so a
     *  later {@code findById} in the same transaction doesn't return first-level-cache-stale data. */
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Transactional
    @Query("DELETE FROM GhsaSyncFailure f WHERE f.ghsaId = :ghsaId")
    void deleteByGhsaId(@Param("ghsaId") String ghsaId);
}
