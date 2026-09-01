package com.vulncheck.app.repository;

import com.vulncheck.app.entity.CpeDictionaryEntry;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface CpeDictionaryRepository extends JpaRepository<CpeDictionaryEntry, Long>, CpeDictionaryRepositoryCustom {

    /**
     * senior-reviewer REVISE (PR #75): the {@code WHERE} predicate below on the {@code ON CONFLICT
     * DO UPDATE} mirrors the same "skip a no-op rewrite" predicate as {@link
     * CpeDictionaryRepositoryImpl#upsertBatch} -- see that method's comment for the full 10GB-cap /
     * GIN-index rationale. This single-row path is used by {@code
     * NvdCpeSyncService#syncKeywordSinglePage}/{@code upsertProduct}, a much lower-volume caller
     * than the batch path, but keeping both predicates identical avoids one silently drifting from
     * the other.
     *
     * <p>Side effect: {@code last_synced_at} now means "last time this row's content changed", not
     * "last time NVD reported this row" -- confirmed unread anywhere in the app (not even the admin
     * screen) before making this change.
     *
     * <p>Note: the {@code WHERE} predicate's commentary lives here rather than as a SQL {@code --}
     * comment inside the {@code @Query} text itself -- Spring Data's native-query parameter-binding
     * parser scans the raw query string for quote characters to find {@code :name} bindings, and
     * does not understand SQL line comments, so an apostrophe inside an inline {@code --} comment
     * (e.g. "row's") was previously miscounted as an unterminated string literal and broke query
     * parsing at startup.
     */
    @Modifying
    @Transactional
    @Query(
            value = """
                    INSERT INTO cpe_dictionary (cpe_string, title, vendor, product, last_synced_at)
                    VALUES (:cpeString, :title, :vendor, :product, now())
                    ON CONFLICT (cpe_string)
                    DO UPDATE SET title = EXCLUDED.title,
                                  vendor = EXCLUDED.vendor,
                                  product = EXCLUDED.product,
                                  last_synced_at = now()
                    WHERE cpe_dictionary.title IS DISTINCT FROM EXCLUDED.title
                       OR cpe_dictionary.vendor IS DISTINCT FROM EXCLUDED.vendor
                       OR cpe_dictionary.product IS DISTINCT FROM EXCLUDED.product
                    """,
            nativeQuery = true)
    void upsert(
            @Param("cpeString") String cpeString,
            @Param("title") String title,
            @Param("vendor") String vendor,
            @Param("product") String product);
}
