package com.vulncheck.app.repository;

import com.vulncheck.app.entity.CpeDictionaryEntry;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface CpeDictionaryRepository extends JpaRepository<CpeDictionaryEntry, Long>, CpeDictionaryRepositoryCustom {

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
                    """,
            nativeQuery = true)
    void upsert(
            @Param("cpeString") String cpeString,
            @Param("title") String title,
            @Param("vendor") String vendor,
            @Param("product") String product);
}
