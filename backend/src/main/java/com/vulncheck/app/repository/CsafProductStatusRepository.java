package com.vulncheck.app.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface CsafProductStatusRepository
        extends JpaRepository<com.vulncheck.app.entity.CsafProductStatus, Long>, CsafProductStatusRepositoryCustom {

    @Modifying
    @Transactional
    @Query(value = "DELETE FROM csaf_product_status WHERE vendor = :vendor AND advisory_id = :advisoryId", nativeQuery = true)
    void deleteByVendorAndAdvisoryId(@Param("vendor") String vendor, @Param("advisoryId") String advisoryId);
}
