package com.vulncheck.app.repository;

import com.vulncheck.app.entity.CsafProduct;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface CsafProductRepository extends JpaRepository<CsafProduct, Long>, CsafProductRepositoryCustom {

    /** Re-synced advisories replace their product rows wholesale — cascades to {@code
     *  csaf_product_status} via the FK's {@code ON DELETE CASCADE} (V17), mirroring {@code
     *  CveOrgAffectedProductRepository#deleteByCveId}'s precedent. */
    @Modifying
    @Transactional
    @Query(value = "DELETE FROM csaf_products WHERE vendor = :vendor AND advisory_id = :advisoryId", nativeQuery = true)
    void deleteByVendorAndAdvisoryId(@Param("vendor") String vendor, @Param("advisoryId") String advisoryId);

    List<CsafProduct> findByVendorAndAdvisoryId(String vendor, String advisoryId);
}
