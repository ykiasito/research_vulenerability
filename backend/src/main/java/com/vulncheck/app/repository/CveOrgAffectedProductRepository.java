package com.vulncheck.app.repository;

import com.vulncheck.app.entity.CveOrgAffectedProduct;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface CveOrgAffectedProductRepository
        extends JpaRepository<CveOrgAffectedProduct, Long>, CveOrgAffectedProductRepositoryCustom {

    /** Re-synced records replace their affected-product rows wholesale (cheap: a handful of rows
     *  per CVE) rather than diffing, since the raw affected[] array can restructure between
     *  updates in ways not worth reconciling row-by-row. */
    @Modifying
    @Transactional
    @Query(value = "DELETE FROM cve_org_affected_products WHERE cve_id = :cveId", nativeQuery = true)
    void deleteByCveId(@Param("cveId") String cveId);

    @Modifying
    @Transactional
    @Query(
            value = "INSERT INTO cve_org_affected_products (cve_id, vendor, product, package_name) "
                    + "VALUES (:cveId, :vendor, :product, :packageName)",
            nativeQuery = true)
    void insert(
            @Param("cveId") String cveId,
            @Param("vendor") String vendor,
            @Param("product") String product,
            @Param("packageName") String packageName);
}
