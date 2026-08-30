package com.vulncheck.app.repository;

import com.vulncheck.app.entity.OsvAffectedPackage;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface OsvAffectedPackageRepository extends JpaRepository<OsvAffectedPackage, Long> {

    /** Re-synced advisories replace their package/range/version rows wholesale — cascades to
     *  {@code osv_affected_ranges}/{@code osv_affected_versions} via V25's {@code ON DELETE
     *  CASCADE}, mirroring {@code GhsaAffectedPackageRepository#deleteByGhsaId}. */
    @Modifying
    @Transactional
    @Query(value = "DELETE FROM osv_affected_packages WHERE osv_id = :osvId", nativeQuery = true)
    void deleteByOsvId(@Param("osvId") String osvId);

    @Query(
            value = """
                    INSERT INTO osv_affected_packages (osv_id, ecosystem, package_name, package_name_normalized)
                    VALUES (:osvId, :ecosystem, :packageName, :packageNameNormalized)
                    ON CONFLICT (osv_id, ecosystem, package_name_normalized) DO NOTHING
                    RETURNING id
                    """,
            nativeQuery = true)
    Long insertAndGetId(
            @Param("osvId") String osvId,
            @Param("ecosystem") String ecosystem,
            @Param("packageName") String packageName,
            @Param("packageNameNormalized") String packageNameNormalized);
}
