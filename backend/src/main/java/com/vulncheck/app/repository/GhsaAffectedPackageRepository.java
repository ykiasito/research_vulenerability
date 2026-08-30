package com.vulncheck.app.repository;

import com.vulncheck.app.entity.GhsaAffectedPackage;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface GhsaAffectedPackageRepository extends JpaRepository<GhsaAffectedPackage, Long> {

    /** Re-synced advisories replace their package/range/version rows wholesale — cascades to
     *  {@code ghsa_affected_ranges}/{@code ghsa_affected_versions} via V19's {@code ON DELETE
     *  CASCADE}, mirroring {@code CveOrgAffectedProductRepository#deleteByCveId}'s precedent. */
    @Modifying
    @Transactional
    @Query(value = "DELETE FROM ghsa_affected_packages WHERE ghsa_id = :ghsaId", nativeQuery = true)
    void deleteByGhsaId(@Param("ghsaId") String ghsaId);

    /** Needs the generated id back (unlike CSAF's {@code csaf_products}, which is keyed by the
     *  document's own natural {@code csaf_product_id}) so the caller can attach {@code
     *  ghsa_affected_ranges}/{@code ghsa_affected_versions} child rows to it. Deliberately NOT
     *  {@code @Modifying} — same as {@code VulnerabilityRepository#upsertAndGetId} — since a
     *  {@code RETURNING} clause makes this behave as a row-returning query to Spring Data JPA, not
     *  a plain update/insert. */
    @Query(
            value = """
                    INSERT INTO ghsa_affected_packages (ghsa_id, ecosystem, package_name, package_name_normalized)
                    VALUES (:ghsaId, :ecosystem, :packageName, :packageNameNormalized)
                    ON CONFLICT (ghsa_id, ecosystem, package_name_normalized) DO NOTHING
                    RETURNING id
                    """,
            nativeQuery = true)
    Long insertAndGetId(
            @Param("ghsaId") String ghsaId,
            @Param("ecosystem") String ecosystem,
            @Param("packageName") String packageName,
            @Param("packageNameNormalized") String packageNameNormalized);
}
