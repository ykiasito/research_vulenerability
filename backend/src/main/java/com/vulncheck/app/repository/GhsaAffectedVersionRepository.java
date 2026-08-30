package com.vulncheck.app.repository;

import com.vulncheck.app.entity.GhsaAffectedVersion;
import com.vulncheck.app.entity.GhsaAffectedVersionId;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface GhsaAffectedVersionRepository extends JpaRepository<GhsaAffectedVersion, GhsaAffectedVersionId> {

    @Modifying
    @Transactional
    @Query(
            value = """
                    INSERT INTO ghsa_affected_versions (affected_package_id, version)
                    VALUES (:affectedPackageId, :version)
                    ON CONFLICT (affected_package_id, version) DO NOTHING
                    """,
            nativeQuery = true)
    void insert(@Param("affectedPackageId") Long affectedPackageId, @Param("version") String version);
}
