package com.vulncheck.app.repository;

import com.vulncheck.app.entity.OsvAffectedRange;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface OsvAffectedRangeRepository extends JpaRepository<OsvAffectedRange, Long> {

    @Modifying
    @Transactional
    @Query(
            value = """
                    INSERT INTO osv_affected_ranges
                        (affected_package_id, range_type, introduced_version, fixed_version, last_affected_version)
                    VALUES
                        (:affectedPackageId, :rangeType, :introducedVersion, :fixedVersion, :lastAffectedVersion)
                    """,
            nativeQuery = true)
    void insert(
            @Param("affectedPackageId") Long affectedPackageId,
            @Param("rangeType") String rangeType,
            @Param("introducedVersion") String introducedVersion,
            @Param("fixedVersion") String fixedVersion,
            @Param("lastAffectedVersion") String lastAffectedVersion);
}
