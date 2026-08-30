package com.vulncheck.app.repository;

import com.vulncheck.app.entity.CveOrgRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface CveOrgRecordRepository extends JpaRepository<CveOrgRecord, String> {

    @Modifying
    @Transactional
    @Query(
            value = """
                    INSERT INTO cve_org_records
                        (cve_id, title, description, cvss_score, cvss_severity, state,
                         date_published, date_updated, raw_json, last_synced_at)
                    VALUES
                        (:cveId, :title, :description, :cvssScore, :cvssSeverity, :state,
                         :datePublished, :dateUpdated, :rawJson, now())
                    ON CONFLICT (cve_id)
                    DO UPDATE SET title = EXCLUDED.title,
                                  description = EXCLUDED.description,
                                  cvss_score = EXCLUDED.cvss_score,
                                  cvss_severity = EXCLUDED.cvss_severity,
                                  state = EXCLUDED.state,
                                  date_published = EXCLUDED.date_published,
                                  date_updated = EXCLUDED.date_updated,
                                  raw_json = EXCLUDED.raw_json,
                                  last_synced_at = now()
                    """,
            nativeQuery = true)
    void upsert(
            @Param("cveId") String cveId,
            @Param("title") String title,
            @Param("description") String description,
            @Param("cvssScore") java.math.BigDecimal cvssScore,
            @Param("cvssSeverity") String cvssSeverity,
            @Param("state") String state,
            @Param("datePublished") java.time.OffsetDateTime datePublished,
            @Param("dateUpdated") java.time.OffsetDateTime dateUpdated,
            @Param("rawJson") String rawJson);
}
