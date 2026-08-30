package com.vulncheck.app.repository;

import com.vulncheck.app.entity.OsvAdvisory;
import java.math.BigDecimal;
import java.time.OffsetDateTime;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface OsvAdvisoryRepository extends JpaRepository<OsvAdvisory, String> {

    @Modifying
    @Transactional
    @Query(
            value = """
                    INSERT INTO osv_advisories
                        (osv_id, cve_id, ghsa_id, summary, details, severity, cvss_score, withdrawn_at,
                         published_at, updated_at, html_url, last_synced_at)
                    VALUES
                        (:osvId, :cveId, :ghsaId, :summary, :details, :severity, :cvssScore, :withdrawnAt,
                         :publishedAt, :updatedAt, :htmlUrl, now())
                    ON CONFLICT (osv_id)
                    DO UPDATE SET cve_id = EXCLUDED.cve_id,
                                  ghsa_id = EXCLUDED.ghsa_id,
                                  summary = EXCLUDED.summary,
                                  details = EXCLUDED.details,
                                  severity = EXCLUDED.severity,
                                  cvss_score = EXCLUDED.cvss_score,
                                  withdrawn_at = EXCLUDED.withdrawn_at,
                                  published_at = EXCLUDED.published_at,
                                  updated_at = EXCLUDED.updated_at,
                                  html_url = EXCLUDED.html_url,
                                  last_synced_at = now()
                    """,
            nativeQuery = true)
    void upsert(
            @Param("osvId") String osvId,
            @Param("cveId") String cveId,
            @Param("ghsaId") String ghsaId,
            @Param("summary") String summary,
            @Param("details") String details,
            @Param("severity") String severity,
            @Param("cvssScore") BigDecimal cvssScore,
            @Param("withdrawnAt") OffsetDateTime withdrawnAt,
            @Param("publishedAt") OffsetDateTime publishedAt,
            @Param("updatedAt") OffsetDateTime updatedAt,
            @Param("htmlUrl") String htmlUrl);

    /** Baseline tombstone pruning (mirrors {@code GhsaAdvisoryRepository#deleteNotSyncedSince}):
     *  rows this baseline run never touched (their {@code last_synced_at} is still older than the
     *  run's own start time) are no longer present in the source data and are deleted. Cascades to
     *  {@code osv_affected_packages} (and, from there, {@code osv_affected_ranges}/{@code
     *  osv_affected_versions}) via V25's {@code ON DELETE CASCADE}. */
    @Modifying
    @Transactional
    @Query(value = "DELETE FROM osv_advisories WHERE last_synced_at < :runStartedAt", nativeQuery = true)
    int deleteNotSyncedSince(@Param("runStartedAt") OffsetDateTime runStartedAt);

    @Query(value = "SELECT COUNT(*) FROM osv_advisories", nativeQuery = true)
    long countAll();

    /** The database server's own current time — see {@code GhsaAdvisoryRepository#currentDatabaseTime}'s
     *  javadoc for why baseline tombstone pruning must use this rather than the app server's clock. */
    @Query(value = "SELECT now()", nativeQuery = true)
    java.time.Instant currentDatabaseTime();
}
