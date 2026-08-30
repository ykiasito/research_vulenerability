package com.vulncheck.app.repository;

import com.vulncheck.app.entity.GhsaAdvisory;
import java.math.BigDecimal;
import java.time.OffsetDateTime;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface GhsaAdvisoryRepository extends JpaRepository<GhsaAdvisory, String> {

    @Modifying
    @Transactional
    @Query(
            value = """
                    INSERT INTO ghsa_advisories
                        (ghsa_id, cve_id, summary, details, severity, cvss_score, withdrawn_at,
                         published_at, updated_at, html_url, raw_json, last_synced_at)
                    VALUES
                        (:ghsaId, :cveId, :summary, :details, :severity, :cvssScore, :withdrawnAt,
                         :publishedAt, :updatedAt, :htmlUrl, :rawJson, now())
                    ON CONFLICT (ghsa_id)
                    DO UPDATE SET cve_id = EXCLUDED.cve_id,
                                  summary = EXCLUDED.summary,
                                  details = EXCLUDED.details,
                                  severity = EXCLUDED.severity,
                                  cvss_score = EXCLUDED.cvss_score,
                                  withdrawn_at = EXCLUDED.withdrawn_at,
                                  published_at = EXCLUDED.published_at,
                                  updated_at = EXCLUDED.updated_at,
                                  html_url = EXCLUDED.html_url,
                                  raw_json = EXCLUDED.raw_json,
                                  last_synced_at = now()
                    """,
            nativeQuery = true)
    void upsert(
            @Param("ghsaId") String ghsaId,
            @Param("cveId") String cveId,
            @Param("summary") String summary,
            @Param("details") String details,
            @Param("severity") String severity,
            @Param("cvssScore") BigDecimal cvssScore,
            @Param("withdrawnAt") OffsetDateTime withdrawnAt,
            @Param("publishedAt") OffsetDateTime publishedAt,
            @Param("updatedAt") OffsetDateTime updatedAt,
            @Param("htmlUrl") String htmlUrl,
            @Param("rawJson") String rawJson);

    /** Baseline tombstone pruning (plan §6-3): rows this baseline run never touched (their {@code
     *  last_synced_at} is still older than the run's own start time) are no longer present in
     *  github-reviewed and are deleted. Cascades to {@code ghsa_affected_packages} (and, from
     *  there, {@code ghsa_affected_ranges}/{@code ghsa_affected_versions}) via V19's {@code ON
     *  DELETE CASCADE}. */
    @Modifying
    @Transactional
    @Query(value = "DELETE FROM ghsa_advisories WHERE last_synced_at < :runStartedAt", nativeQuery = true)
    int deleteNotSyncedSince(@Param("runStartedAt") OffsetDateTime runStartedAt);

    @Query(value = "SELECT COUNT(*) FROM ghsa_advisories", nativeQuery = true)
    long countAll();

    /** The database server's own current time — {@code GhsaSyncService#doSyncBaseline} uses this
     *  (not the application server's {@code OffsetDateTime.now()}) as the tombstone-pruning
     *  boundary ({@code runStartedAt}), specifically to avoid comparing it against {@code
     *  last_synced_at} values written by THIS SAME upsert's own {@code now()} SQL call using a
     *  DIFFERENT clock. Measured live during this implementation: the app/DB containers' clocks can
     *  differ by a few hundred ms — if the app server's clock happens to be even slightly ahead, a
     *  row this very baseline run just upserted (whose {@code last_synced_at} came from the DB's
     *  own, slightly-behind {@code now()}) could otherwise satisfy {@code last_synced_at <
     *  runStartedAt} and be immediately deleted as a false tombstone, right after being inserted. */
    @Query(value = "SELECT now()", nativeQuery = true)
    java.time.Instant currentDatabaseTime();
}
