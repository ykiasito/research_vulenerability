package com.vulncheck.app.repository;

import com.vulncheck.app.entity.CsafAdvisory;
import com.vulncheck.app.entity.CsafAdvisoryId;
import java.math.BigDecimal;
import java.time.OffsetDateTime;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface CsafAdvisoryRepository extends JpaRepository<CsafAdvisory, CsafAdvisoryId> {

    @Modifying
    @Transactional
    @Query(
            value = """
                    INSERT INTO csaf_advisories
                        (vendor, tracking_id, tracking_status, revision, title, tlp_label,
                         cvss_score, cvss_severity, date_published, date_updated, raw_json, last_synced_at)
                    VALUES
                        (:vendor, :trackingId, :trackingStatus, :revision, :title, :tlpLabel,
                         :cvssScore, :cvssSeverity, :datePublished, :dateUpdated, :rawJson, now())
                    ON CONFLICT (vendor, tracking_id)
                    DO UPDATE SET tracking_status = EXCLUDED.tracking_status,
                                  revision = EXCLUDED.revision,
                                  title = EXCLUDED.title,
                                  tlp_label = EXCLUDED.tlp_label,
                                  cvss_score = EXCLUDED.cvss_score,
                                  cvss_severity = EXCLUDED.cvss_severity,
                                  date_published = EXCLUDED.date_published,
                                  date_updated = EXCLUDED.date_updated,
                                  raw_json = EXCLUDED.raw_json,
                                  last_synced_at = now()
                    """,
            nativeQuery = true)
    void upsert(
            @Param("vendor") String vendor,
            @Param("trackingId") String trackingId,
            @Param("trackingStatus") String trackingStatus,
            @Param("revision") String revision,
            @Param("title") String title,
            @Param("tlpLabel") String tlpLabel,
            @Param("cvssScore") BigDecimal cvssScore,
            @Param("cvssSeverity") String cvssSeverity,
            @Param("datePublished") OffsetDateTime datePublished,
            @Param("dateUpdated") OffsetDateTime dateUpdated,
            @Param("rawJson") String rawJson);

    /** Used by {@code RedHatCsafSyncService} to consume {@code deletions.csv} (plan §4-2 step 4) —
     *  a native {@code @Modifying} delete, NOT {@code JpaRepository#deleteById}, deliberately: the
     *  cascade to {@code csaf_products}/{@code csaf_product_status} (V17's {@code ON DELETE CASCADE})
     *  is a database-level FK constraint that only fires once the {@code DELETE} statement itself
     *  actually executes against Postgres — {@code deleteById}'s {@code entityManager.remove()} marks
     *  the entity removed in Hibernate's persistence-context cache immediately (so a same-transaction
     *  {@code findById} on THIS entity looks deleted right away) but doesn't necessarily flush to the
     *  database before a query against a DIFFERENT, JPA-unrelated entity (there is no {@code
     *  @OneToMany}/{@code @ManyToOne} mapping between {@link com.vulncheck.app.entity.CsafAdvisory}
     *  and {@link com.vulncheck.app.entity.CsafProduct} — Hibernate's auto-flush heuristic has no way
     *  to know the two are FK-linked at the DB level). This method matches {@link
     *  com.vulncheck.app.repository.CsafProductRepository#deleteByVendorAndAdvisoryId}'s existing
     *  native-query convention, which doesn't have this gap.
     *
     *  <p>{@code clearAutomatically = true} for a second, related reason: a native {@code
     *  @Modifying} query bypasses Hibernate's persistence-context entity tracking entirely, so
     *  without this flag a PRIOR {@code findById} call earlier in the same transaction (e.g. a
     *  caller verifying the row existed before deleting it) leaves a stale cached {@link
     *  com.vulncheck.app.entity.CsafAdvisory} in the first-level cache — a later {@code findById} in
     *  that same transaction would then return the STALE (pre-delete) cached instance instead of
     *  querying the database, incorrectly looking like the delete never happened.
     *
     *  <p><b>Scope corrected (senior review REVISE item 8, 2026-08-27):</b> an earlier version of this
     *  javadoc implied this fix addressed a PRODUCTION data-corruption risk. The senior reviewer traced
     *  the actual production call flow and found that's overstated: {@code doSyncDelta} opens no
     *  long-lived transaction of its own — each {@code @Modifying @Transactional} repository call runs
     *  in its own transaction boundary, and no production code path does {@code findById} -> delete ->
     *  {@code findById} within a single transaction. The stale-first-level-cache issue this flag
     *  addresses is only reachable from a {@code @DataJpaTest}-style test context (where an entire test
     *  method runs inside one rolled-back transaction, so a same-method {@code findById} before AND
     *  after the delete really does share one persistence context) — observed directly in {@code
     *  RedHatCsafSyncServiceTest}, not in production. The fix itself ({@code clearAutomatically = true})
     *  is correct and free to keep regardless; only the significance of what it fixes is corrected
     *  here, so a future maintainer doesn't mistake this for a production data-integrity guard. */
    @Modifying(clearAutomatically = true)
    @Transactional
    @Query(value = "DELETE FROM csaf_advisories WHERE vendor = :vendor AND tracking_id = :trackingId", nativeQuery = true)
    void deleteByVendorAndTrackingId(@Param("vendor") String vendor, @Param("trackingId") String trackingId);
}
