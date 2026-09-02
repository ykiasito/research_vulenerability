package com.vulncheck.app.repository;

import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * Plain {@link JdbcTemplate}-backed batch writer for {@code nvd_cve_cpe_match} — same rationale as
 * {@link NvdCveRecordRepository} (JDBC batch over JPA entities), even more important here: this
 * table is estimated at 10-15M rows total (§4-2-6 of the closed-mode plan).
 *
 * <p>Unlike {@code nvd_cve_records}, this table has no natural per-row upsert key (a single CVE can
 * report several structurally-identical-looking {@code cpeMatch} entries, and NVD doesn't expose a
 * stable id for one that survives across a re-fetch). So a CVE whose {@code cpeMatch} list changed
 * between syncs — which happens whenever {@code lastModified} moves, since re-scoring/re-scoping is
 * exactly the kind of edit that bumps it — is handled by {@link #replaceForCves}: delete every
 * existing row for that CVE, then insert its current set fresh. Simpler and more clearly correct
 * than trying to diff old vs. new match rows, at the cost of a full row rewrite for every CVE this
 * sync pass actually touches (bounded to whatever page NVD reports as changed, not the whole 10-15M
 * row table).
 */
@Repository
@RequiredArgsConstructor
public class NvdCveCpeMatchRepository {

    private final JdbcTemplate jdbcTemplate;

    /** One parsed {@code cpeMatch} entry, ready to insert. Not a JPA entity — see this class's
     *  javadoc for why the whole table is written via plain JDBC batches instead. */
    public record Row(String cveId, String part, String vendor, String product, String criteria,
            boolean vulnerable, String versionStartIncluding, String versionStartExcluding,
            String versionEndIncluding, String versionEndExcluding) {
    }

    /**
     * Deletes every existing {@code nvd_cve_cpe_match} row for each id in {@code cveIds}, then
     * inserts {@code rows} fresh — see the class javadoc for why this is a delete-then-insert
     * rather than an upsert. {@code cveIds} must include every CVE id that {@code rows} could
     * possibly reference, even a CVE whose current {@code cpeMatch} list is now empty (e.g. NVD
     * withdrew every affected-range entry on that CVE) — otherwise that CVE's now-stale rows from a
     * previous sync would never get cleared.
     */
    @Transactional
    public void replaceForCves(List<String> cveIds, List<Row> rows) {
        if (cveIds.isEmpty()) {
            return;
        }
        jdbcTemplate.batchUpdate("DELETE FROM nvd_cve_cpe_match WHERE cve_id = ?",
                cveIds.stream().map(id -> new Object[] {id}).toList());
        if (rows.isEmpty()) {
            return;
        }
        jdbcTemplate.batchUpdate("""
                INSERT INTO nvd_cve_cpe_match
                    (cve_id, part, vendor, product, criteria, vulnerable, version_start_including,
                     version_start_excluding, version_end_including, version_end_excluding)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows.stream()
                        .map(r -> new Object[] {r.cveId(), r.part(), r.vendor(), r.product(), r.criteria(),
                                r.vulnerable(), r.versionStartIncluding(), r.versionStartExcluding(),
                                r.versionEndIncluding(), r.versionEndExcluding()})
                        .toList());
    }
}
