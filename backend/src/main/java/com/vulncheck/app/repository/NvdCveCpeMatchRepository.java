package com.vulncheck.app.repository;

import java.util.ArrayList;
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
 *
 * <p><b>Sliced batches</b> (closed-mode backlog item 202, REVISE round 1, point 4): a single NVD API
 * page can carry up to 2,000 CVEs, and the design estimate is ~10-15M {@code cpeMatch} rows across
 * ~320k CVEs — roughly 40-50 matches per CVE on average, and considerably more for a
 * kernel/appliance-style advisory with a large {@code configurations} tree. Building one page's
 * entire delete+insert as a single unbounded {@link JdbcTemplate#batchUpdate} call (both the
 * per-row parameter list and the single enclosing transaction) risks tens of thousands of parameter
 * sets in one JDBC batch/transaction. {@link #replaceForCves} slices both the delete and insert
 * batches into {@link #BATCH_SLICE_SIZE}-row pieces (same technique as {@code
 * RegistryMirrorSyncService#chunk}) while keeping the whole call inside one {@code @Transactional}
 * method, so a page's delete+insert for every CVE it touches still commits (or rolls back)
 * atomically as one unit — only the JDBC batch size itself is bounded, not the transaction boundary.
 */
@Repository
@RequiredArgsConstructor
public class NvdCveCpeMatchRepository {

    /** Max rows per {@link JdbcTemplate#batchUpdate} call — see the class javadoc's "Sliced
     *  batches" note. Chosen well under a single NVD page's worst-case row count while still being
     *  large enough that slicing overhead is negligible. */
    private static final int BATCH_SLICE_SIZE = 10_000;

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
        for (List<String> slice : slice(cveIds, BATCH_SLICE_SIZE)) {
            jdbcTemplate.batchUpdate("DELETE FROM nvd_cve_cpe_match WHERE cve_id = ?",
                    slice.stream().map(id -> new Object[] {id}).toList());
        }
        if (rows.isEmpty()) {
            return;
        }
        for (List<Row> slice : slice(rows, BATCH_SLICE_SIZE)) {
            jdbcTemplate.batchUpdate("""
                    INSERT INTO nvd_cve_cpe_match
                        (cve_id, part, vendor, product, criteria, vulnerable, version_start_including,
                         version_start_excluding, version_end_including, version_end_excluding)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    slice.stream()
                            .map(r -> new Object[] {r.cveId(), r.part(), r.vendor(), r.product(), r.criteria(),
                                    r.vulnerable(), r.versionStartIncluding(), r.versionStartExcluding(),
                                    r.versionEndIncluding(), r.versionEndExcluding()})
                            .toList());
        }
    }

    private static <T> List<List<T>> slice(List<T> items, int sliceSize) {
        List<List<T>> slices = new ArrayList<>();
        for (int i = 0; i < items.size(); i += sliceSize) {
            slices.add(items.subList(i, Math.min(i + sliceSize, items.size())));
        }
        return slices;
    }
}
