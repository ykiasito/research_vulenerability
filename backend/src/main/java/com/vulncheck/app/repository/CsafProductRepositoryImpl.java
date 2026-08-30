package com.vulncheck.app.repository;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * See {@code CveOrgAffectedProductRepositoryImpl} for why the fuzzy path is raw JDBC + {@code SET
 * LOCAL} rather than a declarative {@code @Query} — only the {@code %} operator can use a pg_trgm
 * GIN index, and its threshold is a session setting, not a bindable query parameter.
 *
 * <p><b>Phase 2 go/no-go review item 4 — query shape fix (hard merge gate):</b> the trgm {@code %}
 * query alone measured 6,835ms/lookup against ~3.8M {@code csaf_products} rows (the real corpus size
 * once Red Hat's purl-derived naming and improved folding are both in place, per the review's volume
 * estimate) — catastrophic against this project's 1,000-items/3-hours throughput target. {@link
 * #findCandidateProductsExact} is now the PRIMARY path: a purl-derived {@code component_name} is
 * usually already an exact, clean package name (e.g. {@code "openssl"}), so an equality lookup
 * against the V20 generated+indexed {@code component_name_normalized} column resolves the common
 * case without ever touching the trgm index. {@link #findCandidateProducts} (the original fuzzy
 * path) is retained purely as the fallback for when the equality lookup finds nothing (e.g. Siemens'
 * free-text hardware names, which don't reduce to a single clean token).
 *
 * <p><b>Measured {@code EXPLAIN ANALYZE} (2026-08-27, against this project's own live Postgres 16
 * instance — {@code docker exec ... psql}, not a separate benchmark rig — loaded with 3,800,000
 * synthetic {@code csaf_products} rows via {@code generate_series} to reach the review's ~3.8M
 * post-purl-fix/post-fold Red Hat volume estimate, 50,000 of them a repeated {@code "openssl"}-family
 * name to give the actual query this app issues something realistic to search):</b>
 *
 * <table border="1">
 * <caption>{@code csaf_products} candidate lookup — before/after query shape, both measured live</caption>
 * <tr><th>rows in table</th><th>component_name shape</th><th>query</th><th>plan</th><th>timing</th></tr>
 * <tr><td>3,800,000</td>
 *     <td>OLD (pre-item-2): raw NEVRA strings, e.g. {@code "openssl-1:3.0.19-25.el9.x86_64"} — one
 *     distinct string per (component, version, arch) combination, no equality path meaningful</td>
 *     <td>{@code WHERE vendor IN (?,?) AND component_name % 'openssl'} (trgm fuzzy — the only path
 *     that existed before this migration)</td>
 *     <td>{@code Bitmap Heap Scan} + {@code Bitmap Index Scan on
 *     idx_csaf_products_component_name_trgm} (GIN index correctly used — not the V9-style "index
 *     unusable at all" failure); {@code Rows Removed by Index Recheck: 49583} — the GIN bitmap's
 *     lossy 50,000-row candidate set collapses to only 417 once precisely rechecked at the 0.35
 *     threshold, a direct, measured illustration of item 2's correctness bug: most real
 *     {@code "openssl-<version>.<arch>"} NEVRA strings score BELOW 0.35 similarity to {@code
 *     "openssl"} and are invisible to this query even where it doesn't time out</td>
 *     <td>measured 96.8ms execution / 100.3ms wall</td></tr>
 * <tr><td>3,800,000 (separate load)</td>
 *     <td>NEW (post-item-2/3): purl-derived clean names, e.g. {@code "openssl"} (version/arch moved
 *     to separate columns/purl qualifiers) — same {@code "openssl"} row repeated 50,000 times</td>
 *     <td>SAME OLD query shape (trgm fuzzy) against the NEW naming, for comparison</td>
 *     <td>{@code Bitmap Heap Scan} + {@code Bitmap Index Scan on idx_csaf_products_component_name_trgm}
 *     — no recheck loss this time (every candidate IS an exact {@code "openssl"} match)</td>
 *     <td>measured 70.6ms execution / 75.0ms wall</td></tr>
 * <tr><td>3,800,000 (same NEW-naming load)</td>
 *     <td>NEW naming, same data as the row above</td>
 *     <td>NEW: {@code WHERE vendor IN (?,?) AND component_name_normalized = 'openssl'} ({@link
 *     #findCandidateProductsExact})</td>
 *     <td>{@code Index Scan using idx_csaf_products_component_name_normalized} (the V20 composite
 *     btree on {@code (vendor, component_name_normalized)} — no bitmap/recheck step at all, an
 *     equality predicate on a btree goes straight to the matching leaf rows)</td>
 *     <td>measured 0.066ms execution / 2.82ms wall (dominated by client round-trip, not server work)</td></tr>
 * </table>
 *
 * <p><b>Corrected explanation of the go/no-go review's own 6,835ms figure (senior review REVISE item
 * 7, 2026-08-27):</b> an earlier version of this javadoc hedged the gap between this class's own
 * 70-97ms synthetic-benchmark measurement and the review's 6,835ms figure as "plausibly ... a colder
 * page cache" — the senior reviewer traced and measured the REAL cause instead: the synthetic
 * benchmark above used ~6,000 mostly-{@code filler-N} names with minimal real trigram overlap, while
 * the real 28,082-distinct-name corpus has heavy substring overlap ({@code openssl}/{@code
 * openssl-libs}/{@code openssl-devel}/{@code nss}/{@code gnutls} all share the trigram-rich substring
 * {@code ssl}), which drives up GIN candidate-set size and recheck cost far beyond what a
 * low-overlap synthetic name distribution predicts. Reviewer's own re-measurement against the REAL
 * name distribution at 1,751,250 rows (2026-08-27): {@code component_name % 'openssl'} = 500.8ms
 * (301,983 GIN candidates, 296,202 removed by recheck), {@code 'redhat kernel'} = 416.2ms, {@code
 * 'kernel'} = 99.4ms — confirming the trgm fallback path is genuinely expensive at real-corpus scale,
 * not a benchmark artifact, which is exactly why REVISE item 5 (below) scopes it to Siemens only
 * rather than trying to further optimize it as a Red Hat path.
 *
 * <p><b>REVISE item 1 (senior review 2026-08-27, CRITICAL):</b> {@link #findCandidateProductsExact}
 * previously had {@code LIMIT 30} with no {@code ORDER BY} at all — ties silently broke on physical
 * row order (roughly year-ascending, since rows land in tar-walk/insertion order), so a query for a
 * common name like {@code 'kernel'} (5,514 matching real rows) returned {@code RHSA-1999:1} through
 * {@code RHSA-1999:30} and NEVER anything recent. V21 denormalizes the parent advisory's {@code
 * date_updated} onto {@code csaf_products} as {@code advisory_updated_at} (populated at ingest by
 * {@code CsafDocumentUpsertService}) specifically so both {@link #findCandidateProductsExact} and the
 * {@link #findCandidateProducts} fallback's own tiebreak can {@code ORDER BY advisory_updated_at DESC
 * NULLS LAST} without a join — measured by the reviewer at ~1.0ms this way vs ~16.8ms for a
 * join-based alternative.
 *
 * <p><b>REVISE item 5 (senior review 2026-08-27):</b> {@link #findCandidateProducts} (the trgm
 * fallback) is now scoped to {@code vendor = 'siemens'} only, backed by a partial GIN index (V21) —
 * see {@link #TRGM_FALLBACK_VENDOR}'s own javadoc for why Red Hat never legitimately needs this path.
 * The equality path ({@link #findCandidateProductsExact}) remains dramatically faster than either
 * trgm measurement above and is the only path Red Hat ever takes.
 */
@Repository
@RequiredArgsConstructor
class CsafProductRepositoryImpl implements CsafProductRepositoryCustom {

    /** Mirrors {@code CpeDictionaryRepositoryImpl#upsertBatch}'s convention — chunked rather than
     *  one {@code jdbcTemplate.batchUpdate} call for an entire advisory's rows (go/no-go review item
     *  7: a single Red Hat advisory can produce up to ~12,056 product rows). */
    private static final int BATCH_CHUNK_SIZE = 2_000;

    private final JdbcTemplate jdbcTemplate;

    /** {@link #findCandidateProducts} (the trgm fallback) is scoped to this vendor only — see the
     *  class javadoc's "item 5" section and V21's migration comment. Red Hat's purl-derived names are,
     *  by item 2/4's own construction, always found via {@link #findCandidateProductsExact} when a
     *  match exists at all; the fuzzy fallback exists specifically for Siemens' free-text hardware
     *  names, which don't reduce to a single clean token. */
    private static final String TRGM_FALLBACK_VENDOR = "siemens";

    @Override
    @Transactional
    public List<CsafProductCandidate> findCandidateProductsExact(List<String> vendors, String normalizedComponentName, int limit) {
        if (vendors.isEmpty() || normalizedComponentName == null || normalizedComponentName.isBlank()) {
            return List.of();
        }
        String vendorPlaceholders = vendors.stream().map(v -> "?").collect(Collectors.joining(","));
        // REVISE item 1 (senior review 2026-08-27, CRITICAL): ORDER BY advisory_updated_at DESC — see
        // V21's migration comment for why this column exists and the class javadoc for why an
        // unordered LIMIT was actively wrong (ties silently broke on physical row order, i.e. roughly
        // year-ascending, so a common name like 'kernel' returned ONLY 1999-era advisories).
        String sql = "SELECT vendor, advisory_id, csaf_product_id, component_name, component_version, platform_name "
                + "FROM csaf_products "
                + "WHERE vendor IN (" + vendorPlaceholders + ") AND component_name_normalized = ? "
                + "ORDER BY advisory_updated_at DESC NULLS LAST "
                + "LIMIT ?";

        List<Object> args = new ArrayList<>(vendors);
        args.add(normalizedComponentName);
        args.add(limit);

        return jdbcTemplate.query(sql, this::mapCandidate, args.toArray());
    }

    @Override
    @Transactional
    public List<CsafProductCandidate> findCandidateProducts(String componentQuery, double threshold, int limit) {
        jdbcTemplate.execute("SET LOCAL pg_trgm.similarity_threshold = " + threshold);

        // REVISE item 5 (senior review 2026-08-27): scoped to TRGM_FALLBACK_VENDOR ('siemens') only —
        // see the field javadoc and V21's partial-GIN-index migration comment. REVISE item 1 also
        // applies its recency tiebreak here: the original `ORDER BY similarity(...) DESC` alone is an
        // all-ties sort whenever several rows share an identical name, the same underlying problem as
        // item 1's unordered LIMIT.
        String sql = "SELECT vendor, advisory_id, csaf_product_id, component_name, component_version, platform_name "
                + "FROM csaf_products "
                + "WHERE vendor = ? AND component_name % ? "
                + "ORDER BY similarity(component_name, ?) DESC, advisory_updated_at DESC NULLS LAST "
                + "LIMIT ?";

        return jdbcTemplate.query(sql, this::mapCandidate, TRGM_FALLBACK_VENDOR, componentQuery, componentQuery, limit);
    }

    private CsafProductCandidate mapCandidate(java.sql.ResultSet rs, int rowNum) throws java.sql.SQLException {
        return new CsafProductCandidate(
                rs.getString("vendor"),
                rs.getString("advisory_id"),
                rs.getString("csaf_product_id"),
                rs.getString("component_name"),
                rs.getString("component_version"),
                rs.getString("platform_name"));
    }

    @Override
    @Transactional
    public void insertBatch(List<CsafProductInsertRow> rows) {
        if (rows.isEmpty()) {
            return;
        }
        for (int start = 0; start < rows.size(); start += BATCH_CHUNK_SIZE) {
            List<CsafProductInsertRow> chunk = rows.subList(start, Math.min(start + BATCH_CHUNK_SIZE, rows.size()));
            jdbcTemplate.batchUpdate("""
                    INSERT INTO csaf_products
                        (vendor, advisory_id, csaf_product_id, component_name, component_version,
                         platform_name, cpe, purl, raw_leaf_name, advisory_updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    chunk.stream()
                            .map(r -> new Object[] {r.vendor(), r.advisoryId(), r.csafProductId(), r.componentName(),
                                    r.componentVersion(), r.platformName(), r.cpe(), r.purl(), r.rawLeafName(),
                                    r.advisoryUpdatedAt()})
                            .toList());
        }
    }
}
