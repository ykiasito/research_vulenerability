package com.vulncheck.app.repository;

import com.vulncheck.app.entity.CpeDictionaryEntry;
import java.sql.Array;
import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * {@code similarity(col, query) > threshold} — the query shape the old {@code @Query}-annotated
 * method used — cannot use a pg_trgm GIN index at all (confirmed live via {@code EXPLAIN}: even
 * with {@code enable_seqscan} forced off, PostgreSQL has no alternative plan and falls back to a
 * full sequential scan regardless). Only the {@code %} similarity operator is index-accelerated,
 * but its threshold is a session-level setting ({@code pg_trgm.similarity_threshold}), not a query
 * parameter — hence the manual {@code SET LOCAL} + raw JDBC here instead of a declarative
 * {@code @Query}. At the row counts this table had during initial development (a few hundred to
 * ~1,400 rows) the sequential scan was invisibly fast either way; this only becomes a real problem
 * as the dictionary grows, which is exactly the kind of thing worth fixing before it's a surprise.
 */
@Repository
@RequiredArgsConstructor
class CpeDictionaryRepositoryImpl implements CpeDictionaryRepositoryCustom {

    private final JdbcTemplate jdbcTemplate;

    @Override
    @Transactional
    public void upsertBatch(List<CpeDictionaryEntry> entries) {
        if (entries.isEmpty()) {
            return;
        }
        jdbcTemplate.batchUpdate("""
                INSERT INTO cpe_dictionary (cpe_string, title, vendor, product, last_synced_at)
                VALUES (?, ?, ?, ?, now())
                ON CONFLICT (cpe_string)
                DO UPDATE SET title = EXCLUDED.title,
                              vendor = EXCLUDED.vendor,
                              product = EXCLUDED.product,
                              last_synced_at = now()
                """,
                entries.stream()
                        .map(e -> new Object[] {e.getCpeString(), e.getTitle(), e.getVendor(), e.getProduct()})
                        .toList());
    }

    @Override
    @Transactional(readOnly = true)
    public List<CpeDictionaryEntry> findByLeadingInitialismMatch(String abbreviation, String anchor, int limit) {
        // Builds e.g. abbreviation "vs" + anchor "code" -> "^v[^_]*_s[^_]*_code(_|$)": each
        // abbreviation letter must lead its own product-slug word (a run of non-'_' characters),
        // immediately followed by the literal anchor phrase at a word boundary or the end of the
        // slug. Safe to interpolate both directly into the regex without escaping: callers only ever
        // build abbreviation/anchor from tokenize()'d [a-z0-9]+ words joined by "_" (see
        // Stage1IdentificationService#expandLeadingInitialism), so neither can contain a regex
        // metacharacter.
        StringBuilder regex = new StringBuilder("^");
        for (int i = 0; i < abbreviation.length(); i++) {
            regex.append(abbreviation.charAt(i)).append("[^_]*_");
        }
        regex.append(anchor).append("(_|$)");

        // Ordered shortest-product-slug-first as a secondary preference once the regex has already
        // done the real filtering: the canonical/base product for a name usually has the shortest
        // slug, with extensions, plugins and sub-tools ("visual_studio_code_eslint_extension")
        // trailing behind it as longer variants.
        String sql = "SELECT * FROM ("
                + "SELECT DISTINCT ON (vendor, product) id, cpe_string, title, vendor, product, last_synced_at "
                + "FROM cpe_dictionary WHERE product ~ ? "
                + "ORDER BY vendor, product"
                + ") deduped ORDER BY length(product) ASC LIMIT ?";
        List<CpeDictionaryEntry> results = new java.util.ArrayList<>();
        jdbcTemplate.query(sql, rs -> {
            CpeDictionaryEntry entry = new CpeDictionaryEntry();
            entry.setId(rs.getLong("id"));
            entry.setCpeString(rs.getString("cpe_string"));
            entry.setTitle(rs.getString("title"));
            entry.setVendor(rs.getString("vendor"));
            entry.setProduct(rs.getString("product"));
            entry.setLastSyncedAt(rs.getObject("last_synced_at", OffsetDateTime.class));
            results.add(entry);
        }, regex.toString(), limit);
        return results;
    }

    @Override
    @Transactional
    public List<CpeDictionaryEntry> findFuzzyMatches(String productQuery, double productThreshold, double titleThreshold, int limit) {
        Map<Long, CpeDictionaryEntry> byId = new LinkedHashMap<>();
        Map<Long, Double> bestScoreById = new LinkedHashMap<>();

        collect("product", productQuery, productThreshold, limit, byId, bestScoreById);
        collect("title", productQuery, titleThreshold, limit, byId, bestScoreById);

        return byId.values().stream()
                .sorted((a, b) -> Double.compare(bestScoreById.get(b.getId()), bestScoreById.get(a.getId())))
                .limit(limit)
                .toList();
    }

    /** {@code column} is always one of the two hardcoded literals above — never request input —
     *  so interpolating it directly into the SQL text is safe. */
    private void collect(String column, String query, double threshold, int limit,
            Map<Long, CpeDictionaryEntry> byId, Map<Long, Double> bestScoreById) {
        jdbcTemplate.execute("SET LOCAL pg_trgm.similarity_threshold = " + threshold);
        // DISTINCT ON (vendor, product) before applying the limit: the dictionary holds one row
        // per catalogued version, and 72.7% of the real NVD dictionary's 1.8M rows are such
        // version duplicates (TeamViewer alone has dozens). All rows of one product share the same
        // product slug and therefore score identically, so without de-duplicating first a single
        // popular product can occupy the entire candidate window and crowd out every genuinely
        // different product the caller needed to choose between. The de-duplication has to happen
        // inside a subquery because DISTINCT ON requires ORDER BY to lead with its own columns,
        // which is not the ordering we want the limit applied to.
        //
        // target_sw_values (senior review, job 36 root-cause / REVISE item 4): the set of distinct
        // target_sw values (CPE segment 11, 1-indexed) across every row sharing a (vendor, product)
        // pair — needed by Stage1IdentificationService's target_sw gate/ranking preference, which
        // needs the *set* for the pair, not just whichever single row DISTINCT ON happens to keep.
        // A window function, not a join/CTE over the whole table: PostgreSQL applies window
        // functions after the WHERE clause, so this aggregates only over the rows the trigram `%`
        // filter already matched (a small, index-accelerated result set), never a full 1.8M-row
        // scan — folded into this same query rather than a separate per-(vendor,product) follow-up
        // query, which would have no btree index to run on at all (measured and rejected).
        // No DISTINCT inside the array_agg: PostgreSQL rejects DISTINCT in a window-function
        // aggregate ("DISTINCT is not implemented for window functions"). Per-(vendor,product)
        // groups are small (a few hundred rows at most per the comment above), so the array just
        // carries duplicate target_sw values across; toStringSet() below dedupes on the Java side.
        //
        // regexp_replace(cpe_string, '\\:', '', 'g') (senior review, job 37 root-cause): a plain
        // split_part mis-indexes every segment from the first escaped colon onward — CPE 2.3
        // backslash-escapes reserved characters within a segment, and a real dictionary row exercises
        // exactly that (Perl's "HTTP::Session" module: cpe:2.3:a:ktat:http\:\:session:0.01_01:*:*:*:
        // *:perl:*:*). Neutralizing "\:" pairs before splitting realigns every later segment's index
        // without a second round-trip query (an explicit constraint from the round-2 review) — the
        // product/vendor/title columns are untouched, only this target_sw extraction is affected, and
        // it's still folded into the same window-function query. Confirmed via EXPLAIN ANALYZE that
        // this leaves the query plan (bitmap index scan -> window agg -> incremental sort) unchanged.
        String sql = "SELECT * FROM ("
                + "SELECT DISTINCT ON (vendor, product) id, cpe_string, title, vendor, product, last_synced_at, "
                + "similarity(" + column + ", ?) AS score, "
                + "array_agg(split_part(regexp_replace(cpe_string, '\\\\:', '', 'g'), ':', 11)) "
                + "OVER (PARTITION BY vendor, product) AS target_sw_values "
                + "FROM cpe_dictionary WHERE " + column + " % ? "
                + "ORDER BY vendor, product, score DESC"
                + ") deduped ORDER BY score DESC LIMIT ?";
        jdbcTemplate.query(sql, rs -> {
            long id = rs.getLong("id");
            double score = rs.getDouble("score");
            if (bestScoreById.getOrDefault(id, -1.0) < score) {
                CpeDictionaryEntry entry = new CpeDictionaryEntry();
                entry.setId(id);
                entry.setCpeString(rs.getString("cpe_string"));
                entry.setTitle(rs.getString("title"));
                entry.setVendor(rs.getString("vendor"));
                entry.setProduct(rs.getString("product"));
                OffsetDateTime lastSyncedAt = rs.getObject("last_synced_at", OffsetDateTime.class);
                entry.setLastSyncedAt(lastSyncedAt);
                entry.setTargetSwValues(toStringSet(rs.getArray("target_sw_values")));
                byId.put(id, entry);
                bestScoreById.put(id, score);
            }
        }, query, query, limit);
    }

    private Set<String> toStringSet(Array sqlArray) {
        if (sqlArray == null) {
            return Set.of();
        }
        try {
            Object[] values = (Object[]) sqlArray.getArray();
            Set<String> result = new LinkedHashSet<>();
            for (Object value : values) {
                if (value != null) {
                    result.add(value.toString());
                }
            }
            return result;
        } catch (java.sql.SQLException e) {
            return Set.of();
        }
    }
}
