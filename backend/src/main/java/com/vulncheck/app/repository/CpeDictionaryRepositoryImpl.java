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
 * {@code similarity(col, query) > threshold} alone — the query shape the old {@code @Query}-annotated
 * method used — cannot use a pg_trgm GIN index at all (confirmed live via {@code EXPLAIN}: even
 * with {@code enable_seqscan} forced off, PostgreSQL has no alternative plan and falls back to a
 * full sequential scan regardless). Only the {@code %} similarity operator is index-accelerated,
 * but its threshold is a session-level setting ({@code pg_trgm.similarity_threshold}), defaulting
 * to 0.3, not a query parameter.
 *
 * <p>An earlier version of {@link #collect} raised that session threshold per call with {@code SET
 * LOCAL pg_trgm.similarity_threshold = ...}, scoped by wrapping the method in {@code @Transactional}
 * (since {@code SET LOCAL} only has effect inside a transaction block). A PR #14 review round
 * suspected this could silently no-op if a caller ever reached this repository outside a
 * transaction block (e.g. through a different thread/proxy path than the one {@code
 * @Transactional} wraps), which would leave the {@code %} pre-filter running at its 0.3 session
 * default instead of the caller's real threshold. That specific failure was never actually
 * reproduced against the dev DB — the suspected {@code SET LOCAL can only be used in transaction
 * blocks} warning did not appear in the Postgres log for a real request through this method — but
 * the concern about depending on exactly which proxying/threading path a given caller happens to go
 * through (easy to get right by accident today and silently wrong again after an unrelated
 * refactor) still stands. So {@code SET LOCAL} stays, restricting the GIN-indexed {@code %}
 * pre-filter to roughly the caller's own threshold (cheap and index-accelerated, but session-scoped
 * and therefore not fully trustworthy on its own), and {@link #collect} additionally enforces the
 * real per-call threshold with an explicit {@code AND similarity(col, ?) > ?} predicate that does
 * not depend on transaction/thread context at all. Belt and braces: {@code SET LOCAL} is the
 * performance optimization, the explicit predicate is the correctness guarantee.
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
                + "ORDER BY vendor, product, "
                // Backlog item 36 / 38: same part preference key as collect() below, and for the
                // same reason -- this DISTINCT ON has no score column to tie on at all, so without
                // this key a (vendor, product) pair with both a part=a and a part=o row is decided
                // purely by which has the lower id, discarding the other before it ever reaches
                // Stage1IdentificationService#rankCpeCandidates's own part preference (see that
                // method's javadoc) has a chance to choose between them.
                + "CASE split_part(cpe_string, ':', 3) WHEN 'a' THEN 0 WHEN 'o' THEN 1 ELSE 2 END, id"
                // id tiebreaks at both levels for the same reason as collect() below: without "id"
                // trailing the inner ORDER BY, DISTINCT ON's own representative-row choice per
                // (vendor, product) group is unspecified, and without it trailing the outer
                // "length(product) ASC" (ties are common -- many products share the same slug
                // length), which row survives the LIMIT is unspecified too. Both matter here because
                // Stage1's initialism matching ("vs code" -> visual_studio_code) reads directly off
                // whichever row this query returns.
                + ") deduped ORDER BY length(product) ASC, id LIMIT ?";
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
     *  so interpolating it directly into the SQL text is safe.
     *
     * <p>Package-private (rather than {@code private}) so {@code CpeDictionaryRepositoryImplTest} can
     * call it directly to verify the SQL-level {@code ORDER BY} on a single {@code collect()} call's
     * raw JDBC row order, independent of {@link #findFuzzyMatches}'s own Java-side stable sort. */
    void collect(String column, String query, double threshold, int limit,
            Map<Long, CpeDictionaryEntry> byId, Map<Long, Double> bestScoreById) {
        // SET LOCAL restricts the GIN-indexed "%" pre-filter below to roughly the caller's own
        // threshold instead of the 0.3 session default, because a tighter threshold lets "%" itself
        // discard more candidates before anything else runs. The magnitude of that effect depends on
        // how much the query's own trigram score distribution clusters near the session default --
        // it is not a fixed multiplier. Re-measured 2026-08-30 with EXPLAIN (ANALYZE, BUFFERS) against
        // the real dictionary, on this method's current CROSS JOIN LATERAL query shape (title column,
        // limit 40, threshold 0.6 -- CPE_TITLE_SIMILARITY_THRESHOLD): title 'Google Chrome' went from
        // 363.3ms at the 0.3 session default down to 84.5ms with SET LOCAL 0.6 (~4.3x), while title
        // 'Linux Kernel' only went from 222.9ms down to 147.0ms (~1.5x) -- Chrome's query text has few
        // enough close trigram matches that tightening the pre-filter prunes much more aggressively,
        // where Linux Kernel's more common words leave a larger candidate set at either threshold.
        // (These absolute numbers also reflect the dev DB not yet having the V31 (vendor, product)
        // index applied -- see this method's own d.vendor = t.vendor comment below -- so the LATERAL
        // half of each plan falls back to the product trigram index for that equality join; V31 would
        // change the absolute totals but not the relative SET LOCAL effect measured here, since it
        // only touches the LATERAL join, not the "%" pre-filter this comment is about.) See this
        // class's own javadoc for why the explicit "AND similarity(...) > ?" predicate further down is
        // kept alongside this rather than relied on alone.
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
        // target_sw values (CPE segment 11, 1-indexed) across the rows sharing a (vendor, product)
        // pair that also matched this call's own trigram filter — needed by
        // Stage1IdentificationService's target_sw gate/ranking preference, which needs the *set* for
        // the pair, not just whichever single row DISTINCT ON happens to keep.
        //
        // max_cataloged_major (docs/spec/task-backlog.md item 15, P2; PR #14 REVISE): a single
        // nullable scalar rather than the full per-(vendor, product) set of catalogued version
        // strings. Real (vendor, product) pairs get large — vim:vim has 15,751 distinct catalogued
        // versions, google:chrome 9,530 — and Stage1IdentificationService#versionCoverageIsPlausible
        // only ever reduces the set down to its single highest major version anyway, so shipping the
        // whole set over JDBC and re-parsing every element in Java on every ranking comparison was
        // pure waste. Computed here as max() over each row's leading digit run of the version
        // segment (CPE segment 6, 1-indexed), matching
        // Stage1IdentificationService#leadingMajorVersion's own parsing rule; capped at 9 digits so
        // the ::integer cast can never overflow regardless of what a pathological version string
        // contains. NULLIF/max collapse to SQL NULL when nothing in the partition has a numeric
        // leading run, which versionCoverageIsPlausible treats identically to "no evidence"
        // (always plausible).
        //
        // Both are re-derived via a CROSS JOIN LATERAL against the small (<= limit, currently 40)
        // row set the trigram-filtered subquery above already narrows down to, rather than as a
        // window function over that subquery: a window function is evaluated *after* the WHERE
        // <column> % ? filter, so its partition would silently only ever contain whichever rows of
        // the group happened to pass this call's own trigram filter. That's the deliberately
        // preserved gate semantics for target_sw_values (see above), but would be a real bug for
        // max_cataloged_major, which needs every catalogued version for the pair regardless of
        // whether that particular row's product/title trigram-matched the query — e.g. a (vendor,
        // product) group whose title varies a lot release to release could otherwise have some of
        // its version rows silently excluded depending on which of the two collect() calls
        // (product-column vs title-column) found it and how well each individual row's title
        // happened to match.
        //   - target_sw_values keeps an explicit FILTER reproducing this call's own trigram filter
        //     exactly — both the "%" pre-filter and the "similarity(...) > ?" predicate, mirroring
        //     the outer subquery's WHERE clause — so this PR intentionally does not change that
        //     gate's existing behavior (see docs/spec/task-backlog.md items 24/26, which reason
        //     about the current gate as-is). Without the similarity(...) predicate here too, this
        //     FILTER would fall back to the "%" operator's session-level threshold alone, which can
        //     admit a wider set than the outer query's own explicit threshold.
        //   - max_cataloged_major has no filter at all and aggregates the whole (vendor, product)
        //     partition, which is the actual bug fix.
        //
        // d.vendor = t.vendor AND d.product = t.product (not IS NOT DISTINCT FROM): a NULL vendor
        // or product would never equal itself under plain "=", dropping that row out of the LATERAL
        // aggregate entirely instead of joining back to its own outer row — verified against the
        // real dictionary that vendor/product are NULL on zero rows today, so this never actually
        // happens in practice. "=" was chosen over "IS NOT DISTINCT FROM" because it is a plain
        // btree-indexable equality that the V31 (vendor, product) index (see that migration) can
        // back directly, where "IS NOT DISTINCT FROM" cannot use a plain btree index scan the same
        // way. The "cost 8.57 vs 47147" figure from an earlier revision of this comment was written
        // before V31 had actually been applied to any real database and was never reproduced — as of
        // 2026-08-30 the dev DB still only has V30 applied (V31 has not been rolled out yet), so that
        // specific comparison remains unverified pending V31's actual rollout; re-measure with EXPLAIN
        // once V31 is applied rather than trusting the old figure.
        //
        // What has been verified against the real dictionary on this dev DB (2026-08-30, before V31):
        // product 'chrome' went from 2003.2ms on the pre-LATERAL query shape (a window function over
        // the whole trigram-filtered set, re-parsed row by row in Java) to 375.0ms on this method's
        // current CROSS JOIN LATERAL shape, ~5x faster, because the LATERAL join only re-derives
        // target_sw_values/max_cataloged_major for the <= limit rows the trigram filter already
        // narrowed down to, rather than for every trigram-filtered row up front.
        //
        // regexp_replace(d.cpe_string, '\\:', '', 'g') (senior review, job 37 root-cause): a plain
        // split_part mis-indexes every segment from the first escaped colon onward — CPE 2.3
        // backslash-escapes reserved characters within a segment, and a real dictionary row exercises
        // exactly that (Perl's "HTTP::Session" module: cpe:2.3:a:ktat:http\:\:session:0.01_01:*:*:*:
        // *:perl:*:*). Neutralizing "\:" pairs before splitting realigns every later segment's index
        // without a second round-trip query (an explicit constraint from the round-2 review) — the
        // product/vendor/title columns are untouched, only this target_sw/version extraction is
        // affected.
        String sql = "SELECT t.*, a.target_sw_values, a.max_cataloged_major FROM ("
                + "SELECT * FROM ("
                + "SELECT DISTINCT ON (vendor, product) id, cpe_string, title, vendor, product, last_synced_at, "
                + "similarity(" + column + ", ?) AS score "
                + "FROM cpe_dictionary WHERE " + column + " % ? AND similarity(" + column + ", ?) > ? "
                + "ORDER BY vendor, product, score DESC, "
                // Backlog item 36 / 38 (senior review 2026-08-30): a part preference key, inserted
                // ahead of the "id" tiebreak below -- without it, a (vendor, product) pair that
                // happens to have a part=a (application) row and a part=o (operating system) row
                // tied on score is a coin flip decided purely by which one has the lower id, with no
                // regard for which part Stage1IdentificationService actually prefers. Confirmed live
                // against the real dictionary: cisco:ios_xe has a title-similarity-1.0 row for both
                // part=o (id 83468) and part=a (id 875652), so whichever of the two happened to sort
                // first here was the only one DISTINCT ON ever kept -- the other was discarded before
                // Stage1IdentificationService#rankCpeCandidates's own part=a-preferred/part=o-fallback
                // logic (see that method's javadoc) ever got a chance to choose between them, because
                // DISTINCT ON never let both into the pool at once. This CASE realigns the
                // representative-row choice with that same preference (part=a first, part=o second,
                // anything else last) so the two layers of part handling agree instead of the outer
                // one silently overriding the inner one. split_part (not the escape-aware
                // regexp_replace variant used for target_sw/version below) is safe here because the
                // part segment (index 3, 1-indexed) always precedes the escapable vendor segment
                // (index 4) in a CPE 2.3 URI, so it can never itself contain an escaped colon.
                + "CASE split_part(cpe_string, ':', 3) WHEN 'a' THEN 0 WHEN 'o' THEN 1 ELSE 2 END, id"
                // Determinism here needs id as a tiebreaker at *both* levels, not just the outer one:
                // DISTINCT ON (vendor, product) itself picks whichever row sorts first within each
                // group under the inner ORDER BY, so without "id" trailing "score DESC" there, the
                // representative row DISTINCT ON keeps for a group with tied scores is itself
                // unspecified -- confirmed live against the real dictionary, where google:chrome's
                // representative row id varied between 30447 and 443462 across otherwise-identical
                // query plans. The outer "score DESC, id" then breaks ties *between* the (already
                // deterministic) representative rows of different groups, so which rows land in the
                // top-`limit` candidate pool no longer depends on Postgres's otherwise-unspecified
                // return order for equal ORDER BY keys (docs/spec/task-backlog.md item 33) -- both
                // tiebreaks together are what make this reproducible for the golden benchmark.
                + ") deduped ORDER BY score DESC, id LIMIT ?"
                + ") t "
                + "CROSS JOIN LATERAL ("
                + "SELECT array_agg(split_part(regexp_replace(d.cpe_string, '\\\\:', '', 'g'), ':', 11)) "
                + "FILTER (WHERE d." + column + " % ? AND similarity(d." + column + ", ?) > ?) AS target_sw_values, "
                + "max((NULLIF(substring(split_part(regexp_replace(d.cpe_string, '\\\\:', '', 'g'), ':', 6) "
                + "from '^[0-9]{1,9}'), ''))::integer) AS max_cataloged_major "
                + "FROM cpe_dictionary d "
                + "WHERE d.vendor = t.vendor AND d.product = t.product"
                + ") a "
                // The outermost ORDER BY also carries an id tiebreak for the same reason as the
                // inner two levels above (deduped ORDER BY and the DISTINCT ON's own inner ORDER
                // BY): ties on t.score alone would otherwise leave the return order unspecified.
                // On this query's current shape, the planner picks a Nested Loop for the CROSS
                // JOIN LATERAL, which walks its outer side (t) in whatever order it was produced
                // in rather than re-sorting it — confirmed no Sort node appears for this outer
                // ORDER BY in the query plan — so in practice this outer ORDER BY is eliminated by
                // the planner entirely, because the Nested Loop already preserves the inner
                // "deduped ORDER BY score DESC, id LIMIT ?" subquery's order as-is. But that is an
                // artifact of today's plan shape, not something this ORDER BY clause can rely on:
                // if a future change to this query (e.g. swapping the LATERAL join for something
                // that forces materialization/re-sorting of t) makes the planner actually realize
                // this outer ORDER BY as a real Sort node, PostgreSQL's sort is not stable, so
                // without "t.id" here the tied t.score rows would be shuffled again on every plan
                // change.
                + "ORDER BY t.score DESC, t.id";
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
                entry.setMaxCatalogedMajor(rs.getObject("max_cataloged_major", Integer.class));
                byId.put(id, entry);
                bestScoreById.put(id, score);
            }
        }, query, query, query, threshold, limit, query, query, threshold);
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
