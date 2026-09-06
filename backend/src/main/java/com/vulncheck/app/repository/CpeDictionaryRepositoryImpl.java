package com.vulncheck.app.repository;

import com.vulncheck.app.entity.CpeDictionaryEntry;
import java.sql.Array;
import java.time.OffsetDateTime;
import java.util.ArrayList;
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
                -- senior-reviewer REVISE (PR #75): only rewrite the row (and its two GIN indexes)
                -- when content actually changed. Without this predicate, ON CONFLICT DO UPDATE
                -- unconditionally rewrites all ~1.8M rows every full sync even when NVD reports the
                -- exact same title/vendor/product, generating a full new heap version + index entry
                -- (including both GIN indexes) plus an equal amount of dead tuple per week -- a bad
                -- fit for the 10GB DB size cap this mirror runs under.
                -- Side effect: last_synced_at now means "last time this row's content changed", not
                -- "last time NVD reported this row" -- confirmed unread anywhere in the app (not even
                -- the admin screen) before making this change, so no caller-visible behavior changes.
                WHERE cpe_dictionary.title IS DISTINCT FROM EXCLUDED.title
                   OR cpe_dictionary.vendor IS DISTINCT FROM EXCLUDED.vendor
                   OR cpe_dictionary.product IS DISTINCT FROM EXCLUDED.product
                """,
                entries.stream()
                        .map(e -> new Object[] {e.getCpeString(), e.getTitle(), e.getVendor(), e.getProduct()})
                        .toList());
        // Note: batch.size() upstream (NvdCpeSyncService#sync) still counts every row *processed*
        // in this batch as "upserted", not just the rows this predicate actually wrote -- that
        // counter's meaning ("how many dictionary entries did this sync pass over") is unchanged by
        // this fix, which only affects whether a given row's UPDATE branch is a no-op.
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
                // id tiebreaks at both levels for the same reason as collect() below: without "id"
                // trailing the inner ORDER BY, DISTINCT ON's own representative-row choice per
                // (vendor, product) group is unspecified, and without it trailing the outer
                // "length(product) ASC" (ties are common -- many products share the same slug
                // length), which row survives the LIMIT is unspecified too. Both matter here because
                // Stage1's initialism matching ("vs code" -> visual_studio_code) reads directly off
                // whichever row this query returns.
                + "ORDER BY vendor, product, id"
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

    /**
     * Item 302 safety net: {@link CpeDictionaryRepositoryCustom#findByVendorProductPairs}'s own
     * caller ({@code Stage1IdentificationService#exactVendorProductMatches}) already caps generated pairs at 64
     * (8 vendor tokens x 8 product tokens, both taken from {@code tokenize()}'s own bounded output —
     * see that method's javadoc for the full worst-case-explosion rationale), but this repository
     * method has no way to know a future caller will respect that, and a {@code product} column being
     * {@code VARCHAR(255)} means a naive caller could otherwise reach tens of thousands of bind
     * parameters in one query. Silently truncating (rather than throwing) matches this fallback's own
     * "best effort, never block the item" spirit — same reasoning as {@code
     * MAX_NAME_VARIANT_QUERIES_PER_ITEM}'s cap in {@code Stage1IdentificationService}.
     */
    private static final int MAX_VENDOR_PRODUCT_PAIRS = 64;

    @Override
    @Transactional(readOnly = true)
    public List<CpeDictionaryEntry> findByVendorProductPairs(
            List<CpeDictionaryRepositoryCustom.VendorProductPair> pairs, int limit) {
        if (pairs.isEmpty()) {
            return List.of();
        }
        List<CpeDictionaryRepositoryCustom.VendorProductPair> capped =
                pairs.size() > MAX_VENDOR_PRODUCT_PAIRS ? pairs.subList(0, MAX_VENDOR_PRODUCT_PAIRS) : pairs;

        // Row-value IN list, e.g. "(vendor, product) IN ((?, ?), (?, ?))" — every value is a JDBC
        // bind parameter, never string-interpolated (the pair's vendor/product text ultimately comes
        // from item CSV data, so this must never be built via string concatenation of the values
        // themselves). Postgres can rewrite a row-value IN list with a fixed set of tuples into an OR
        // of per-tuple equalities, each of which can use the (vendor, product) btree index (V31) via
        // a BitmapOr — the same index this fallback exists to exploit.
        StringBuilder valuesList = new StringBuilder();
        List<Object> params = new ArrayList<>();
        for (int i = 0; i < capped.size(); i++) {
            if (i > 0) {
                valuesList.append(", ");
            }
            valuesList.append("(?, ?)");
            params.add(capped.get(i).vendor());
            params.add(capped.get(i).product());
        }

        // Reuses collect()'s own CROSS JOIN LATERAL shape for target_sw_values/max_cataloged_major/
        // cataloged_row_count via the shared outlierGuardedAggregateSql helper (see that method's own
        // javadoc for why this is factored out, and collect()'s own extensive comment for what each
        // column means and why the LATERAL join, rather than a window function, is required for
        // max_cataloged_major/cataloged_row_count's whole-partition semantics, and for the rule A/B
        // outlier guard itself, backlog item 346) — but target_sw_values here has NO
        // "FILTER (WHERE d.<column> % ? AND similarity(...) > ?)" clause, unlike collect()'s version.
        // collect()'s FILTER deliberately preserves the existing trigram-gate semantics (target_sw_
        // values there is scoped to only the rows that ALSO matched that call's own similarity
        // filter). There is no similarity filter at all on this exact-match path — every row sharing
        // the (vendor, product) pair is an equally valid piece of evidence for what target_sw values
        // exist for that pair — so this aggregates unconditionally over the whole partition, exactly
        // like max_cataloged_major/cataloged_row_count already do. Carrying collect()'s FILTER over
        // unchanged here would silently and incorrectly re-introduce a "must also similarity-match"
        // requirement that has no meaning on an exact-match query with no query string to score
        // against in the first place — passing the literal SQL "true" as outlierGuardedAggregateSql's
        // own matchedExpression parameter (rather than collect()'s real trigram predicate) is what
        // keeps target_sw_values here unconditional, exactly like the pre-item-346 version did.
        String sql = "SELECT t.*, a.target_sw_values, a.max_cataloged_major, a.cataloged_row_count FROM ("
                + "SELECT DISTINCT ON (vendor, product) id, cpe_string, title, vendor, product, last_synced_at "
                + "FROM cpe_dictionary WHERE (vendor, product) IN (" + valuesList + ") "
                // Same determinism reasoning as findByLeadingInitialismMatch's own inner ORDER BY:
                // without "id" trailing "vendor, product", DISTINCT ON's representative-row choice per
                // pair is unspecified.
                + "ORDER BY vendor, product, id"
                + ") t "
                + "CROSS JOIN LATERAL ("
                + outlierGuardedAggregateSql("true")
                + ") a "
                // Outer ORDER BY id: same defensive determinism reasoning as collect()'s own outer
                // ORDER BY (see that method's comment) — no score column exists on this exact-match
                // path to order by, so id is the only ordering key available, kept purely so the
                // returned row order for tied/duplicate pairs is reproducible rather than plan-shape-
                // dependent.
                + "ORDER BY t.id LIMIT ?";
        params.add(limit);

        List<CpeDictionaryEntry> results = new ArrayList<>();
        jdbcTemplate.query(sql, rs -> {
            CpeDictionaryEntry entry = new CpeDictionaryEntry();
            entry.setId(rs.getLong("id"));
            entry.setCpeString(rs.getString("cpe_string"));
            entry.setTitle(rs.getString("title"));
            entry.setVendor(rs.getString("vendor"));
            entry.setProduct(rs.getString("product"));
            entry.setLastSyncedAt(rs.getObject("last_synced_at", OffsetDateTime.class));
            entry.setTargetSwValues(toStringSet(rs.getArray("target_sw_values")));
            entry.setMaxCatalogedMajor(rs.getObject("max_cataloged_major", Integer.class));
            entry.setCatalogedRowCount(rs.getObject("cataloged_row_count", Integer.class));
            results.add(entry);
        }, params.toArray());
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
        // pure waste. Each row's own leading digit run of the version segment (CPE segment 6,
        // 1-indexed) is parsed exactly like Stage1IdentificationService#leadingMajorVersion's own
        // parsing rule; capped at 9 digits so no ::integer cast below can ever overflow regardless of
        // what a pathological version string contains.
        //
        // Backlog item 346 (senior review 2026-09-05): this is the *credible* highest cataloged
        // major, not the plain max() over every row in the partition — a single broken NVD version
        // string can otherwise inflate the whole (vendor, product) pair's value forever (real
        // example: oracle:vm_virtualbox's max() was 71, from one row's "71.6" among 270 catalogued
        // versions — a typo, not a real major release) and permanently push
        // Stage1IdentificationService#versionCoverageRank to COVERS(0) for that pair regardless of
        // the item's actual version. The outlier-guard mechanics (rule A/B), the measured effect on
        // the real dictionary, and the two rejected alternatives are all documented on {@link
        // #outlierGuardedAggregateSql} itself, which both this method and {@link
        // #findByVendorProductPairs} call to build this LATERAL body — see that method's own javadoc
        // rather than duplicating it here (REVISE on PR #257: the two callers' LATERAL bodies had
        // drifted apart once before when this was inline SQL copied by hand instead of a shared
        // method).
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
        // cataloged_row_count (docs/spec/task-backlog.md item 89, K3 ranking tie-break): a plain
        // count(*) added to the same unfiltered LATERAL aggregate as max_cataloged_major (same
        // partition, same "whole pair regardless of this call's own trigram filter" reasoning) — one
        // extra column on an aggregate that already scans the partition, not an extra query/round
        // trip. Stage1IdentificationService#rankCpeCandidates uses it, descending, as its final K3
        // tie-break (e.g. getgreenshot:greenshot's 80 catalogued rows vs. greenshot:greenshot's 1).
        //
        // d.vendor = t.vendor AND d.product = t.product (not IS NOT DISTINCT FROM): a NULL vendor
        // or product would never equal itself under plain "=", dropping that row out of the LATERAL
        // aggregate entirely instead of joining back to its own outer row — verified against the
        // real dictionary that vendor/product are NULL on zero rows today, so this never actually
        // happens in practice. "=" was chosen over "IS NOT DISTINCT FROM" because it is a plain
        // btree-indexable equality that the V31 (vendor, product) index (idx_cpe_dictionary_vendor_
        // product, see that migration) can back directly, where "IS NOT DISTINCT FROM" cannot use a
        // plain btree index scan the same way. The "cost 8.57 vs 47147" figure from an earlier
        // revision of this comment was written before V31 had actually been applied to any real
        // database and was never reproduced — V31 is applied on this dev DB as of 2026-09-06
        // (confirmed via \d cpe_dictionary), and the LATERAL join for both 'chrome' and 'vim' below
        // does use a Bitmap Index Scan on idx_cpe_dictionary_vendor_product (see the item 346 EXPLAIN
        // (ANALYZE, BUFFERS) figures further down), so the index itself is doing its job; the specific
        // "cost 8.57 vs 47147" equality-operator comparison was still not independently re-verified.
        //
        // What has been verified against the real dictionary on this dev DB (2026-08-30, before V31):
        // product 'chrome' went from 2003.2ms on the pre-LATERAL query shape (a window function over
        // the whole trigram-filtered set, re-parsed row by row in Java) to 375.0ms on this method's
        // current CROSS JOIN LATERAL shape, ~5x faster, because the LATERAL join only re-derives
        // target_sw_values/max_cataloged_major for the <= limit rows the trigram filter already
        // narrowed down to, rather than for every trigram-filtered row up front.
        //
        // Backlog item 346's own EXPLAIN (ANALYZE, BUFFERS), measured directly against this LATERAL
        // subquery in isolation (not the whole collect() call) on this dev DB with a fully warm
        // buffer cache (repeated back-to-back to eliminate first-run disk read noise), 2026-09-06,
        // before vs. after the rule A/B outlier guard below: google:chrome (9,558 rows) 14.2ms ->
        // 17.6ms, vim:vim (15,751 rows, the largest partition) 19.8ms -> 26.1ms. Both partitions
        // switch from a plain Aggregate to an Aggregate over an explicit Sort (needed by
        // percentile_disc/count(DISTINCT major)), which accounts for essentially all of the added
        // time -- still comfortably sub-30ms and negligible next to the <= limit (40) LATERAL
        // invocations any one collect() call makes.
        //
        // regexp_replace(d.cpe_string, '\\:', '', 'g') (senior review, job 37 root-cause): a plain
        // split_part mis-indexes every segment from the first escaped colon onward — CPE 2.3
        // backslash-escapes reserved characters within a segment, and a real dictionary row exercises
        // exactly that (Perl's "HTTP::Session" module: cpe:2.3:a:ktat:http\:\:session:0.01_01:*:*:*:
        // *:perl:*:*). Neutralizing "\:" pairs before splitting realigns every later segment's index
        // without a second round-trip query (an explicit constraint from the round-2 review) — the
        // product/vendor/title columns are untouched, only this target_sw/version extraction is
        // affected.
        String sql = "SELECT t.*, a.target_sw_values, a.max_cataloged_major, a.cataloged_row_count FROM ("
                + "SELECT * FROM ("
                + "SELECT DISTINCT ON (vendor, product) id, cpe_string, title, vendor, product, last_synced_at, "
                + "similarity(" + column + ", ?) AS score "
                + "FROM cpe_dictionary WHERE " + column + " % ? AND similarity(" + column + ", ?) > ? "
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
                + "ORDER BY vendor, product, score DESC, id"
                + ") deduped ORDER BY score DESC, id LIMIT ?"
                + ") t "
                + "CROSS JOIN LATERAL ("
                + outlierGuardedAggregateSql(
                        "d." + column + " % ? AND similarity(d." + column + ", ?) > ?")
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
                entry.setCatalogedRowCount(rs.getObject("cataloged_row_count", Integer.class));
                byId.put(id, entry);
                bestScoreById.put(id, score);
            }
        }, query, query, query, threshold, limit, query, query, threshold);
    }

    /**
     * Backlog item 346 REVISE (peer review on PR #257 caught {@link #findByVendorProductPairs}'s own
     * LATERAL aggregate carrying a hand-copied, unguarded {@code max()} that had silently drifted out
     * of sync with {@link #collect}'s outlier-guarded version): the body of the {@code CROSS JOIN
     * LATERAL (...) a} block both {@link #collect} and {@link #findByVendorProductPairs} use to
     * compute {@code target_sw_values}/{@code max_cataloged_major}/{@code cataloged_row_count} for a
     * (vendor, product) partition, factored out so there is exactly one copy of the rule A/B outlier
     * guard rather than two that can independently drift. Callers supply only {@code
     * matchedExpression} — the boolean SQL expression {@code target_sw_values}'s own {@code FILTER
     * (WHERE ...)} is scoped to — because that is the one piece of this LATERAL body that legitimately
     * differs between the two callers: {@link #collect} passes its real trigram-match predicate
     * ({@code "d.<column> % ? AND similarity(d.<column>, ?) > ?"}, preserving the existing gate
     * semantics — {@code target_sw_values} there is scoped to only the rows that also matched that
     * call's own similarity filter), while {@link #findByVendorProductPairs} has no similarity filter
     * at all on its exact-match path (every row sharing the pair is equally valid target_sw evidence)
     * and passes the SQL literal {@code "true"} instead, aggregating {@code target_sw_values}
     * unconditionally over the whole partition. Every caller must reference the same outer alias
     * {@code t} (with {@code t.vendor}/{@code t.product} columns) for the {@code WHERE d.vendor =
     * t.vendor AND d.product = t.product} correlation below to resolve.
     *
     * <p>The three layers below are unchanged from this method's own history before being extracted
     * (originally inline in {@link #collect}):
     * <ul>
     *   <li><b>Layer 1 ({@code per_row}, innermost):</b> one row per cataloged row in the (vendor,
     *   product) partition — {@code target_sw} (CPE segment 11, 1-indexed) and {@code major} (the
     *   leading digit run of CPE segment 6, 1-indexed, matching {@code
     *   Stage1IdentificationService#leadingMajorVersion}'s own parsing rule and capped at 9 digits so
     *   no {@code ::integer} cast downstream can ever overflow) parsed exactly as before {@code
     *   max_cataloged_major} existed at all, plus {@code matched} evaluating the caller-supplied
     *   {@code matchedExpression}.
     *   <li><b>Layer 2 ({@code agg}):</b> {@code target_sw_values} (unfiltered pre-item-346, now
     *   {@code FILTER (WHERE matched)}) and {@code cataloged_row_count} unchanged in meaning from
     *   before, plus the whole-partition ("_all") and sub-1000-major-only ("_narrow") statistics rule
     *   A/B (layer 3 below) choose between: {@code rows_all}/{@code rows_wide}/{@code rows_narrow}
     *   partition the row count by whether {@code major >= 1000} (a genuine 4+-digit versioning
     *   scheme vs. a date-formatted version misparsed as one), {@code max_all}/{@code max_narrow} and
     *   {@code dist_all}/{@code dist_narrow} the same way, {@code p99_all}/{@code p99_narrow} the 99th
     *   percentile major each side would use if rule B fires. {@code count(DISTINCT major)} looks
     *   redundant next to {@code max()}/{@code percentile_disc()} but is kept because removing it is a
     *   measured regression: on {@code vim:vim} (the largest partition, 15,751 rows), this aggregate's
     *   own {@code EXPLAIN (ANALYZE, BUFFERS)} execution time went from 19ms to 108ms without it —
     *   with {@code count(DISTINCT major)} present, the planner sorts the partition once and shares
     *   that sort between the ordered-set aggregates ({@code percentile_disc}) and the distinct count;
     *   without it, the distinct count forces its own separate hashed pass instead. {@code
     *   percentile_disc(0.99)} ignores NULL inputs on its own — no {@code NULLS LAST}/{@code FIRST} or
     *   extra filtering is needed for a row with no parseable major version to simply not participate
     *   in either percentile.
     *   <li><b>Layer 2b ({@code credible}):</b> rule A — split the partition into "major &lt; 1000"
     *   and "major &gt;= 1000" rows; when the &gt;=1000 rows are less than 10% of all rows that have a
     *   parseable major AND at least one &lt;1000 row exists, the &gt;=1000 rows are dropped from
     *   consideration entirely (a real 4+-digit major version scheme, e.g. a genuine year-based
     *   versioning product, would not be a small minority next to a completely different,
     *   3-digit-or-fewer scheme in the same partition) — named {@code credible_*} columns so layer 3's
     *   rule B, below, reads uniformly regardless of which side rule A picked.
     *   <li><b>Layer 3 (outermost {@code SELECT}):</b> rule B — applied on whichever set rule A left
     *   as credible, when that set has at least 20 rows, at least 3 distinct majors, a 99th-percentile
     *   major of at least 4, and the max is more than 4x that 99th percentile, the max is replaced by
     *   the 99th percentile instead (a lone outlier far beyond everything else the pair has ever
     *   catalogued, with no other row anywhere near it). {@code credible_max}/{@code credible_p99} are
     *   compared as {@code bigint} (not the {@code ::integer} they're stored as): {@code 4 *
     *   credible_p99} can exceed {@code Integer.MAX_VALUE} for a pathological 9-digit parsed major,
     *   which would otherwise raise a runtime "integer out of range" error instead of just comparing
     *   false. {@code credible_max IS NULL} collapses the whole {@code CASE} to {@code NULL} the same
     *   way the pre-item-346 plain {@code max()} did when nothing in the partition had a numeric
     *   leading run, which {@code Stage1IdentificationService#versionCoverageIsPlausible} treats
     *   identically to "no evidence" (always plausible).
     * </ul>
     *
     * <p>Measured against the real dictionary (read-only, 2026-09-05, via {@link #collect}'s own
     * call sites before this REVISE): of 66,228 (vendor, product) pairs with at least one parseable
     * major, rule A fires for 204 (all of which change value, since any &gt;=1000 row is always larger
     * than every &lt;1000 row and so always was the pre-fix max) and rule B fires for 14 (12 without
     * rule A, 2 more on top of rule A's own narrowed set) — 216 pairs total change value, 0.33% of all
     * pairs. {@code oracle:vm_virtualbox} goes from 71 to 7 (still COVERS item version 7.0.14, same as
     * before — see backlog items 308/345), and {@code google:android} goes from 2024 to 15 (Android
     * 15, the real answer — backlog item 289/348). Legitimate large majors were confirmed to survive
     * unchanged, e.g. {@code postgresql:postgresql_jdbc_driver} (42), GNOME {@code nautilus} (42),
     * Signal (6), {@code onlyoffice:google_translate} (99) — none of these have the "buried under
     * everything else" shape rule B looks for. A rejected alternative was unconditionally dropping the
     * single highest-major row per partition: NVD only catalogs the versions a CVE actually named, so
     * a (vendor, product) pair whose latest major has exactly one row (a real, ordinary case — see
     * backlog item 89's own {@code pdf-xchange:pdf-xchange_editor} example) would always lose its true
     * latest major under that rule. A rejected alternative was a plain percentile alone (no rule A
     * first): partition sizes here range from 1 row to {@code vim:vim}'s 15,751, four orders of
     * magnitude apart, so a single percentile rule is either meaningless on tiny partitions or wrongly
     * trims a legitimate latest major off large ones.
     */
    private static String outlierGuardedAggregateSql(String matchedExpression) {
        return "WITH per_row AS ("
                + "SELECT split_part(regexp_replace(d.cpe_string, '\\\\:', '', 'g'), ':', 11) AS target_sw, "
                + "(" + matchedExpression + ") AS matched, "
                + "(NULLIF(substring(split_part(regexp_replace(d.cpe_string, '\\\\:', '', 'g'), ':', 6) "
                + "from '^[0-9]{1,9}'), ''))::integer AS major "
                + "FROM cpe_dictionary d "
                + "WHERE d.vendor = t.vendor AND d.product = t.product"
                + "), "
                + "agg AS ("
                + "SELECT array_agg(target_sw) FILTER (WHERE matched) AS target_sw_values, "
                + "count(*)::integer AS cataloged_row_count, "
                + "count(major) AS rows_all, "
                + "count(*) FILTER (WHERE major >= 1000) AS rows_wide, "
                + "count(major) FILTER (WHERE major < 1000) AS rows_narrow, "
                + "max(major) AS max_all, "
                + "max(major) FILTER (WHERE major < 1000) AS max_narrow, "
                + "count(DISTINCT major) AS dist_all, "
                + "count(DISTINCT major) FILTER (WHERE major < 1000) AS dist_narrow, "
                + "percentile_disc(0.99) WITHIN GROUP (ORDER BY major) AS p99_all, "
                + "percentile_disc(0.99) WITHIN GROUP (ORDER BY major) FILTER (WHERE major < 1000) AS p99_narrow "
                + "FROM per_row"
                + "), "
                + "credible AS ("
                + "SELECT target_sw_values, cataloged_row_count, "
                + "CASE WHEN rows_wide > 0 AND rows_wide * 10 < rows_all AND rows_narrow > 0 "
                + "THEN max_narrow ELSE max_all END AS credible_max, "
                + "CASE WHEN rows_wide > 0 AND rows_wide * 10 < rows_all AND rows_narrow > 0 "
                + "THEN p99_narrow ELSE p99_all END AS credible_p99, "
                + "CASE WHEN rows_wide > 0 AND rows_wide * 10 < rows_all AND rows_narrow > 0 "
                + "THEN rows_narrow ELSE rows_all END AS credible_rows, "
                + "CASE WHEN rows_wide > 0 AND rows_wide * 10 < rows_all AND rows_narrow > 0 "
                + "THEN dist_narrow ELSE dist_all END AS credible_distinct "
                + "FROM agg"
                + ") "
                + "SELECT target_sw_values, cataloged_row_count, "
                + "CASE "
                + "WHEN credible_max IS NULL THEN NULL "
                + "WHEN credible_rows >= 20 AND credible_distinct >= 3 AND credible_p99 >= 4 "
                + "AND credible_max::bigint > 4::bigint * credible_p99::bigint "
                + "THEN credible_p99 "
                + "ELSE credible_max "
                + "END AS max_cataloged_major "
                + "FROM credible";
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
