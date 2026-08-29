package com.vulncheck.app.repository;

import static org.assertj.core.api.Assertions.assertThat;

import com.vulncheck.app.entity.CpeDictionaryEntry;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Exercises {@link CpeDictionaryRepositoryImpl#findFuzzyMatches} directly against a real Postgres
 * instance (trgm scoring and the (vendor, product) LATERAL join can't be meaningfully verified
 * against a mock).
 *
 * <p>Covers docs/spec/task-backlog.md item 27: the pg_trgm session default is 0.3, so a title-only
 * match scoring in the [0.3, 0.6) band is exactly the case a session-level {@code SET LOCAL
 * pg_trgm.similarity_threshold = ...} alone would be fragile against if it ever silently failed to
 * apply on some caller's transaction/thread path — {@link CpeDictionaryRepositoryImpl}'s own class
 * javadoc has the full history of why an explicit {@code similarity(...) > ?} predicate is kept
 * alongside {@code SET LOCAL} rather than relying on either alone. {@link #collect} enforces the
 * threshold with that explicit predicate, which cannot silently no-op the way a session-level
 * setting could.
 *
 * <p>Also covers docs/spec/task-backlog.md item 15, P2 (PR #14 REVISE): {@code max_cataloged_major}
 * must reflect every row sharing a (vendor, product) pair, even rows this particular call's own
 * trigram filter didn't match, while {@code target_sw_values} must keep aggregating only the rows
 * that did match (the pre-existing, deliberately-unchanged gate behavior — see {@code
 * CpeDictionaryRepositoryImpl#collect}'s own comment). Also implicitly covers the {@code collect()}
 * bind-parameter ordering the CROSS JOIN LATERAL rewrite introduced: a misaligned bind would
 * surface here as a JDBC type-mismatch exception or the wrong rows/values below, not just a
 * compile-time issue.
 *
 * <p>{@code @DataJpaTest} wraps each test in a transaction rolled back afterward, so nothing
 * written here is persisted past the test run.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class CpeDictionaryRepositoryImplTest {

    @Autowired
    private CpeDictionaryRepository cpeDictionaryRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private static CpeDictionaryEntry entry(String cpeString, String title, String vendor, String product) {
        CpeDictionaryEntry entry = new CpeDictionaryEntry();
        entry.setCpeString(cpeString);
        entry.setTitle(title);
        entry.setVendor(vendor);
        entry.setProduct(product);
        return entry;
    }

    private void insert(String cpeString, String title, String vendor, String product) {
        CpeDictionaryEntry entry = new CpeDictionaryEntry();
        entry.setCpeString(cpeString);
        entry.setTitle(title);
        entry.setVendor(vendor);
        entry.setProduct(product);
        entry.setLastSyncedAt(OffsetDateTime.now());
        cpeDictionaryRepository.save(entry);
    }

    @Test
    void findFuzzyMatchesExcludesATitleOnlyMatchScoringBelowTheTitleThreshold() {
        // Same shape as the false positive documented in Stage1IdentificationService's own
        // CPE_TITLE_SIMILARITY_THRESHOLD javadoc: a short query sharing only a vendor word with an
        // unrelated product's full title scores in the [0.3, 0.6) band on the title column, while
        // scoring near-zero on the normalized single-word product slug ("nuget") so the product-slug
        // collect() pass can't accidentally smuggle it back in.
        cpeDictionaryRepository.upsertBatch(List.of(
                entry("cpe:2.3:a:microsoft:nuget:4.3.1:*:*:*:*:*:*:*", "Microsoft NuGet 4.3.1",
                        "microsoft", "nuget")));

        String query = "Microsoft Edge";
        Double titleScore = jdbcTemplate.queryForObject(
                "SELECT similarity(title, ?) FROM cpe_dictionary WHERE product = 'nuget'",
                Double.class, query);
        // Sanity-check the fixture actually reproduces the bug's [0.3, 0.6) band; if pg_trgm's
        // scoring ever shifts enough to break this assumption, this fails loudly here rather than
        // the assertion below passing for the wrong reason.
        assertThat(titleScore).isGreaterThan(0.3).isLessThan(0.6);

        List<CpeDictionaryEntry> results = cpeDictionaryRepository.findFuzzyMatches(query, 0.3, 0.6, 10);

        assertThat(results).noneMatch(e -> "nuget".equals(e.getProduct()));
    }

    @Test
    void findFuzzyMatchesStillReturnsATitleMatchScoringAtOrAboveTheTitleThreshold() {
        cpeDictionaryRepository.upsertBatch(List.of(
                entry("cpe:2.3:a:microsoft:nuget:4.3.1:*:*:*:*:*:*:*", "Microsoft NuGet 4.3.1",
                        "microsoft", "nuget")));

        List<CpeDictionaryEntry> results = cpeDictionaryRepository.findFuzzyMatches(
                "Microsoft NuGet 4.3.1", 0.3, 0.6, 10);

        assertThat(results).anyMatch(e -> "nuget".equals(e.getProduct()));
    }

    /**
     * Two rows share one (vendor, product) pair but have very different titles, and the query text
     * ({@code "AlphaMarkerXQ42 Suite"}) is deliberately unrelated to the shared {@code product}
     * column value ({@code "zzzrevise14product"}, similarity measured at 0.0), so the product-column
     * collect() call never matches either row — isolating the title-column call, whose row1 title
     * contains the query near-verbatim (similarity ~0.58) while row2's is unrelated (similarity
     * ~0.01), both comfortably on either side of the 0.3 threshold used here. Only row1 survives
     * that trigram filter, which used to also gate cataloged_versions/max_cataloged_major before
     * this fix. (Similarity scores measured directly against this test's real Postgres instance
     * before picking thresholds — pg_trgm's {@code %} operator is {@code similarity >= threshold},
     * not strictly greater than, so an "unreachable" threshold isn't a reliable way to force zero
     * matches when a value can legitimately score a perfect 1.0.)
     */
    @Test
    void maxCatalogedMajorCoversWholeVendorProductPartitionEvenWhenTrigramFilterExcludesSomeRows() {
        insert(
                "cpe:2.3:a:zzzrevise14vendor:zzzrevise14product:1.0:*:*:*:*:windows:*:*",
                "AlphaMarkerXQ42 Suite Desktop Edition",
                "zzzrevise14vendor",
                "zzzrevise14product");
        insert(
                "cpe:2.3:a:zzzrevise14vendor:zzzrevise14product:2.0:*:*:*:*:linux:*:*",
                "Totally unrelated other title words that share no trigrams",
                "zzzrevise14vendor",
                "zzzrevise14product");

        List<CpeDictionaryEntry> results = cpeDictionaryRepository.findFuzzyMatches(
                "AlphaMarkerXQ42 Suite", 0.3, 0.3, 10);

        assertThat(results).hasSize(1);
        CpeDictionaryEntry entry = results.get(0);
        assertThat(entry.getCpeString()).isEqualTo("cpe:2.3:a:zzzrevise14vendor:zzzrevise14product:1.0:*:*:*:*:windows:*:*");

        // Bug fix: max_cataloged_major spans the whole (vendor, product) partition, including
        // version 2.0's row, which never matched the title trigram filter — if it had silently
        // excluded that row, this would come back as 1 instead of 2.
        assertThat(entry.getMaxCatalogedMajor()).isEqualTo(2);

        // Deliberately preserved gate behavior: target_sw_values stays restricted to the rows that
        // matched this call's own trigram filter (row1 only), not the whole partition.
        assertThat(entry.getTargetSwValues()).isEqualTo(Set.of("windows"));
    }

    /**
     * Regression test for a PR #14 REVISE finding: {@code max_cataloged_major} cast its aggregate
     * to {@code ::integer} <em>outside</em> {@code max()}, so {@code max()} itself compared version
     * strings lexicographically rather than numerically. A fixture only spanning single-digit major
     * versions (e.g. "1.0"/"2.0") cannot detect that bug, because lexicographic and numeric order
     * agree for same-length digit strings — this fixture deliberately crosses the 9/10 digit-count
     * boundary, where {@code '9' > '10'} as strings but {@code 9 < 10} as integers, so a
     * regression back to comparing strings would make this test fail with {@code 9} instead of the
     * correct {@code 10}.
     *
     * <p>Both rows share one (vendor, product) pair but the query text ("zzzrevise14digitproduct")
     * happens to score differently against their two distinct titles ("... Nine" vs "... Ten"), so
     * the product-column and title-column {@code collect()} calls can each independently pick either
     * physical row as that pair's {@code DISTINCT ON} representative — both are asserted on here
     * rather than assuming a specific count, since {@code max_cataloged_major} must come out
     * correct (10) for the pair regardless of which single row a given {@code collect()} call
     * happened to keep.
     */
    @Test
    void maxCatalogedMajorComparesVersionsNumericallyNotLexicographically() {
        insert(
                "cpe:2.3:a:zzzrevise14digitvendor:zzzrevise14digitproduct:9.0:*:*:*:*:*:*:*",
                "Zzzrevise14digitproduct Nine",
                "zzzrevise14digitvendor",
                "zzzrevise14digitproduct");
        insert(
                "cpe:2.3:a:zzzrevise14digitvendor:zzzrevise14digitproduct:10.0:*:*:*:*:*:*:*",
                "Zzzrevise14digitproduct Ten",
                "zzzrevise14digitvendor",
                "zzzrevise14digitproduct");

        List<CpeDictionaryEntry> results = cpeDictionaryRepository.findFuzzyMatches(
                "zzzrevise14digitproduct", 0.3, 0.3, 10);

        assertThat(results).isNotEmpty();
        // Lexicographic max() would incorrectly return 9 here, since "9" > "10" as strings.
        assertThat(results).allMatch(e -> Integer.valueOf(10).equals(e.getMaxCatalogedMajor()));
    }

    /**
     * Regression test for a PR #14 REVISE finding: the outer {@code collect()} query had no
     * {@code ORDER BY}, so the score ordering the inner subquery already computed was not
     * guaranteed to survive the {@code CROSS JOIN LATERAL} into the final result set. Two products
     * here score differently against the query (one an exact product match, the other only a
     * partial/fuzzy one), so a correct implementation must return the exact match first regardless
     * of how the LATERAL join happens to order its output internally.
     */
    @Test
    void findFuzzyMatchesReturnsResultsSortedByScoreDescending() {
        insert(
                "cpe:2.3:a:zzzrevise14ordervendor:zzzrevise14orderproductexact:1.0:*:*:*:*:*:*:*",
                "Zzzrevise14orderproductexact",
                "zzzrevise14ordervendor",
                "zzzrevise14orderproductexact");
        insert(
                "cpe:2.3:a:zzzrevise14ordervendor:zzzrevise14orderproductfuzzyish:1.0:*:*:*:*:*:*:*",
                "Zzzrevise14orderproductfuzzyish",
                "zzzrevise14ordervendor",
                "zzzrevise14orderproductfuzzyish");

        List<CpeDictionaryEntry> results = cpeDictionaryRepository.findFuzzyMatches(
                "zzzrevise14orderproductexact", 0.3, 0.3, 10);

        assertThat(results).hasSizeGreaterThanOrEqualTo(2);
        assertThat(results.get(0).getProduct()).isEqualTo("zzzrevise14orderproductexact");
    }
}
