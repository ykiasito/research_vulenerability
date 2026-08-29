package com.vulncheck.app.repository;

import static org.assertj.core.api.Assertions.assertThat;

import com.vulncheck.app.entity.CpeDictionaryEntry;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Exercises {@link CpeDictionaryRepositoryImpl#findFuzzyMatches} directly against a real Postgres
 * instance (trgm scoring can't be meaningfully verified against a mock). Regression coverage for
 * docs/spec/task-backlog.md item 27: the pg_trgm session default is 0.3, so a title-only match
 * scoring in the [0.3, 0.6) band is exactly the case the old {@code SET LOCAL
 * pg_trgm.similarity_threshold = ...} approach could silently fail to reject whenever it ran
 * outside a transaction block (confirmed live against the dev DB, senior review, PR #14 final
 * review, 2026-08-30) — {@link CpeDictionaryRepositoryImpl}'s own class javadoc has the full
 * history. {@link #collect} now enforces the threshold with an explicit {@code similarity(...) >
 * ?} predicate instead, which cannot silently no-op the way a session-level setting could.
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
}
