package com.vulncheck.app.repository;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.OffsetDateTime;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

/**
 * Exercises {@link CsafProductRepositoryImpl} directly against a real Postgres instance (same
 * rationale as {@code VulnerabilityRepositoryTest} — trgm/ordering behavior can't be meaningfully
 * verified against a mock). Covers senior review REVISE item 1 (2026-08-27, CRITICAL): {@link
 * CsafProductRepositoryCustom#findCandidateProductsExact} used to have {@code LIMIT 30} with no
 * {@code ORDER BY} at all, so ties silently broke on physical row order (roughly year-ascending) —
 * a query for a common name like {@code "kernel"} returned only the OLDEST matching advisories,
 * never anything recent.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class CsafProductRepositoryImplTest {

    @Autowired
    private CsafAdvisoryRepository csafAdvisoryRepository;
    @Autowired
    private CsafProductRepository csafProductRepository;

    private void seedAdvisory(String vendor, String trackingId, OffsetDateTime dateUpdated) {
        csafAdvisoryRepository.upsert(vendor, trackingId, "final", "1", "title for " + trackingId, "WHITE",
                null, null, dateUpdated, dateUpdated, "{}");
    }

    @Test
    void findCandidateProductsExactOrdersByAdvisoryRecencyNotPhysicalRowOrder() {
        // Insert the OLD (1999) advisory/product FIRST — a physical-row-order tiebreak (the pre-fix
        // bug) would put this one first in the result, exactly the wrong answer.
        seedAdvisory("redhat", "RHSA-1999:1", OffsetDateTime.parse("1999-01-01T00:00:00Z"));
        seedAdvisory("redhat", "RHSA-2026:1", OffsetDateTime.parse("2026-08-01T00:00:00Z"));
        csafProductRepository.insertBatch(List.of(
                new CsafProductInsertRow("redhat", "RHSA-1999:1", "kernel-old", "kernel", "2.4.0-1", null,
                        null, null, "kernel-2.4.0-1", OffsetDateTime.parse("1999-01-01T00:00:00Z")),
                new CsafProductInsertRow("redhat", "RHSA-2026:1", "kernel-new", "kernel", "6.10.0-1", null,
                        null, null, "kernel-6.10.0-1", OffsetDateTime.parse("2026-08-01T00:00:00Z"))));

        List<CsafProductCandidate> results = csafProductRepository.findCandidateProductsExact(List.of("redhat"), "kernel", 30);

        assertThat(results).hasSize(2);
        assertThat(results.get(0).advisoryId()).isEqualTo("RHSA-2026:1");
        assertThat(results.get(1).advisoryId()).isEqualTo("RHSA-1999:1");
    }

    @Test
    void findCandidateProductsExactPutsARowWithANullAdvisoryUpdatedAtLast() {
        seedAdvisory("redhat", "RHSA-1999:1", OffsetDateTime.parse("1999-01-01T00:00:00Z"));
        seedAdvisory("redhat", "RHSA-2026:1", OffsetDateTime.parse("2026-08-01T00:00:00Z"));
        csafProductRepository.insertBatch(List.of(
                // Simulates a row inserted before V21's backfill (advisory_updated_at legitimately
                // NULL) — must sort LAST, not crash or sort first.
                new CsafProductInsertRow("redhat", "RHSA-1999:1", "widget-nulldate", "widget", "1.0-1", null,
                        null, null, "widget-1.0-1", null),
                new CsafProductInsertRow("redhat", "RHSA-2026:1", "widget-dated", "widget", "2.0-1", null,
                        null, null, "widget-2.0-1", OffsetDateTime.parse("2026-08-01T00:00:00Z"))));

        List<CsafProductCandidate> results = csafProductRepository.findCandidateProductsExact(List.of("redhat"), "widget", 30);

        assertThat(results).extracting(CsafProductCandidate::csafProductId)
                .containsExactly("widget-dated", "widget-nulldate");
    }

    @Test
    void findCandidateProductsFallbackTiebreaksTiedSimilarityScoresByAdvisoryRecency() {
        // REVISE item 1's recency tiebreak also applies to the trgm fallback (scoped to Siemens only
        // as of REVISE item 5) — two rows with an IDENTICAL component_name score identically on
        // similarity(), so without the tiebreak the old/new ordering would again be arbitrary.
        seedAdvisory("siemens", "SSA-OLD", OffsetDateTime.parse("2010-01-01T00:00:00Z"));
        seedAdvisory("siemens", "SSA-NEW", OffsetDateTime.parse("2026-08-01T00:00:00Z"));
        csafProductRepository.insertBatch(List.of(
                new CsafProductInsertRow("siemens", "SSA-OLD", "gadget-old", "Widget Gadget", null, null,
                        null, null, "Widget Gadget", OffsetDateTime.parse("2010-01-01T00:00:00Z")),
                new CsafProductInsertRow("siemens", "SSA-NEW", "gadget-new", "Widget Gadget", null, null,
                        null, null, "Widget Gadget", OffsetDateTime.parse("2026-08-01T00:00:00Z"))));

        List<CsafProductCandidate> results = csafProductRepository.findCandidateProducts("Widget Gadget", 0.35, 30);

        assertThat(results).hasSizeGreaterThanOrEqualTo(2);
        assertThat(results.get(0).advisoryId()).isEqualTo("SSA-NEW");
    }

    @Test
    void findCandidateProductsFallbackNeverReturnsARedHatRow() {
        // REVISE item 5 (senior review 2026-08-27): scoped to vendor='siemens' only now — a Red Hat
        // row with a name that would otherwise fuzzy-match must never come back from this path.
        seedAdvisory("redhat", "RHSA-2026:1", OffsetDateTime.parse("2026-08-01T00:00:00Z"));
        csafProductRepository.insertBatch(List.of(
                new CsafProductInsertRow("redhat", "RHSA-2026:1", "openssl-libs-id", "openssl-libs", "3.0.7-1", null,
                        null, null, "openssl-libs-3.0.7-1", OffsetDateTime.parse("2026-08-01T00:00:00Z"))));

        List<CsafProductCandidate> results = csafProductRepository.findCandidateProducts("openssl", 0.35, 30);

        assertThat(results).noneMatch(c -> "redhat".equals(c.vendor()));
    }
}
