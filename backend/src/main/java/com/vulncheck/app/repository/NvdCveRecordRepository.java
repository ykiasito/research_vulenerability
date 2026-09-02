package com.vulncheck.app.repository;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * Plain {@link JdbcTemplate}-backed batch upsert for {@code nvd_cve_records} — not a Spring Data
 * JPA repository, matching {@code CpeDictionaryRepositoryImpl#upsertBatch}'s own reasoning: this
 * table is populated a page (up to 2,000 rows) at a time by {@link
 * com.vulncheck.app.service.NvdCveSyncService}, and a full mirror is ~320k rows (§4-2-6) — one
 * statement per row via an entity manager would turn the sync's estimated 20-40 minute ingest
 * budget into hours of pure round-trip overhead.
 */
@Repository
@RequiredArgsConstructor
public class NvdCveRecordRepository {

    private final JdbcTemplate jdbcTemplate;

    /** One parsed NVD CVE record, ready to upsert. Not a JPA entity — see this class's javadoc for
     *  why the whole table is batch-upserted via plain JDBC instead. */
    public record Row(String cveId, String description, String severity, BigDecimal cvssScore,
            OffsetDateTime publishedAt, OffsetDateTime lastModifiedAt) {
    }

    @Transactional
    public void upsertBatch(List<Row> rows) {
        if (rows.isEmpty()) {
            return;
        }
        jdbcTemplate.batchUpdate("""
                INSERT INTO nvd_cve_records
                    (cve_id, description, severity, cvss_score, published_at, last_modified_at, last_synced_at)
                VALUES (?, ?, ?, ?, ?, ?, now())
                ON CONFLICT (cve_id)
                DO UPDATE SET description = EXCLUDED.description,
                              severity = EXCLUDED.severity,
                              cvss_score = EXCLUDED.cvss_score,
                              published_at = EXCLUDED.published_at,
                              last_modified_at = EXCLUDED.last_modified_at,
                              last_synced_at = now()
                """,
                rows.stream()
                        .map(r -> new Object[] {r.cveId(), r.description(), r.severity(), r.cvssScore(),
                                r.publishedAt(), r.lastModifiedAt()})
                        .toList());
    }
}
