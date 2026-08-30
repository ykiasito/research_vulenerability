package com.vulncheck.app.repository;

import com.vulncheck.app.service.vuln.CsafStatusRow;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/** Raw JDBC (not a declarative {@code @Query}) for the same reason {@code CsafProductRepositoryImpl}
 *  is — a Postgres row-value {@code IN ((?,?,?),(?,?,?),...)} tuple list has to be built with a
 *  parameter count that varies per call, which a fixed {@code @Query} string can't express. */
@Repository
@RequiredArgsConstructor
class CsafProductStatusRepositoryImpl implements CsafProductStatusRepositoryCustom {

    private final JdbcTemplate jdbcTemplate;

    @Override
    public List<CsafStatusRow> findFinalStatuses(List<CsafProductCandidate> candidates) {
        if (candidates.isEmpty()) {
            return List.of();
        }

        String tuplePlaceholders = candidates.stream().map(c -> "(?,?,?)").collect(Collectors.joining(","));
        // REVISE item 2 (senior review 2026-08-27): joins csaf_products too now, purely to surface
        // p.component_version (the clean, purl-derived version of THIS status row's specific product
        // node) — needed so CsafVulnerabilitySource can apply the real RPM EVR fixed-version gate per
        // STATUS ROW rather than per candidate (a single product node can carry different statuses,
        // and therefore a different applicable check, for different CVEs — see
        // CsafDocumentUpsertServiceTest's real RHEA-2014:1175 fixture). The join key is exactly the
        // UNIQUE (vendor, advisory_id, csaf_product_id) constraint from V17 — no new index needed.
        String sql = "SELECT s.vendor, s.cve_id, s.status, s.fixed_version, s.remediation_url, "
                + "a.tracking_id, a.title, a.cvss_severity, p.component_version "
                + "FROM csaf_product_status s "
                + "JOIN csaf_advisories a ON a.vendor = s.vendor AND a.tracking_id = s.advisory_id "
                + "JOIN csaf_products p ON p.vendor = s.vendor AND p.advisory_id = s.advisory_id "
                + "AND p.csaf_product_id = s.csaf_product_id "
                + "WHERE (s.vendor, s.advisory_id, s.csaf_product_id) IN (" + tuplePlaceholders + ") "
                + "AND a.tracking_status = 'final'";

        List<Object> args = new ArrayList<>(candidates.size() * 3);
        for (CsafProductCandidate candidate : candidates) {
            args.add(candidate.vendor());
            args.add(candidate.advisoryId());
            args.add(candidate.csafProductId());
        }

        return jdbcTemplate.query(sql,
                (rs, rowNum) -> new CsafStatusRow(
                        rs.getString("vendor"),
                        rs.getString("cve_id"),
                        rs.getString("status"),
                        rs.getString("fixed_version"),
                        rs.getString("remediation_url"),
                        rs.getString("tracking_id"),
                        rs.getString("title"),
                        rs.getString("cvss_severity"),
                        rs.getString("component_version")),
                args.toArray());
    }

    /** Mirrors {@code CsafProductRepositoryImpl}'s chunking convention (go/no-go review item 7 — a
     *  single Red Hat advisory can produce up to ~171,072 status rows). */
    private static final int BATCH_CHUNK_SIZE = 2_000;

    @Override
    public void insertBatch(List<CsafProductStatusInsertRow> rows) {
        if (rows.isEmpty()) {
            return;
        }
        for (int start = 0; start < rows.size(); start += BATCH_CHUNK_SIZE) {
            List<CsafProductStatusInsertRow> chunk = rows.subList(start, Math.min(start + BATCH_CHUNK_SIZE, rows.size()));
            jdbcTemplate.batchUpdate("""
                    INSERT INTO csaf_product_status
                        (vendor, advisory_id, cve_id, csaf_product_id, status, fixed_version, remediation_url)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    chunk.stream()
                            .map(r -> new Object[] {r.vendor(), r.advisoryId(), r.cveId(), r.csafProductId(),
                                    r.status(), r.fixedVersion(), r.remediationUrl()})
                            .toList());
        }
    }
}
