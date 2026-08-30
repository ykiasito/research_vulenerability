package com.vulncheck.app.repository;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/** See {@code CpeDictionaryRepositoryImpl} for why this is raw JDBC + {@code SET LOCAL} rather
 *  than a declarative {@code @Query} — the short version: only the {@code %} operator can use a
 *  pg_trgm GIN index, and its threshold is a session setting, not a bindable query parameter. */
@Repository
@RequiredArgsConstructor
class CveOrgAffectedProductRepositoryImpl implements CveOrgAffectedProductRepositoryCustom {

    private final JdbcTemplate jdbcTemplate;

    @Override
    @Transactional
    public List<String> findCandidateCveIds(String productQuery, double threshold, int limit) {
        Map<String, Double> bestScoreByCveId = new LinkedHashMap<>();

        collect("product", productQuery, threshold, limit, bestScoreByCveId);
        collect("package_name", productQuery, threshold, limit, bestScoreByCveId);

        return bestScoreByCveId.entrySet().stream()
                .sorted((a, b) -> Double.compare(b.getValue(), a.getValue()))
                .limit(limit)
                .map(Map.Entry::getKey)
                .toList();
    }

    /** {@code column} is always one of the two hardcoded literals above — never request input —
     *  so interpolating it directly into the SQL text is safe. */
    private void collect(String column, String query, double threshold, int limit, Map<String, Double> bestScoreByCveId) {
        jdbcTemplate.execute("SET LOCAL pg_trgm.similarity_threshold = " + threshold);
        String sql = "SELECT cve_id, similarity(" + column + ", ?) AS score FROM cve_org_affected_products "
                + "WHERE " + column + " % ? ORDER BY score DESC LIMIT ?";
        jdbcTemplate.query(sql, rs -> {
            String cveId = rs.getString("cve_id");
            double score = rs.getDouble("score");
            if (bestScoreByCveId.getOrDefault(cveId, -1.0) < score) {
                bestScoreByCveId.put(cveId, score);
            }
        }, query, query, limit);
    }
}
