package com.vulncheck.app.repository;

import java.sql.Array;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@RequiredArgsConstructor
class RegistryPackageMirrorRepositoryImpl implements RegistryPackageMirrorRepository {

    private final JdbcTemplate jdbcTemplate;

    @Override
    @Transactional(readOnly = true)
    public boolean hasAnyEntries(String ecosystem) {
        Boolean exists = jdbcTemplate.queryForObject(
                "SELECT EXISTS(SELECT 1 FROM registry_package_mirror WHERE ecosystem = ?)",
                Boolean.class, ecosystem);
        return Boolean.TRUE.equals(exists);
    }

    @Override
    @Transactional(readOnly = true)
    public List<String> findVersions(String ecosystem, String normalizedPackageName) {
        List<String> result = new ArrayList<>();
        jdbcTemplate.query(
                "SELECT versions FROM registry_package_mirror WHERE ecosystem = ? AND package_name = ?",
                rs -> result.addAll(toStringList(rs.getArray("versions"))),
                ecosystem, normalizedPackageName);
        return result;
    }

    @Override
    @Transactional
    public void upsertBatch(String ecosystem, Map<String, List<String>> versionsByNormalizedPackageName) {
        if (versionsByNormalizedPackageName.isEmpty()) {
            return;
        }
        List<Map.Entry<String, List<String>>> entries = List.copyOf(versionsByNormalizedPackageName.entrySet());
        // BatchPreparedStatementSetter (not the simpler jdbcTemplate.batchUpdate(sql, List<Object[]>)
        // overload) because the versions column needs a real java.sql.Array built from this
        // PreparedStatement's own Connection -- pgjdbc has no implicit Java-String[]-to-SQL-array
        // conversion via plain setObject, unlike the scalar columns here.
        jdbcTemplate.batchUpdate("""
                INSERT INTO registry_package_mirror (ecosystem, package_name, versions, last_synced_at)
                VALUES (?, ?, ?, now())
                ON CONFLICT (ecosystem, package_name)
                DO UPDATE SET versions = EXCLUDED.versions, last_synced_at = now()
                """, new BatchPreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps, int i) throws SQLException {
                Map.Entry<String, List<String>> entry = entries.get(i);
                ps.setString(1, ecosystem);
                ps.setString(2, entry.getKey());
                ps.setArray(3, ps.getConnection().createArrayOf("text", entry.getValue().toArray(new String[0])));
            }

            @Override
            public int getBatchSize() {
                return entries.size();
            }
        });
    }

    private List<String> toStringList(Array sqlArray) throws SQLException {
        if (sqlArray == null) {
            return List.of();
        }
        Object[] values = (Object[]) sqlArray.getArray();
        List<String> result = new ArrayList<>();
        for (Object value : values) {
            if (value != null) {
                result.add(value.toString());
            }
        }
        return result;
    }
}
