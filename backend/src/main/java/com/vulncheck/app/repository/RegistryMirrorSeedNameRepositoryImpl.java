package com.vulncheck.app.repository;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@RequiredArgsConstructor
class RegistryMirrorSeedNameRepositoryImpl implements RegistryMirrorSeedNameRepository {

    private final JdbcTemplate jdbcTemplate;

    @Override
    @Transactional(readOnly = true)
    public List<String> findDistinctPackageNames(String ecosystem) {
        return jdbcTemplate.queryForList(
                "SELECT DISTINCT package_name FROM registry_mirror_seed_name WHERE ecosystem = ?",
                String.class, ecosystem);
    }

    @Override
    @Transactional
    public void insertBatch(String ecosystem, List<String> packageNames) {
        if (packageNames.isEmpty()) {
            return;
        }
        jdbcTemplate.batchUpdate("""
                INSERT INTO registry_mirror_seed_name (ecosystem, package_name, added_at)
                VALUES (?, ?, now())
                ON CONFLICT (ecosystem, package_name) DO NOTHING
                """, new BatchPreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps, int i) throws SQLException {
                ps.setString(1, ecosystem);
                ps.setString(2, packageNames.get(i));
            }

            @Override
            public int getBatchSize() {
                return packageNames.size();
            }
        });
    }
}
