package com.vulncheck.app.repository;

import java.sql.Array;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowCallbackHandler;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@RequiredArgsConstructor
class RegistryPackageMirrorRepositoryImpl implements RegistryPackageMirrorRepository {

    /**
     * TTL for the {@link #hasAnyEntries} in-memory cache (closed-mode backlog item 179 -- flagged by
     * senior-reviewer during the PR#112 batch review). This dates from before closed-mode B3 removed
     * the live-HTTP fallback: every {@code *RegistryClient#lookup} call used to check {@code
     * mirrorEnabled && hasAnyEntries(ecosystem)} before falling back to a live HTTP call, and without
     * caching that was one DB round trip per CSV item per registry once a mirror flag was turned on --
     * an N+1 pattern across all 9 registries at CSV-job scale. No caller does that check anymore (see
     * {@link RegistryPackageMirrorRepository#hasAnyEntries}'s own javadoc), but the cache itself is
     * kept working rather than deleted -- it is still exercised directly by {@code
     * RegistryPackageMirrorRepositoryImplTest} -- and it still only ever changes when a sync job
     * actually writes rows (see {@link #upsertBatch}, which proactively refreshes this cache the
     * moment that happens -- the primary invalidation path). This TTL is a safety net for the one case
     * that bypasses that proactive path: rows appearing out-of-band (e.g. a direct DB fix) rather than
     * through this repository's own write method.
     *
     * <p><b>Only {@code true} results are ever cached (see {@link #hasAnyEntries}) -- REVISE fix,
     * closed-mode item 179 round 2.</b> A negative result used to be cached too, which raced against
     * {@link #upsertBatch}'s proactive {@code true} write: a thread's {@code SELECT EXISTS} could
     * observe "no rows yet" just before a concurrent sync's {@code INSERT} commits, and if that
     * thread's {@code false} write landed in the map *after* the sync's {@code true} write, it clobbered
     * the correct answer for up to this whole TTL. Since {@code hasAnyEntries==false} always means "no
     * mirror yet, fall back to live" and there is no live network in closed-mode, that clobber was a
     * guaranteed lookup failure for every item of that registry until the stale entry expired -- not
     * merely a missed optimization. Caching only {@code true} closes this: both writers can only ever
     * write {@code true}, so no ordering between them can produce a wrong cached value. The cost is
     * that an ecosystem with no mirror yet re-queries the DB on every call -- acceptable, since that's
     * a single indexed {@code EXISTS} query, and once any given ecosystem's mirror is actually synced
     * (the steady-state, hot-path case this cache exists for), the result is {@code true} and gets
     * cached exactly as before.
     */
    private static final long HAS_ANY_ENTRIES_CACHE_TTL_MILLIS = 5 * 60 * 1000L;

    // No boolean payload: only a positive hasAnyEntries result is ever cached (see the TTL constant's
    // javadoc above), so an entry's mere presence (and being unexpired) already means "true".
    private record HasAnyEntriesCacheEntry(long expiresAtMillis) {
    }

    private final JdbcTemplate jdbcTemplate;

    // ConcurrentHashMap, not a Spring-cache abstraction: same reasoning as RegistryLookupCache /
    // NvdResponseCache in service.registry / service.vuln -- a handful of ecosystem keys, read by up
    // to itemProcessingExecutor's 8 parallel threads, doesn't need anything heavier.
    private final Map<String, HasAnyEntriesCacheEntry> hasAnyEntriesCache = new ConcurrentHashMap<>();

    @Override
    public boolean hasAnyEntries(String ecosystem) {
        long now = System.currentTimeMillis();
        HasAnyEntriesCacheEntry cached = hasAnyEntriesCache.get(ecosystem);
        if (cached != null && cached.expiresAtMillis() > now) {
            return true;
        }
        // Deliberately no @Transactional here (unlike findVersions/upsertBatch below): this is a
        // single JdbcTemplate statement, which runs correctly on a plain pooled connection without an
        // explicit transaction boundary, and skipping it means a cache hit above never pays even the
        // cost of a transaction manager borrowing a connection just to no-op.
        Boolean exists = jdbcTemplate.queryForObject(
                "SELECT EXISTS(SELECT 1 FROM registry_package_mirror WHERE ecosystem = ?)",
                Boolean.class, ecosystem);
        boolean result = Boolean.TRUE.equals(exists);
        // Only cache true (see this cache's own field javadoc for why false is never written here):
        // caching a false here as well raced against upsertBatch's proactive true write, and a false
        // that lost that race could clobber the correct true for up to the whole TTL.
        if (result) {
            hasAnyEntriesCache.put(ecosystem, new HasAnyEntriesCacheEntry(now + HAS_ANY_ENTRIES_CACHE_TTL_MILLIS));
        }
        return result;
    }

    /**
     * Test-only hook (package-private, used by {@code RegistryPackageMirrorRepositoryImplTest}): the
     * {@link #hasAnyEntriesCache} field lives on this Spring-managed singleton bean, which {@code
     * @DataJpaTest} reuses across every test method in a class run -- unlike this bean's DB writes,
     * a per-test transaction rollback does not reset a plain JVM-heap field on its own.
     */
    void clearHasAnyEntriesCacheForTesting() {
        hasAnyEntriesCache.clear();
    }

    @Override
    @Transactional(readOnly = true)
    public List<String> findVersions(String ecosystem, String normalizedPackageName) {
        List<String> result = new ArrayList<>();
        // Explicit (RowCallbackHandler) cast: without it, javac reports this call as ambiguous
        // between JdbcTemplate's RowCallbackHandler and ResultSetExtractor<T> overloads -- this
        // lambda's shape (a single expression whose value happens to be discarded) is applicable to
        // both.
        jdbcTemplate.query(
                "SELECT versions FROM registry_package_mirror WHERE ecosystem = ? AND package_name = ?",
                (RowCallbackHandler) rs -> result.addAll(toStringList(rs.getArray("versions"))),
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
        // Proactive refresh (closed-mode backlog item 179): a non-empty batch just wrote at least one
        // row for this ecosystem, so hasAnyEntries is unconditionally true for it from this point on
        // -- reflect that immediately instead of leaving a caller to wait out
        // HAS_ANY_ENTRIES_CACHE_TTL_MILLIS. (This runs before the enclosing @Transactional commits;
        // on the rare rollback of this whole batch, the cache would say true for up to that TTL
        // before self-correcting on a later query -- the same bounded staleness this cache already
        // accepts for out-of-band DB changes, so not worth the extra complexity of an after-commit
        // hook for it.)
        hasAnyEntriesCache.put(ecosystem,
                new HasAnyEntriesCacheEntry(System.currentTimeMillis() + HAS_ANY_ENTRIES_CACHE_TTL_MILLIS));
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
