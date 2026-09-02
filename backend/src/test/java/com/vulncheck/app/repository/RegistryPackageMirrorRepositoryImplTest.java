package com.vulncheck.app.repository;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Exercises {@link RegistryPackageMirrorRepositoryImpl} against a real Postgres instance — the
 * {@code versions text[]} column's read/write path (an explicit {@code java.sql.Array}, not a plain
 * JDBC scalar type) can't be meaningfully verified against a mock. Same {@code @DataJpaTest} +
 * {@code @AutoConfigureTestDatabase(Replace.NONE)} shape as {@code CpeDictionaryRepositoryImplTest} —
 * each test runs in a transaction rolled back afterward, so nothing written here is persisted past
 * the test run.
 *
 * <p>{@code @Import} is needed here (unlike {@code CpeDictionaryRepositoryImplTest}): {@link
 * RegistryPackageMirrorRepository} is a plain interface, not a Spring Data {@code JpaRepository},
 * because this table has no JPA entity (see that interface's own javadoc for why) — so {@code
 * @DataJpaTest}'s slice, which only auto-detects real Spring Data repositories, never picks up
 * {@link RegistryPackageMirrorRepositoryImpl} on its own the way it does for {@code
 * CpeDictionaryRepositoryImpl} (a custom-implementation fragment of an actual {@code JpaRepository}).
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(RegistryPackageMirrorRepositoryImpl.class)
class RegistryPackageMirrorRepositoryImplTest {

    @Autowired
    private RegistryPackageMirrorRepository registryPackageMirrorRepository;

    // Concrete type (not just the interface above), so tests below can reach the package-private
    // clearHasAnyEntriesCacheForTesting() hook -- same bean, autowired twice by different declared
    // types is fine for a singleton.
    @Autowired
    private RegistryPackageMirrorRepositoryImpl registryPackageMirrorRepositoryImpl;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    // closed-mode backlog item 179: hasAnyEntries is now cached in-process (see that method's
    // javadoc), and that cache lives on the singleton bean Spring reuses across every test method in
    // this class run -- reset it before each test so tests stay independent of execution order and
    // of what an earlier test cached, same as the DB itself being rolled back between tests.
    @BeforeEach
    void clearHasAnyEntriesCache() {
        registryPackageMirrorRepositoryImpl.clearHasAnyEntriesCacheForTesting();
    }

    @Test
    void hasAnyEntriesIsFalseForAnEcosystemWithNoRowsAtAll() {
        assertThat(registryPackageMirrorRepository.hasAnyEntries("crates.io")).isFalse();
    }

    @Test
    void findVersionsReturnsEmptyListForAPackageThatWasNeverSynced() {
        assertThat(registryPackageMirrorRepository.findVersions("crates.io", "totally-unknown-crate")).isEmpty();
    }

    @Test
    void upsertThenFindRoundTripsTheFullVersionList() {
        registryPackageMirrorRepository.upsertBatch("crates.io",
                Map.of("serde", List.of("1.0.228", "1.0.229")));

        assertThat(registryPackageMirrorRepository.hasAnyEntries("crates.io")).isTrue();
        assertThat(registryPackageMirrorRepository.findVersions("crates.io", "serde"))
                .containsExactlyInAnyOrder("1.0.228", "1.0.229");
    }

    @Test
    void upsertOverwritesThePreviousVersionListOnConflict() {
        registryPackageMirrorRepository.upsertBatch("crates.io", Map.of("serde", List.of("1.0.228")));
        registryPackageMirrorRepository.upsertBatch("crates.io",
                Map.of("serde", List.of("1.0.228", "1.0.229", "1.0.230")));

        assertThat(registryPackageMirrorRepository.findVersions("crates.io", "serde"))
                .containsExactlyInAnyOrder("1.0.228", "1.0.229", "1.0.230");
    }

    @Test
    void ecosystemsAreIsolatedFromEachOther() {
        registryPackageMirrorRepository.upsertBatch("crates.io", Map.of("serde", List.of("1.0.228")));

        assertThat(registryPackageMirrorRepository.hasAnyEntries("npm")).isFalse();
        assertThat(registryPackageMirrorRepository.findVersions("npm", "serde")).isEmpty();
    }

    @Test
    void upsertBatchWithAnEmptyMapIsANoOp() {
        registryPackageMirrorRepository.upsertBatch("crates.io", Map.of());

        assertThat(registryPackageMirrorRepository.hasAnyEntries("crates.io")).isFalse();
    }

    @Test
    void upsertBatchImmediatelyRefreshesTheHasAnyEntriesCacheWithoutWaitingForTtl() {
        // Prime the cache with a negative result -- exactly the value a sync-not-run-yet ecosystem
        // would cache -- so the assertion below can only pass if upsertBatch actively refreshes it.
        assertThat(registryPackageMirrorRepository.hasAnyEntries("crates.io")).isFalse();

        registryPackageMirrorRepository.upsertBatch("crates.io", Map.of("serde", List.of("1.0.228")));

        assertThat(registryPackageMirrorRepository.hasAnyEntries("crates.io")).isTrue();
    }

    @Test
    void hasAnyEntriesNeverCachesAFalseResultSoAnOutOfBandRowIsVisibleImmediately() {
        // REVISE fix, closed-mode item 179 round 2: caching a false result raced against
        // upsertBatch's proactive true write (see hasAnyEntries's own javadoc for the exact
        // sequence) -- a losing false could clobber a correct true for up to the whole TTL, which in
        // closed-mode (no live-HTTP fallback network to catch the mistake) meant guaranteed lookup
        // failures for every item of that registry until the stale entry expired. Fixed by never
        // caching false at all, which this test pins down directly: a row appearing without going
        // through upsertBatch's own proactive cache refresh (so there is nothing here that could
        // have refreshed a cache entry) must still be visible on the very next call, with no need to
        // reach for clearHasAnyEntriesCacheForTesting.
        assertThat(registryPackageMirrorRepository.hasAnyEntries("crates.io")).isFalse();

        jdbcTemplate.update(
                "INSERT INTO registry_package_mirror (ecosystem, package_name, versions, last_synced_at) "
                        + "VALUES (?, ?, ARRAY['1.0.228'], now())",
                "crates.io", "serde");

        assertThat(registryPackageMirrorRepository.hasAnyEntries("crates.io")).isTrue();
    }

    @Test
    void hasAnyEntriesServesTheCachedTrueValueUntilExplicitlyCleared() {
        registryPackageMirrorRepository.upsertBatch("crates.io", Map.of("serde", List.of("1.0.228")));
        assertThat(registryPackageMirrorRepository.hasAnyEntries("crates.io")).isTrue();

        // Remove the row directly, bypassing this repository's own cache-management entirely -- the
        // only way left for the cached "true" above to go stale without this repository knowing.
        jdbcTemplate.update("DELETE FROM registry_package_mirror WHERE ecosystem = ?", "crates.io");

        // Still true: proves the cached value, not a fresh query, answered this call.
        assertThat(registryPackageMirrorRepository.hasAnyEntries("crates.io")).isTrue();

        registryPackageMirrorRepositoryImpl.clearHasAnyEntriesCacheForTesting();

        // Now false: a fresh query sees the delete above.
        assertThat(registryPackageMirrorRepository.hasAnyEntries("crates.io")).isFalse();
    }
}
