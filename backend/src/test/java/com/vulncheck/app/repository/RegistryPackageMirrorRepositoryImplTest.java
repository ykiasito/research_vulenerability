package com.vulncheck.app.repository;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

/**
 * Exercises {@link RegistryPackageMirrorRepositoryImpl} against a real Postgres instance — the
 * {@code versions text[]} column's read/write path (an explicit {@code java.sql.Array}, not a plain
 * JDBC scalar type) can't be meaningfully verified against a mock. Same {@code @DataJpaTest} +
 * {@code @AutoConfigureTestDatabase(Replace.NONE)} shape as {@code CpeDictionaryRepositoryImplTest} —
 * each test runs in a transaction rolled back afterward, so nothing written here is persisted past
 * the test run.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class RegistryPackageMirrorRepositoryImplTest {

    @Autowired
    private RegistryPackageMirrorRepository registryPackageMirrorRepository;

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
}
