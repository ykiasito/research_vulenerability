package com.vulncheck.app.repository;

import static org.assertj.core.api.Assertions.assertThat;

import com.vulncheck.app.entity.EcosystemRegistry;
import com.vulncheck.app.entity.User;
import com.vulncheck.app.entity.UserSecret;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Closed-mode backlog item 262 (Phase B6, {@code docs/spec/closed-mode-plan.md} §3-2): verifies
 * {@code R__closed_mode_strip.sql} — a Flyway repeatable migration. Per Flyway's own
 * repeatable-migration semantics (see that file's own header comment for the full explanation,
 * corrected senior-reviewer REVISE on this same item): it runs once on a brand-new database
 * (guaranteeing a fresh DB starts with both target tables empty) but only re-runs on an
 * already-migrated database when its own checksum changes — not automatically on every
 * build/deploy or in response to either table's row count.
 *
 * <p>Two complementary checks, {@code @DataJpaTest} + {@code @AutoConfigureTestDatabase(Replace.NONE)}
 * against the real test Postgres instance (same shape as {@code JobCostLedgerRepositoryTest} et al.):
 *
 * <ol>
 *   <li>{@link #repeatableMigrationIsRecordedAsSuccessfullyAppliedInFlywayHistory} — queries {@code
 *       flyway_schema_history} directly and asserts a successful entry for this migration exists.
 *       This does NOT prove the migration ran as part of THIS test run/context bootstrap
 *       specifically (per the semantics above, it may have run at any earlier point against this
 *       same shared test database and simply never needed to re-run since) — only that Flyway's own
 *       history considers it successfully applied at some point, which is what actually matters for
 *       "did this migration ever corrupt the schema/fail silently".</li>
 *   <li>{@link #repeatableMigrationSqlDeletesOnlyClaudeUserSecretsAndClearsEcosystemRegistries} —
 *       rather than trusting whatever {@code user_secrets}/{@code ecosystem_registries} rows happen
 *       to already exist in the shared test database at the moment this test runs (order-dependent:
 *       some other, non-{@code @DataJpaTest} integration test elsewhere in the suite could leave a
 *       committed row behind), inserts its own fresh rows — a {@code claude} secret and an {@code
 *       nvd} secret for a throwaway user, plus one {@code ecosystem_registries} row — inside this
 *       test's own transaction (rolled back afterward, same as every other {@code @DataJpaTest} here),
 *       then re-executes the migration file's ACTUAL statements (read from the classpath resource
 *       itself, not copied into this test as a literal — see {@link #readMigrationStatements}'s own
 *       javadoc for why that distinction matters) and asserts only the {@code claude} row was removed
 *       (the {@code nvd} row survives, proving the {@code WHERE provider = 'claude'} predicate is
 *       selective, not a blanket wipe) and {@code ecosystem_registries} is now empty.</li>
 * </ol>
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class ClosedModeStripMigrationTest {

    private static final String MIGRATION_CLASSPATH_RESOURCE = "db/migration/R__closed_mode_strip.sql";

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private UserSecretRepository userSecretRepository;
    @Autowired
    private EcosystemRegistryRepository ecosystemRegistryRepository;
    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void repeatableMigrationIsRecordedAsSuccessfullyAppliedInFlywayHistory() {
        List<Map<String, Object>> rows = jdbcTemplate.queryForList(
                "SELECT success FROM flyway_schema_history WHERE script LIKE '%closed_mode_strip%'");

        assertThat(rows)
                .as("R__closed_mode_strip.sql must have a successfully-applied entry in Flyway's own "
                        + "history -- not merely exist as a file on disk")
                .isNotEmpty();
        assertThat(rows).allSatisfy(row -> assertThat(row.get("success")).isEqualTo(true));
    }

    @Test
    void repeatableMigrationSqlDeletesOnlyClaudeUserSecretsAndClearsEcosystemRegistries() {
        User user = new User();
        user.setEmail("closed-mode-strip-test-" + System.nanoTime() + "@example.com");
        user.setPasswordHash("hash");
        user = userRepository.save(user);

        userSecretRepository.upsert(user.getId(), UserSecret.PROVIDER_CLAUDE, "encrypted-claude-blob");
        userSecretRepository.upsert(user.getId(), UserSecret.PROVIDER_NVD, "encrypted-nvd-blob");
        ecosystemRegistryRepository.save(
                new EcosystemRegistry(null, "npm", "npm", "https://registry.npmjs.org", true));

        // Sanity check: the rows this test just inserted are actually there before the migration
        // SQL runs -- otherwise the assertions below would trivially pass for the wrong reason.
        assertThat(userSecretRepository.findByUserIdAndProvider(user.getId(), UserSecret.PROVIDER_CLAUDE))
                .isPresent();
        assertThat(userSecretRepository.findByUserIdAndProvider(user.getId(), UserSecret.PROVIDER_NVD))
                .isPresent();
        assertThat(ecosystemRegistryRepository.findAll()).isNotEmpty();

        // The migration file's ACTUAL statements, read from the classpath resource itself (see
        // readMigrationStatements's own javadoc) -- re-executed here rather than relying solely on
        // whatever state Flyway's own once-per-database run left behind, so this test's outcome
        // doesn't depend on execution order relative to other tests that might insert rows into
        // these same tables.
        for (String statement : readMigrationStatements()) {
            jdbcTemplate.execute(statement);
        }

        assertThat(userSecretRepository.findByUserIdAndProvider(user.getId(), UserSecret.PROVIDER_CLAUDE))
                .as("claude secrets must be stripped")
                .isEmpty();
        assertThat(userSecretRepository.findByUserIdAndProvider(user.getId(), UserSecret.PROVIDER_NVD))
                .as("nvd secrets must survive -- the DELETE is scoped to provider = 'claude' only")
                .isPresent();
        assertThat(ecosystemRegistryRepository.findAll())
                .as("ecosystem_registries must be fully cleared, not just filtered")
                .isEmpty();
    }

    /**
     * Reads {@code R__closed_mode_strip.sql} straight off the classpath and splits it into
     * individual statements (comment lines dropped, then split on {@code ;}) — senior-reviewer
     * REVISE (item 262/PR#200): the first version of this test hand-copied the migration's two
     * {@code DELETE} statements as Java string literals, so an edit to the real migration file (e.g.
     * accidentally dropping the {@code WHERE provider = 'claude'} predicate, turning it into a
     * blanket wipe of every provider's secrets) would silently leave this test green — it was
     * verifying its own copy, not the file Flyway actually runs. Reading the real file means this
     * test can only pass if the file's actual current content behaves as asserted.
     */
    private List<String> readMigrationStatements() {
        String sql;
        try {
            sql = new ClassPathResource(MIGRATION_CLASSPATH_RESOURCE).getContentAsString(StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read " + MIGRATION_CLASSPATH_RESOURCE + " off the classpath", e);
        }
        String withoutComments = sql.lines()
                .filter(line -> !line.strip().startsWith("--"))
                .collect(Collectors.joining("\n"));
        return List.of(withoutComments.split(";")).stream()
                .map(String::strip)
                .filter(statement -> !statement.isEmpty())
                .collect(Collectors.toList());
    }
}
