package com.vulncheck.app.repository;

import static org.assertj.core.api.Assertions.assertThat;

import com.vulncheck.app.entity.EcosystemRegistry;
import com.vulncheck.app.entity.User;
import com.vulncheck.app.entity.UserSecret;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Closed-mode backlog item 262 (Phase B6, {@code docs/spec/closed-mode-plan.md} §3-2): verifies
 * {@code R__closed_mode_strip.sql} — a Flyway repeatable migration, run automatically on every
 * context bootstrap (this test's own {@code @DataJpaTest} context included) whenever its checksum
 * changes, not a one-time versioned cutover.
 *
 * <p>Two complementary checks, {@code @DataJpaTest} + {@code @AutoConfigureTestDatabase(Replace.NONE)}
 * against the real test Postgres instance (same shape as {@code JobCostLedgerRepositoryTest} et al.):
 *
 * <ol>
 *   <li>{@link #repeatableMigrationIsRecordedAsSuccessfullyAppliedInFlywayHistory} — queries {@code
 *       flyway_schema_history} directly, proving Flyway actually discovered and ran this specific
 *       file as part of this context's own startup (not just that the SQL text elsewhere happens to
 *       be correct) — a syntax error or an unresolved table name in the migration would have failed
 *       context startup for every test in the suite, not just this one, so a green build already
 *       implies success; this asserts it explicitly and by name.</li>
 *   <li>{@link #repeatableMigrationSqlDeletesOnlyClaudeUserSecretsAndClearsEcosystemRegistries} —
 *       rather than trusting whatever {@code user_secrets}/{@code ecosystem_registries} rows happen
 *       to already exist in the shared test database at the moment this test runs (order-dependent:
 *       some other, non-{@code @DataJpaTest} integration test elsewhere in the suite could leave a
 *       committed row behind), inserts its own fresh rows — a {@code claude} secret and an {@code
 *       nvd} secret for a throwaway user, plus one {@code ecosystem_registries} row — inside this
 *       test's own transaction (rolled back afterward, same as every other {@code @DataJpaTest} here),
 *       then re-executes the migration's exact two statements directly and asserts only the {@code
 *       claude} row was removed (the {@code nvd} row survives, proving the {@code WHERE provider =
 *       'claude'} predicate is selective, not a blanket wipe) and {@code ecosystem_registries} is
 *       now empty.</li>
 * </ol>
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class ClosedModeStripMigrationTest {

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
                .as("R__closed_mode_strip.sql must have actually run as part of this context's own "
                        + "Flyway migration, not merely exist as a file on disk")
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

        // The migration's own two statements, verbatim (R__closed_mode_strip.sql) -- re-executed
        // here rather than relying solely on whatever state Flyway's own once-per-context run left
        // behind, so this test's outcome doesn't depend on execution order relative to other tests
        // that might insert rows into these same tables.
        jdbcTemplate.update("DELETE FROM user_secrets WHERE provider = 'claude'");
        jdbcTemplate.update("DELETE FROM ecosystem_registries");

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
}
