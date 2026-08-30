package com.vulncheck.app.service;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * One-shot post-rotation check for the 2026-08-29 {@code POSTGRES_PASSWORD} rotation (see
 * `docs/spec/nfr-status-2026-08.md` §5): confirms the live database is reachable over TCP with the
 * newly rotated password AND that existing {@code user_secrets} rows (encrypted under the
 * unrelated, unchanged {@code APP_SECRET_ENCRYPTION_KEY}) still round-trip correctly through it —
 * i.e. rotating the DB password did not corrupt or orphan anything that
 * {@link UserApiKeyService}/{@link SecretsController} rely on for real job processing.
 *
 * <p>Deliberately plain JDBC, no Spring context, same rationale as {@link SecretKeyRotationJobCreator}
 * (avoids double-firing {@code @Scheduled} sync jobs against the live DB this backend is already
 * connected to).
 *
 * <p>Reads the new DB password and the encryption key from env vars only (never hardcoded, never
 * committed): {@code ROTATION_JDBC_URL}, {@code ROTATION_DB_USER}, {@code ROTATION_DB_PASSWORD},
 * {@code ROTATION_ENC_KEY}. Never prints any of those values or any decrypted plaintext — only row
 * counts and provider names.
 *
 * <p>Throwaway; not part of the permanent suite (same convention as {@code SecretKeyRotationJobCreator}
 * — not named {@code *Test} so Surefire's default discovery skips it; run explicitly via
 * {@code -Dtest=...}).
 */
class PostgresPasswordRotationVerifyJobCreator {

    private record Row(long id, String provider, String encryptedKey) {}

    @Test
    void newDbPasswordConnectsAndExistingSecretsStillDecrypt() throws Exception {
        String jdbcUrl = requireEnv("ROTATION_JDBC_URL");
        String dbUser = requireEnv("ROTATION_DB_USER");
        String dbPassword = requireEnv("ROTATION_DB_PASSWORD");
        String encKey = requireEnv("ROTATION_ENC_KEY");

        SecretEncryptionService encryptionService = new SecretEncryptionService(encKey, Set.of());

        List<Row> rows = new ArrayList<>();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, dbUser, dbPassword);
                PreparedStatement select =
                        conn.prepareStatement("SELECT id, provider, encrypted_key FROM user_secrets ORDER BY id");
                ResultSet rs = select.executeQuery()) {
            while (rs.next()) {
                rows.add(new Row(rs.getLong("id"), rs.getString("provider"), rs.getString("encrypted_key")));
            }
        }

        assertTrue(!rows.isEmpty(), "Expected at least one existing user_secrets row to verify against");

        for (Row row : rows) {
            // Throws IllegalStateException on failure; a clean return proves the row is intact.
            encryptionService.decrypt(row.encryptedKey());
        }

        System.out.println("\n=== POSTGRES PASSWORD ROTATION VERIFY: connected with new password over TCP, "
                + rows.size() + " existing user_secrets row(s) still decrypt correctly (providers: "
                + rows.stream().map(Row::provider).distinct().toList() + ") ===\n");
    }

    private static String requireEnv(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Set " + name + " before running this one-shot check.");
        }
        return value;
    }
}
