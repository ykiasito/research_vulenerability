package com.vulncheck.app.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * One-shot re-encryption of every {@code user_secrets.encrypted_key} row from the retiring
 * encryption key to the newly rotated one (infra-rollout-plan.md §2 item 4b(d), the "既存キーを
 * 再暗号化" option). Deliberately plain JDBC, no Spring context: booting a second full app instance
 * against the same live database this backend is already connected to would also fire its
 * {@code @Scheduled} sync jobs (Ghsa/Csaf/CveOrg) a second time concurrently, which this migration
 * has no need to risk.
 *
 * <p>Reads both keys and the DB connection info from env vars only (never hardcoded, never
 * committed anywhere) so neither key literal ever appears in source: {@code ROTATION_OLD_KEY},
 * {@code ROTATION_NEW_KEY}, {@code ROTATION_JDBC_URL}, {@code ROTATION_DB_USER},
 * {@code ROTATION_DB_PASSWORD}. Uses {@link SecretEncryptionService}'s package-private
 * constructor to deliberately bypass the retired-key deny-list — {@code ROTATION_OLD_KEY} is
 * expected to BE a retired default here, that's the point of running this at all.
 *
 * <p>Self-verifies each row by decrypting the freshly-written ciphertext with the new key and
 * comparing it to the original plaintext before committing — neither value is ever printed, only
 * row counts. Throwaway; not part of the permanent suite (same convention as
 * {@code ReverifyJobCreator}/{@code FpCheckJobCreator} — not named {@code *Test} so Surefire's
 * default discovery skips it; run explicitly via {@code -Dtest=...}).
 */
class SecretKeyRotationJobCreator {

    private record Row(long id, long userId, String provider, String encryptedKey) {}

    @Test
    void reencryptAllUserSecretsFromOldKeyToNewKey() throws Exception {
        String oldKey = requireEnv("ROTATION_OLD_KEY");
        String newKey = requireEnv("ROTATION_NEW_KEY");
        String jdbcUrl = requireEnv("ROTATION_JDBC_URL");
        String dbUser = requireEnv("ROTATION_DB_USER");
        String dbPassword = requireEnv("ROTATION_DB_PASSWORD");

        SecretEncryptionService oldKeyService = new SecretEncryptionService(oldKey, Set.of());
        SecretEncryptionService newKeyService = new SecretEncryptionService(newKey, Set.of());

        try (Connection conn = DriverManager.getConnection(jdbcUrl, dbUser, dbPassword)) {
            conn.setAutoCommit(false);

            List<Row> rows = new ArrayList<>();
            try (PreparedStatement select = conn.prepareStatement(
                            "SELECT id, user_id, provider, encrypted_key FROM user_secrets ORDER BY id");
                    ResultSet rs = select.executeQuery()) {
                while (rs.next()) {
                    rows.add(new Row(
                            rs.getLong("id"),
                            rs.getLong("user_id"),
                            rs.getString("provider"),
                            rs.getString("encrypted_key")));
                }
            }

            int migrated = 0;
            try (PreparedStatement update =
                    conn.prepareStatement("UPDATE user_secrets SET encrypted_key = ? WHERE id = ?")) {
                for (Row row : rows) {
                    String plaintextBefore = oldKeyService.decrypt(row.encryptedKey(), row.userId(), row.provider());
                    String reencrypted = newKeyService.encrypt(plaintextBefore, row.userId(), row.provider());

                    update.setString(1, reencrypted);
                    update.setLong(2, row.id());
                    update.executeUpdate();

                    // Self-verify the round trip without ever printing either value.
                    String plaintextAfter = newKeyService.decrypt(reencrypted, row.userId(), row.provider());
                    assertEquals(
                            plaintextBefore, plaintextAfter, "Round-trip mismatch for user_secrets.id=" + row.id());
                    migrated++;
                }
            }

            conn.commit();
            System.out.println("\n=== SECRET KEY ROTATION: re-encrypted " + migrated + " of " + rows.size()
                    + " user_secrets row(s) from old key to new key ===\n");
            assertEquals(rows.size(), migrated, "Not all rows were migrated");
        }
    }

    /**
     * Independent post-migration check, meant to be run by hand (separately from
     * {@link #reencryptAllUserSecretsFromOldKeyToNewKey()}, after it has already committed) as
     * belt-and-suspenders on top of that method's own in-transaction round-trip assertion: confirms
     * the old key genuinely can no longer decrypt what's now in the table, and the new key still
     * can. Same env vars as above; never prints either plaintext or ciphertext.
     */
    @Test
    void verifyOldKeyNoLongerDecryptsMigratedRowsButNewKeyDoes() throws Exception {
        String oldKey = requireEnv("ROTATION_OLD_KEY");
        String newKey = requireEnv("ROTATION_NEW_KEY");
        String jdbcUrl = requireEnv("ROTATION_JDBC_URL");
        String dbUser = requireEnv("ROTATION_DB_USER");
        String dbPassword = requireEnv("ROTATION_DB_PASSWORD");

        SecretEncryptionService oldKeyService = new SecretEncryptionService(oldKey, Set.of());
        SecretEncryptionService newKeyService = new SecretEncryptionService(newKey, Set.of());

        List<Row> rows = new ArrayList<>();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, dbUser, dbPassword);
                PreparedStatement select = conn.prepareStatement(
                        "SELECT id, user_id, provider, encrypted_key FROM user_secrets ORDER BY id");
                ResultSet rs = select.executeQuery()) {
            while (rs.next()) {
                rows.add(new Row(
                        rs.getLong("id"),
                        rs.getLong("user_id"),
                        rs.getString("provider"),
                        rs.getString("encrypted_key")));
            }
        }

        for (Row row : rows) {
            // Decrypting now-migrated ciphertext with the OLD key must fail (wrong AES-GCM key/tag)
            // — this is what proves the row was actually re-encrypted, not left untouched.
            assertThrows(
                    IllegalStateException.class,
                    () -> oldKeyService.decrypt(row.encryptedKey(), row.userId(), row.provider()),
                    "Old key should no longer decrypt user_secrets.id=" + row.id() + " after rotation");

            // The new key must decrypt it without throwing.
            newKeyService.decrypt(row.encryptedKey(), row.userId(), row.provider());
        }

        System.out.println("\n=== SECRET KEY ROTATION VERIFY: checked " + rows.size()
                + " row(s) — old key rejected, new key accepted ===\n");
    }

    private static String requireEnv(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Set " + name + " before running this one-shot migration.");
        }
        return value;
    }
}
