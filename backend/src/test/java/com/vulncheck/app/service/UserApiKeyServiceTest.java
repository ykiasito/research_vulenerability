package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.vulncheck.app.entity.User;
import com.vulncheck.app.entity.UserSecret;
import com.vulncheck.app.repository.UserRepository;
import com.vulncheck.app.repository.UserSecretRepository;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Unit coverage for {@link UserApiKeyService#getAdminNvdApiKey()} (task-backlog item 142) — the
 * three ways it must fall back to {@link Optional#empty()} without throwing (matching the
 * existing "works fine unkeyed, just slower" design), plus the happy path where an admin NVD key
 * is actually resolved. Also covers {@link UserApiKeyService#getNvdApiKey(Long)}'s own fail-soft
 * decrypt behavior and {@link UserApiKeyService#getClaudeApiKey(Long)}'s intentional
 * fail-hard behavior directly (task-backlog item 248).
 */
class UserApiKeyServiceTest {

    private final UserSecretRepository userSecretRepository = mock(UserSecretRepository.class);
    private final SecretEncryptionService secretEncryptionService = mock(SecretEncryptionService.class);
    private final UserRepository userRepository = mock(UserRepository.class);
    private final UserApiKeyService service =
            new UserApiKeyService(userSecretRepository, secretEncryptionService, userRepository);

    @Test
    void getAdminNvdApiKeyReturnsEmptyWhenAdminEmailIsUnset() {
        ReflectionTestUtils.setField(service, "adminEmail", "");

        assertThat(service.getAdminNvdApiKey()).isEmpty();
        verify(userRepository, never()).findByEmail(org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void getAdminNvdApiKeyReturnsEmptyWhenAdminEmailIsBlank() {
        ReflectionTestUtils.setField(service, "adminEmail", "   ");

        assertThat(service.getAdminNvdApiKey()).isEmpty();
        verify(userRepository, never()).findByEmail(org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void getAdminNvdApiKeyReturnsEmptyWhenNoUserIsRegisteredForTheAdminEmail() {
        ReflectionTestUtils.setField(service, "adminEmail", "admin@example.com");
        when(userRepository.findByEmail("admin@example.com")).thenReturn(Optional.empty());

        assertThat(service.getAdminNvdApiKey()).isEmpty();
    }

    @Test
    void getAdminNvdApiKeyReturnsEmptyWhenTheAdminUserHasNoNvdKeyRegistered() {
        ReflectionTestUtils.setField(service, "adminEmail", "admin@example.com");
        User admin = new User(42L, "admin@example.com", "hash", null);
        when(userRepository.findByEmail("admin@example.com")).thenReturn(Optional.of(admin));
        when(userSecretRepository.findByUserIdAndProvider(42L, UserSecret.PROVIDER_NVD)).thenReturn(Optional.empty());

        assertThat(service.getAdminNvdApiKey()).isEmpty();
    }

    @Test
    void getAdminNvdApiKeyReturnsEmptyWhenDecryptThrows() {
        // Regression test for task-backlog item 143: a decrypt failure (key rotation, AAD
        // mismatch, row corruption) must degrade to Optional.empty(), matching this method's own
        // javadoc contract, rather than propagate and abort CpeDictionaryScheduledResync before it
        // ever reaches syncAllAndRelease()'s guard-releasing finally block.
        ReflectionTestUtils.setField(service, "adminEmail", "admin@example.com");
        User admin = new User(42L, "admin@example.com", "hash", null);
        UserSecret secret = new UserSecret(1L, 42L, UserSecret.PROVIDER_NVD, "encrypted-blob", null);
        when(userRepository.findByEmail("admin@example.com")).thenReturn(Optional.of(admin));
        when(userSecretRepository.findByUserIdAndProvider(42L, UserSecret.PROVIDER_NVD))
                .thenReturn(Optional.of(secret));
        when(secretEncryptionService.decrypt("encrypted-blob", 42L, UserSecret.PROVIDER_NVD))
                .thenThrow(new IllegalStateException("Failed to decrypt secret"));

        assertThat(service.getAdminNvdApiKey()).isEmpty();
    }

    @Test
    void getAdminNvdApiKeyReturnsEmptyWhenTheUserLookupFails() {
        // Regression test for task-backlog item 143: a transient DB failure while resolving the
        // admin user must degrade to Optional.empty() the same way, not propagate.
        ReflectionTestUtils.setField(service, "adminEmail", "admin@example.com");
        when(userRepository.findByEmail("admin@example.com"))
                .thenThrow(new DataAccessResourceFailureException("DB unavailable"));

        assertThat(service.getAdminNvdApiKey()).isEmpty();
    }

    @Test
    void getAdminNvdApiKeyResolvesTheAdminUsersDecryptedNvdKey() {
        ReflectionTestUtils.setField(service, "adminEmail", "admin@example.com");
        User admin = new User(42L, "admin@example.com", "hash", null);
        UserSecret secret = new UserSecret(1L, 42L, UserSecret.PROVIDER_NVD, "encrypted-blob", null);
        when(userRepository.findByEmail("admin@example.com")).thenReturn(Optional.of(admin));
        when(userSecretRepository.findByUserIdAndProvider(42L, UserSecret.PROVIDER_NVD))
                .thenReturn(Optional.of(secret));
        when(secretEncryptionService.decrypt("encrypted-blob", 42L, UserSecret.PROVIDER_NVD))
                .thenReturn("decrypted-nvd-key");

        assertThat(service.getAdminNvdApiKey()).contains("decrypted-nvd-key");
    }

    @Test
    void getAdminNvdApiKeyResolvesTheAdminUserWhenAdminEmailDiffersOnlyInAsciiCaseFromStoredEmail() {
        // Regression test for task-backlog item 148 REVISE R3: this method now looks the admin
        // user up via findByEmail(adminEmail.toLowerCase(Locale.ROOT)) instead of the Postgres
        // upper()-based findByEmailIgnoreCase, so ADMIN_EMAIL config values that differ from the
        // (already-lowercased) stored row only in ASCII case must still resolve.
        ReflectionTestUtils.setField(service, "adminEmail", "Admin@Example.com");
        User admin = new User(42L, "admin@example.com", "hash", null);
        UserSecret secret = new UserSecret(1L, 42L, UserSecret.PROVIDER_NVD, "encrypted-blob", null);
        when(userRepository.findByEmail("admin@example.com")).thenReturn(Optional.of(admin));
        when(userSecretRepository.findByUserIdAndProvider(42L, UserSecret.PROVIDER_NVD))
                .thenReturn(Optional.of(secret));
        when(secretEncryptionService.decrypt("encrypted-blob", 42L, UserSecret.PROVIDER_NVD))
                .thenReturn("decrypted-nvd-key");

        assertThat(service.getAdminNvdApiKey()).contains("decrypted-nvd-key");
    }

    @Test
    void getAdminNvdApiKeyReturnsEmptyWhenNoRowExistsForTheNormalizedAdminEmail() {
        // Regression test for task-backlog item 148 REVISE R3, senior-reviewer item 6(a): the fix
        // replaced the Postgres upper()-based findByEmailIgnoreCase lookup (which folds Unicode
        // case variants such as long s U+017F "ſ" -> "S", so it would have wrongly resolved a
        // ſ-containing stored row as the admin) with an exact findByEmail(adminEmail.toLowerCase(
        // Locale.ROOT)) match. This test only exercises the exact-match query at the unit level —
        // Mockito can't reproduce Postgres's own upper() folding since the repository is mocked
        // here, so it can't show the vulnerable behavior directly. That folding behavior itself was
        // confirmed against a live Postgres instance separately (senior-reviewer, item 6(a)). What
        // this test does confirm: when no row exists for the exact normalized admin email, the
        // lookup returns empty rather than falling back to any case-insensitive match.
        ReflectionTestUtils.setField(service, "adminEmail", "admin@syscorp.com");
        when(userRepository.findByEmail("admin@syscorp.com")).thenReturn(Optional.empty());

        assertThat(service.getAdminNvdApiKey()).isEmpty();
    }

    @Test
    void getAdminNvdApiKeyResolvesTheAdminUserWhenAdminEmailDiffersOnlyInCaseSyscorpDomain() {
        // Senior-reviewer item 6(b): companion to the two tests above, confirming the ASCII-case
        // fold still resolves correctly on the same domain used in the Unicode-rejection test.
        ReflectionTestUtils.setField(service, "adminEmail", "Admin@Syscorp.com");
        User admin = new User(42L, "admin@syscorp.com", "hash", null);
        UserSecret secret = new UserSecret(1L, 42L, UserSecret.PROVIDER_NVD, "encrypted-blob", null);
        when(userRepository.findByEmail("admin@syscorp.com")).thenReturn(Optional.of(admin));
        when(userSecretRepository.findByUserIdAndProvider(42L, UserSecret.PROVIDER_NVD))
                .thenReturn(Optional.of(secret));
        when(secretEncryptionService.decrypt("encrypted-blob", 42L, UserSecret.PROVIDER_NVD))
                .thenReturn("decrypted-nvd-key");

        assertThat(service.getAdminNvdApiKey()).contains("decrypted-nvd-key");
    }

    @Test
    void getNvdApiKeyReturnsEmptyWhenDecryptThrows() {
        // Regression test for task-backlog item 248: a decrypt failure (e.g. AEADBadTagException
        // from a key registered before the 2026-08-28 encryption key rotation) must degrade to
        // Optional.empty() rather than propagate — the NVD key is only a rate-limit optimization,
        // and before this fix the exception aborted the entire pipeline (Stage1IdentificationService
        // / NvdVulnerabilitySource / NvdKeywordVulnerabilitySource / AdminController).
        UserSecret secret = new UserSecret(1L, 7L, UserSecret.PROVIDER_NVD, "encrypted-blob", null);
        when(userSecretRepository.findByUserIdAndProvider(7L, UserSecret.PROVIDER_NVD))
                .thenReturn(Optional.of(secret));
        when(secretEncryptionService.decrypt("encrypted-blob", 7L, UserSecret.PROVIDER_NVD))
                .thenThrow(new IllegalStateException("Failed to decrypt secret"));

        assertThat(service.getNvdApiKey(7L)).isEmpty();
    }

    @Test
    void getNvdApiKeyLogsAtWarnOnlyOnceThenDowngradesToDebugForTheSameUser() {
        // Task-backlog item 274: getNvdApiKey is called once per job item -- up to twice per item
        // across its several callers (Stage1IdentificationService's live CPE fallback,
        // NvdVulnerabilitySource's live CVE lookup) -- so a permanently-failing decrypt (e.g. a key
        // registered before the 2026-08-28 encryption key rotation, item 248) would otherwise log
        // the exact same WARN line up to 2,000 times for a single 1,000-item job. Confirms the
        // first failure for a given userId logs at WARN and every later one for that same userId
        // logs at DEBUG instead.
        UserSecret secret = new UserSecret(1L, 7L, UserSecret.PROVIDER_NVD, "encrypted-blob", null);
        when(userSecretRepository.findByUserIdAndProvider(7L, UserSecret.PROVIDER_NVD))
                .thenReturn(Optional.of(secret));
        when(secretEncryptionService.decrypt("encrypted-blob", 7L, UserSecret.PROVIDER_NVD))
                .thenThrow(new IllegalStateException("Failed to decrypt secret"));

        List<ILoggingEvent> events = captureLogEvents(() -> {
            assertThat(service.getNvdApiKey(7L)).isEmpty();
            assertThat(service.getNvdApiKey(7L)).isEmpty();
            assertThat(service.getNvdApiKey(7L)).isEmpty();
        });

        assertThat(events).hasSize(3);
        assertThat(events.get(0).getLevel()).isEqualTo(Level.WARN);
        assertThat(events.get(1).getLevel()).isEqualTo(Level.DEBUG);
        assertThat(events.get(2).getLevel()).isEqualTo(Level.DEBUG);
    }

    @Test
    void getNvdApiKeyTracksTheWarnedFlagPerUserIdIndependently() {
        // A different user's own first decrypt failure must still log at WARN even after another
        // user has already been warned -- the dedup is per-userId, not a single process-wide switch
        // that would silently hide a second, unrelated user's own first-time failure.
        UserSecret secretUserA = new UserSecret(1L, 7L, UserSecret.PROVIDER_NVD, "encrypted-blob-a", null);
        UserSecret secretUserB = new UserSecret(2L, 8L, UserSecret.PROVIDER_NVD, "encrypted-blob-b", null);
        when(userSecretRepository.findByUserIdAndProvider(7L, UserSecret.PROVIDER_NVD))
                .thenReturn(Optional.of(secretUserA));
        when(userSecretRepository.findByUserIdAndProvider(8L, UserSecret.PROVIDER_NVD))
                .thenReturn(Optional.of(secretUserB));
        when(secretEncryptionService.decrypt("encrypted-blob-a", 7L, UserSecret.PROVIDER_NVD))
                .thenThrow(new IllegalStateException("Failed to decrypt secret"));
        when(secretEncryptionService.decrypt("encrypted-blob-b", 8L, UserSecret.PROVIDER_NVD))
                .thenThrow(new IllegalStateException("Failed to decrypt secret"));

        List<ILoggingEvent> events = captureLogEvents(() -> {
            assertThat(service.getNvdApiKey(7L)).isEmpty();
            assertThat(service.getNvdApiKey(8L)).isEmpty();
        });

        assertThat(events).hasSize(2);
        assertThat(events).allSatisfy(event -> assertThat(event.getLevel()).isEqualTo(Level.WARN));
    }

    @Test
    void getNvdApiKeyLogsAtWarnAgainAfterAnInterveningSuccessClearsTheDedupFlag() {
        // REVISE round 2 (senior-reviewer 2026-09-04, PR#188): the catch block in getNvdApiKey
        // covers both a permanent decrypt failure AND a transient repository-layer exception, so
        // the dedup must only suppress repeats of the SAME ongoing failure episode -- not every
        // future failure for that user -- or a single transient blip that later resolves itself
        // would permanently downgrade a later, genuinely new (and actionable) decrypt failure to
        // DEBUG for the rest of the process's lifetime. Confirms a success between two failures
        // clears the flag, so the second failure logs at WARN again rather than DEBUG.
        UserSecret secret = new UserSecret(1L, 7L, UserSecret.PROVIDER_NVD, "encrypted-blob", null);
        when(userSecretRepository.findByUserIdAndProvider(7L, UserSecret.PROVIDER_NVD))
                .thenReturn(Optional.of(secret));
        when(secretEncryptionService.decrypt("encrypted-blob", 7L, UserSecret.PROVIDER_NVD))
                .thenThrow(new IllegalStateException("Failed to decrypt secret"))
                .thenReturn("decrypted-nvd-key")
                .thenThrow(new IllegalStateException("Failed to decrypt secret"));

        List<ILoggingEvent> events = captureLogEvents(() -> {
            assertThat(service.getNvdApiKey(7L)).isEmpty();
            assertThat(service.getNvdApiKey(7L)).contains("decrypted-nvd-key");
            assertThat(service.getNvdApiKey(7L)).isEmpty();
        });

        assertThat(events).hasSize(2);
        assertThat(events).allSatisfy(event -> assertThat(event.getLevel()).isEqualTo(Level.WARN));
    }

    /** Captures every log event {@code UserApiKeyService}'s own logger emits while {@code action}
     *  runs, temporarily lowering the logger to DEBUG (Spring Boot's default root level is INFO,
     *  which would otherwise silently drop the DEBUG-level events these tests need to see) and
     *  restoring both the original level and appender list afterward regardless of outcome. */
    private List<ILoggingEvent> captureLogEvents(Runnable action) {
        Logger logger = (Logger) LoggerFactory.getLogger(UserApiKeyService.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        Level originalLevel = logger.getLevel();
        logger.setLevel(Level.DEBUG);
        try {
            action.run();
        } finally {
            logger.detachAppender(appender);
            logger.setLevel(originalLevel);
        }
        return appender.list;
    }

    @Test
    void getClaudeApiKeyStillThrowsWhenDecryptFails() {
        // Task-backlog item 248 explicitly keeps getClaudeApiKey throwing on decrypt failure: the
        // Claude key gates real API spend/accuracy and a decrypt failure can also signal tampered
        // ciphertext, so it must not be silently swallowed like the NVD key above.
        UserSecret secret = new UserSecret(1L, 7L, UserSecret.PROVIDER_CLAUDE, "encrypted-blob", null);
        when(userSecretRepository.findByUserIdAndProvider(7L, UserSecret.PROVIDER_CLAUDE))
                .thenReturn(Optional.of(secret));
        when(secretEncryptionService.decrypt("encrypted-blob", 7L, UserSecret.PROVIDER_CLAUDE))
                .thenThrow(new IllegalStateException("Failed to decrypt secret"));

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> service.getClaudeApiKey(7L))
                .isInstanceOf(IllegalStateException.class);
    }
}
