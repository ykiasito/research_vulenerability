package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.vulncheck.app.entity.User;
import com.vulncheck.app.entity.UserSecret;
import com.vulncheck.app.repository.UserRepository;
import com.vulncheck.app.repository.UserSecretRepository;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Unit coverage for {@link UserApiKeyService#getAdminNvdApiKey()} (task-backlog item 142) — the
 * three ways it must fall back to {@link Optional#empty()} without throwing (matching the
 * existing "works fine unkeyed, just slower" design), plus the happy path where an admin NVD key
 * is actually resolved. {@link #getNvdApiKey(Long)} itself is exercised indirectly through {@code
 * getAdminNvdApiKey()}; it has no other test coverage to duplicate here.
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
}
