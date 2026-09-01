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
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Unit coverage for {@link UserApiKeyService#getAdminNvdApiKey()} (task-backlog item 142) — the
 * three ways it must fall back to {@link Optional#empty()} without throwing (matching the
 * existing "works fine unkeyed, just slower" design), plus the happy path where an admin NVD key
 * is actually resolved. {@link #getClaudeApiKey(Long)}/{@link #getNvdApiKey(Long)} themselves are
 * exercised indirectly through {@code getAdminNvdApiKey()}; they have no other test coverage to
 * duplicate here.
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
}
