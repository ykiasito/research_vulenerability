package com.vulncheck.app.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import com.vulncheck.app.entity.User;
import com.vulncheck.app.entity.UserSecret;
import com.vulncheck.app.repository.UserRepository;
import com.vulncheck.app.repository.UserSecretRepository;
import com.vulncheck.app.service.SecretEncryptionService;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;

/**
 * {@link SecretsController#list} — a plain Mockito unit test invoking the controller method
 * directly, same convention as {@code JobControllerTest} (this codebase has no MockMvc/@WebMvcTest
 * infrastructure for most controllers).
 *
 * <p>Task-backlog item 279 (senior-reviewer REVISE on PR#188): before this class existed,
 * {@link SecretsController#list} had no test coverage at all, and a decrypt failure (e.g. a key
 * registered before the 2026-08-28 encryption key rotation — same root cause as task-backlog item
 * 248) propagated straight out of {@code maskOrNull}, making {@code GET /settings/secrets} itself
 * throw an unhandled exception — the exact screen the affected user needs to open to fix the
 * problem (delete and re-register the key). These tests confirm the page renders successfully
 * (never throws) regardless of which provider(s), if any, fail to decrypt.
 */
@ExtendWith(MockitoExtension.class)
class SecretsControllerTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private UserSecretRepository userSecretRepository;
    @Mock
    private SecretEncryptionService secretEncryptionService;

    private SecretsController newController() {
        return new SecretsController(userRepository, userSecretRepository, secretEncryptionService);
    }

    private User user(Long id, String email) {
        User user = new User();
        user.setId(id);
        user.setEmail(email);
        user.setPasswordHash("hash");
        return user;
    }

    private UserDetails userDetails(String email) {
        return org.springframework.security.core.userdetails.User
                .withUsername(email).password("x").roles("USER").build();
    }

    private UserSecret secret(Long userId, String provider, String encryptedKey) {
        return new UserSecret(1L, userId, provider, encryptedKey, null);
    }

    /** Same masking formula as {@link SecretsController#maskOrNull} itself, so the happy-path
     *  test's expected value can never silently drift from that method's own logic -- this test's
     *  job is to confirm decrypt-success behavior is unchanged by this task's fail-soft addition,
     *  not to duplicate/hardcode the masking format's own exact bullet count as a magic string. */
    private String expectedMask(String plaintext) {
        int visibleTail = Math.min(4, plaintext.length());
        return "•".repeat(Math.max(0, plaintext.length() - visibleTail)) + plaintext.substring(plaintext.length() - visibleTail);
    }

    @Test
    void listRendersMaskedKeysWhenBothProvidersDecryptSuccessfully() {
        User owner = user(1L, "owner@example.com");
        UserSecret claudeSecret = secret(1L, UserSecret.PROVIDER_CLAUDE, "encrypted-claude");
        UserSecret nvdSecret = secret(1L, UserSecret.PROVIDER_NVD, "encrypted-nvd");
        String claudePlaintext = "sk-ant-abcd1234";
        String nvdPlaintext = "11111111-2222-3333-4444-555555555555";

        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(owner));
        when(userSecretRepository.findByUserId(1L)).thenReturn(List.of(claudeSecret, nvdSecret));
        when(secretEncryptionService.decrypt("encrypted-claude", 1L, UserSecret.PROVIDER_CLAUDE))
                .thenReturn(claudePlaintext);
        when(secretEncryptionService.decrypt("encrypted-nvd", 1L, UserSecret.PROVIDER_NVD))
                .thenReturn(nvdPlaintext);

        Model model = new ExtendedModelMap();
        String view = newController().list(userDetails("owner@example.com"), model);

        assertThat(view).isEqualTo("settings/secrets");
        assertThat(model.getAttribute("claudeConfigured")).isEqualTo(true);
        assertThat(model.getAttribute("claudeMasked")).isEqualTo(expectedMask(claudePlaintext));
        assertThat(model.getAttribute("nvdConfigured")).isEqualTo(true);
        assertThat(model.getAttribute("nvdMasked")).isEqualTo(expectedMask(nvdPlaintext));
    }

    @Test
    void listShowsAReRegisterPlaceholderWhenTheClaudeKeyFailsToDecryptInsteadOfThrowing() {
        User owner = user(1L, "owner@example.com");
        UserSecret claudeSecret = secret(1L, UserSecret.PROVIDER_CLAUDE, "encrypted-claude");

        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(owner));
        when(userSecretRepository.findByUserId(1L)).thenReturn(List.of(claudeSecret));
        when(secretEncryptionService.decrypt("encrypted-claude", 1L, UserSecret.PROVIDER_CLAUDE))
                .thenThrow(new IllegalStateException("Failed to decrypt secret"));

        Model model = new ExtendedModelMap();
        String view = newController().list(userDetails("owner@example.com"), model);

        assertThat(view).isEqualTo("settings/secrets");
        assertThat(model.getAttribute("claudeConfigured")).isEqualTo(true);
        assertThat(model.getAttribute("claudeMasked")).isEqualTo("復号できません（再登録してください）");
    }

    @Test
    void listShowsAReRegisterPlaceholderWhenTheNvdKeyFailsToDecryptInsteadOfThrowing() {
        User owner = user(1L, "owner@example.com");
        UserSecret nvdSecret = secret(1L, UserSecret.PROVIDER_NVD, "encrypted-nvd");

        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(owner));
        when(userSecretRepository.findByUserId(1L)).thenReturn(List.of(nvdSecret));
        when(secretEncryptionService.decrypt("encrypted-nvd", 1L, UserSecret.PROVIDER_NVD))
                .thenThrow(new IllegalStateException("Failed to decrypt secret"));

        Model model = new ExtendedModelMap();
        String view = newController().list(userDetails("owner@example.com"), model);

        assertThat(view).isEqualTo("settings/secrets");
        assertThat(model.getAttribute("nvdConfigured")).isEqualTo(true);
        assertThat(model.getAttribute("nvdMasked")).isEqualTo("復号できません（再登録してください）");
    }

    @Test
    void listRendersSuccessfullyWhenBothProvidersFailToDecrypt() {
        // The scenario item 279 itself is named after: a user whose keys were both registered
        // before the 2026-08-28 encryption key rotation must still be able to open this exact page
        // to fix it (delete and re-register), not get locked out by an unhandled exception.
        User owner = user(1L, "owner@example.com");
        UserSecret claudeSecret = secret(1L, UserSecret.PROVIDER_CLAUDE, "encrypted-claude");
        UserSecret nvdSecret = secret(1L, UserSecret.PROVIDER_NVD, "encrypted-nvd");

        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(owner));
        when(userSecretRepository.findByUserId(1L)).thenReturn(List.of(claudeSecret, nvdSecret));
        when(secretEncryptionService.decrypt("encrypted-claude", 1L, UserSecret.PROVIDER_CLAUDE))
                .thenThrow(new IllegalStateException("Failed to decrypt secret"));
        when(secretEncryptionService.decrypt("encrypted-nvd", 1L, UserSecret.PROVIDER_NVD))
                .thenThrow(new IllegalStateException("Failed to decrypt secret"));

        Model model = new ExtendedModelMap();
        String view = newController().list(userDetails("owner@example.com"), model);

        assertThat(view).isEqualTo("settings/secrets");
        assertThat(model.getAttribute("claudeMasked")).isEqualTo("復号できません（再登録してください）");
        assertThat(model.getAttribute("nvdMasked")).isEqualTo("復号できません（再登録してください）");
    }

    @Test
    void listLeavesMaskedAttributesNullWhenNeitherProviderIsConfigured() {
        User owner = user(1L, "owner@example.com");

        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(owner));
        when(userSecretRepository.findByUserId(1L)).thenReturn(List.of());

        Model model = new ExtendedModelMap();
        String view = newController().list(userDetails("owner@example.com"), model);

        assertThat(view).isEqualTo("settings/secrets");
        assertThat(model.getAttribute("claudeConfigured")).isEqualTo(false);
        assertThat(model.getAttribute("claudeMasked")).isNull();
        assertThat(model.getAttribute("nvdConfigured")).isEqualTo(false);
        assertThat(model.getAttribute("nvdMasked")).isNull();
    }
}
