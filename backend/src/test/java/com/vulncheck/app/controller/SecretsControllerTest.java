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
 * (never throws) regardless of whether the provider it still supports fails to decrypt.
 *
 * <p>Closed-mode backlog item 360 Step2 (2026-09-06 master merge): this class arrived from master,
 * which still lets a user register a Claude key. Closed-mode's own B2 cleanup permanently stripped
 * the Claude key UI out of {@link SecretsController#list} — it never sets a {@code claudeConfigured}
 * /{@code claudeMasked} model attribute at all now, regardless of what {@code user_secrets} rows
 * happen to exist (see that method's own {@code VALID_PROVIDERS} field) — so master's Claude-related
 * fixtures/assertions were adapted or dropped here rather than carried over verbatim: {@code
 * listShowsAReRegisterPlaceholderWhenTheClaudeKeyFailsToDecryptInsteadOfThrowing} (Claude-only
 * scenario, no closed-mode equivalent) and {@code listRendersSuccessfullyWhenBothProvidersFailToDecrypt}
 * (became a duplicate of the NVD-only decrypt-failure test below once the Claude half was removed)
 * were both dropped; the rest were narrowed to the NVD provider only.
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
    void listRendersMaskedKeyWhenNvdProviderDecryptsSuccessfully() {
        User owner = user(1L, "owner@example.com");
        UserSecret nvdSecret = secret(1L, UserSecret.PROVIDER_NVD, "encrypted-nvd");
        String nvdPlaintext = "11111111-2222-3333-4444-555555555555";

        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(owner));
        when(userSecretRepository.findByUserId(1L)).thenReturn(List.of(nvdSecret));
        when(secretEncryptionService.decrypt("encrypted-nvd", 1L, UserSecret.PROVIDER_NVD))
                .thenReturn(nvdPlaintext);

        Model model = new ExtendedModelMap();
        String view = newController().list(userDetails("owner@example.com"), model);

        assertThat(view).isEqualTo("settings/secrets");
        assertThat(model.getAttribute("nvdConfigured")).isEqualTo(true);
        assertThat(model.getAttribute("nvdMasked")).isEqualTo(expectedMask(nvdPlaintext));
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
    void listLeavesMaskedAttributeNullWhenNvdProviderIsNotConfigured() {
        User owner = user(1L, "owner@example.com");

        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(owner));
        when(userSecretRepository.findByUserId(1L)).thenReturn(List.of());

        Model model = new ExtendedModelMap();
        String view = newController().list(userDetails("owner@example.com"), model);

        assertThat(view).isEqualTo("settings/secrets");
        assertThat(model.getAttribute("nvdConfigured")).isEqualTo(false);
        assertThat(model.getAttribute("nvdMasked")).isNull();
    }
}
