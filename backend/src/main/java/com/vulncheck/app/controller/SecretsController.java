package com.vulncheck.app.controller;

import com.vulncheck.app.entity.User;
import com.vulncheck.app.entity.UserSecret;
import com.vulncheck.app.repository.UserRepository;
import com.vulncheck.app.repository.UserSecretRepository;
import com.vulncheck.app.service.SecretEncryptionService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

/**
 * Per-user API key management ("設定画面: プロバイダごとのシークレットキー登録" in the plan).
 * Keys are never redisplayed in full after saving — only a masked hint decrypted momentarily for
 * this same authenticated user's own render, matching {@link SecretEncryptionService}'s posture
 * that only this app (holding the shared encryption key) can ever recover the plaintext.
 */
@Controller
@RequiredArgsConstructor
@Slf4j
public class SecretsController {

    // Matches the user_secrets.provider CHECK constraint (V1__init.sql) — validated here too so
    // a bad provider value fails with a friendly form error instead of a DB constraint exception.
    // Closed-mode B2 (docs/spec/closed-mode-plan.md §9-2) removed the only reader of a Claude
    // key (UserApiKeyService#getClaudeApiKey), so this UI no longer offers registering one —
    // see UserApiKeyService's own javadoc for why UserSecret.PROVIDER_CLAUDE itself is untouched.
    private static final Set<String> VALID_PROVIDERS = Set.of(UserSecret.PROVIDER_NVD);

    private final UserRepository userRepository;
    private final UserSecretRepository userSecretRepository;
    private final SecretEncryptionService secretEncryptionService;

    @GetMapping("/settings/secrets")
    public String list(@AuthenticationPrincipal UserDetails userDetails, Model model) {
        User user = currentUser(userDetails);
        Map<String, UserSecret> byProvider = userSecretRepository.findByUserId(user.getId()).stream()
                .collect(Collectors.toMap(UserSecret::getProvider, s -> s));

        model.addAttribute("nvdConfigured", byProvider.containsKey(UserSecret.PROVIDER_NVD));
        model.addAttribute("nvdMasked", maskOrNull(byProvider.get(UserSecret.PROVIDER_NVD)));

        if (!model.containsAttribute("secretForm")) {
            model.addAttribute("secretForm", new SecretForm());
        }
        return "settings/secrets";
    }

    @PostMapping("/settings/secrets")
    public String save(@AuthenticationPrincipal UserDetails userDetails,
                        @Valid @ModelAttribute("secretForm") SecretForm form,
                        BindingResult bindingResult,
                        Model model) {
        if (!VALID_PROVIDERS.contains(form.getProvider())) {
            bindingResult.rejectValue("provider", "invalid", "不正なプロバイダーです。");
        }

        if (bindingResult.hasErrors()) {
            return list(userDetails, model);
        }

        User user = currentUser(userDetails);
        String encrypted = secretEncryptionService.encrypt(form.getApiKey().strip(), user.getId(), form.getProvider());
        userSecretRepository.upsert(user.getId(), form.getProvider(), encrypted);

        return "redirect:/settings/secrets?saved";
    }

    @PostMapping("/settings/secrets/{provider}/delete")
    public String delete(@AuthenticationPrincipal UserDetails userDetails, @PathVariable String provider) {
        User user = currentUser(userDetails);
        userSecretRepository.deleteByUserIdAndProvider(user.getId(), provider);
        return "redirect:/settings/secrets?deleted";
    }

    /** Placeholder shown in the provider table cell in place of a masked key when decryption fails
     *  (task-backlog item 279) — e.g. a key registered before the 2026-08-28 encryption key
     *  rotation (see task-backlog item 248's own note on the same root cause). Deliberately says
     *  "re-register" rather than anything more technical: this is the exact screen the affected
     *  user needs to reach to fix it themselves, by deleting and re-saving the key. */
    private static final String DECRYPT_FAILED_PLACEHOLDER = "復号できません（再登録してください）";

    /**
     * Never lets a decrypt failure escape to {@link #list}'s caller (task-backlog item 279,
     * senior-reviewer REVISE on PR#188): before this, an undecryptable key (e.g. one registered
     * before the 2026-08-28 encryption key rotation — same root cause as task-backlog item 248's
     * {@code UserApiKeyService#getNvdApiKey} fix) made {@code GET /settings/secrets} itself throw an
     * unhandled exception, since {@link #list} calls this once per configured provider (Claude/NVD).
     * That's the exact screen the affected user needs to open to fix the problem (delete and
     * re-register the key) — so failing the whole page over it locked them out of their own fix.
     * Falls back to {@link #DECRYPT_FAILED_PLACEHOLDER} instead, logging the failure at WARN with
     * only {@code userId}/{@code provider} (never the ciphertext, key material, or exception
     * message) so an operator can still notice the pattern without any secret material reaching the
     * logs.
     */
    private String maskOrNull(UserSecret secret) {
        if (secret == null) {
            return null;
        }
        String plaintext;
        try {
            plaintext = secretEncryptionService.decrypt(secret.getEncryptedKey(), secret.getUserId(), secret.getProvider());
        } catch (Exception e) {
            log.warn("Failed to decrypt {} secret for userId={} while rendering /settings/secrets "
                            + "-- showing a re-register placeholder instead of failing the whole page",
                    secret.getProvider(), secret.getUserId());
            return DECRYPT_FAILED_PLACEHOLDER;
        }
        int visibleTail = Math.min(4, plaintext.length());
        return "•".repeat(Math.max(0, plaintext.length() - visibleTail)) + plaintext.substring(plaintext.length() - visibleTail);
    }

    private User currentUser(UserDetails userDetails) {
        return userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new IllegalStateException("Authenticated user not found: " + userDetails.getUsername()));
    }

    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SecretForm {

        @NotBlank
        private String provider;

        @NotBlank
        private String apiKey;
    }
}
