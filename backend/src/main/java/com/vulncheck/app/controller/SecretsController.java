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
public class SecretsController {

    // Matches the user_secrets.provider CHECK constraint (V1__init.sql) — validated here too so
    // a bad provider value fails with a friendly form error instead of a DB constraint exception.
    private static final Set<String> VALID_PROVIDERS = Set.of(UserSecret.PROVIDER_CLAUDE, UserSecret.PROVIDER_NVD);

    private final UserRepository userRepository;
    private final UserSecretRepository userSecretRepository;
    private final SecretEncryptionService secretEncryptionService;

    @GetMapping("/settings/secrets")
    public String list(@AuthenticationPrincipal UserDetails userDetails, Model model) {
        User user = currentUser(userDetails);
        Map<String, UserSecret> byProvider = userSecretRepository.findByUserId(user.getId()).stream()
                .collect(Collectors.toMap(UserSecret::getProvider, s -> s));

        model.addAttribute("claudeConfigured", byProvider.containsKey(UserSecret.PROVIDER_CLAUDE));
        model.addAttribute("claudeMasked", maskOrNull(byProvider.get(UserSecret.PROVIDER_CLAUDE)));
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
        String encrypted = secretEncryptionService.encrypt(form.getApiKey().strip());
        userSecretRepository.upsert(user.getId(), form.getProvider(), encrypted);

        return "redirect:/settings/secrets?saved";
    }

    @PostMapping("/settings/secrets/{provider}/delete")
    public String delete(@AuthenticationPrincipal UserDetails userDetails, @PathVariable String provider) {
        User user = currentUser(userDetails);
        userSecretRepository.deleteByUserIdAndProvider(user.getId(), provider);
        return "redirect:/settings/secrets?deleted";
    }

    private String maskOrNull(UserSecret secret) {
        if (secret == null) {
            return null;
        }
        String plaintext = secretEncryptionService.decrypt(secret.getEncryptedKey());
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
