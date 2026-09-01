package com.vulncheck.app.service;

import com.vulncheck.app.entity.UserSecret;
import com.vulncheck.app.repository.UserRepository;
import com.vulncheck.app.repository.UserSecretRepository;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Resolves a user's own decrypted provider API key, on demand, for exactly the request that
 * needs it — never cached or held longer than one call. Backs Stage1 Tier2/Tier3 and Stage4,
 * which must use each job's owner's own Claude key (per the plan's per-user-keys design), not a
 * shared server-wide key.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserApiKeyService {

    private final UserSecretRepository userSecretRepository;
    private final SecretEncryptionService secretEncryptionService;
    private final UserRepository userRepository;

    /** Same {@code ADMIN_EMAIL} env var {@link AppUserDetailsService} uses to grant ROLE_ADMIN —
     *  see application.yml. Unset/blank means "no admin", not an error. */
    @Value("${app.admin-email:}")
    private String adminEmail;

    public Optional<String> getClaudeApiKey(Long userId) {
        return userSecretRepository.findByUserIdAndProvider(userId, UserSecret.PROVIDER_CLAUDE)
                .map(secret -> secretEncryptionService.decrypt(
                        secret.getEncryptedKey(), userId, UserSecret.PROVIDER_CLAUDE));
    }

    /** NVD keys are free (no billing) and only unlock a higher client-side rate limit, so unlike
     *  the Claude key there's no cost reason to gate this — it's simply "does this user have one
     *  registered", used by whichever job/admin action happens to be running as them. */
    public Optional<String> getNvdApiKey(Long userId) {
        return userSecretRepository.findByUserIdAndProvider(userId, UserSecret.PROVIDER_NVD)
                .map(secret -> secretEncryptionService.decrypt(
                        secret.getEncryptedKey(), userId, UserSecret.PROVIDER_NVD));
    }

    /**
     * Resolves the admin user's own registered NVD key for non-interactive callers that have no
     * logged-in user context of their own (task-backlog item 142) — currently only {@link
     * CpeDictionaryScheduledResync}, which otherwise runs the weekly full CPE resync unkeyed and
     * so rate-limited to 5 req/30s (~10x slower than a keyed run).
     *
     * <p>Falls back to {@link Optional#empty()}, matching the existing "works fine without a key,
     * just slower" design, for every way this can be unconfigured: {@code ADMIN_EMAIL} unset or
     * blank, no user registered under that email, or that user simply hasn't registered an NVD
     * key. None of these are errors — an operator who hasn't set both up yet just gets the
     * unkeyed (slower) behavior that already existed before this method.
     *
     * <p>Also falls back to {@link Optional#empty()} (logging a warning rather than throwing) if
     * the lookup or decryption itself fails — e.g. a transient {@code DataAccessException} from
     * {@link UserRepository#findByEmail} or a decrypt failure from {@link
     * SecretEncryptionService#decrypt} (key rotation, AAD mismatch, row corruption). This method's
     * only caller ({@code CpeDictionaryScheduledResync}) runs unattended on a Sunday-night cron,
     * so a transient failure here must degrade to the unkeyed path rather than abort the caller
     * before it ever reaches its own guard-release logic (task-backlog item 143).
     */
    public Optional<String> getAdminNvdApiKey() {
        if (adminEmail == null || adminEmail.isBlank()) {
            return Optional.empty();
        }
        try {
            return userRepository.findByEmail(adminEmail)
                    .flatMap(user -> getNvdApiKey(user.getId()));
        } catch (Exception e) {
            log.warn("Failed to resolve the admin's NVD key — falling back to unkeyed", e);
            return Optional.empty();
        }
    }
}
