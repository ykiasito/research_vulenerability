package com.vulncheck.app.service;

import com.vulncheck.app.entity.UserSecret;
import com.vulncheck.app.repository.UserSecretRepository;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Resolves a user's own decrypted provider API key, on demand, for exactly the request that
 * needs it — never cached or held longer than one call. Backs Stage1 Tier2/Tier3 and Stage4,
 * which must use each job's owner's own Claude key (per the plan's per-user-keys design), not a
 * shared server-wide key.
 */
@Service
@RequiredArgsConstructor
public class UserApiKeyService {

    private final UserSecretRepository userSecretRepository;
    private final SecretEncryptionService secretEncryptionService;

    public Optional<String> getClaudeApiKey(Long userId) {
        return userSecretRepository.findByUserIdAndProvider(userId, UserSecret.PROVIDER_CLAUDE)
                .map(secret -> secretEncryptionService.decrypt(secret.getEncryptedKey()));
    }

    /** NVD keys are free (no billing) and only unlock a higher client-side rate limit, so unlike
     *  the Claude key there's no cost reason to gate this — it's simply "does this user have one
     *  registered", used by whichever job/admin action happens to be running as them. */
    public Optional<String> getNvdApiKey(Long userId) {
        return userSecretRepository.findByUserIdAndProvider(userId, UserSecret.PROVIDER_NVD)
                .map(secret -> secretEncryptionService.decrypt(secret.getEncryptedKey()));
    }
}
