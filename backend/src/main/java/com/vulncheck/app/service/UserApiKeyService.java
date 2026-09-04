package com.vulncheck.app.service;

import com.vulncheck.app.entity.User;
import com.vulncheck.app.entity.UserSecret;
import com.vulncheck.app.repository.UserRepository;
import com.vulncheck.app.repository.UserSecretRepository;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
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

    /**
     * Task-backlog item 274: {@link #getNvdApiKey(Long)} is called once per job item (up to twice
     * — {@code Stage1IdentificationService}'s live CPE fallback and {@code
     * NvdVulnerabilitySource}'s live CVE lookup each call it independently for the same item), so a
     * user whose NVD key permanently fails to decrypt (e.g. registered before the 2026-08-28
     * encryption key rotation — item 248) would otherwise log the exact same WARN line up to 2,000
     * times for a single 1,000-item job. Tracks which {@code userId}s currently have an
     * unacknowledged failure already logged at WARN, process-wide (not per-job — simpler). {@link
     * #getNvdApiKey(Long)} itself removes a {@code userId} from this set the moment it next
     * succeeds (REVISE round 2, senior-reviewer 2026-09-04, PR#188), so membership here means "this
     * user's current, still-ongoing failure episode was already logged at WARN once" — not "this
     * user has ever failed" — and a later, genuinely new failure for the same user (after an
     * intervening success) logs at WARN again rather than staying suppressed for the rest of the
     * process's lifetime. See {@link #getNvdApiKey(Long)}'s own javadoc for why that distinction
     * matters. {@link ConcurrentHashMap#newKeySet()} rather than a plain {@code HashSet} since
     * {@link #getNvdApiKey(Long)} runs concurrently across {@code itemProcessingExecutor}'s threads
     * within one job (and potentially across concurrently-running jobs, since this service is a
     * singleton).
     */
    private final Set<Long> nvdKeyDecryptFailureWarnedUserIds = ConcurrentHashMap.newKeySet();

    /**
     * Intentionally left to throw on decrypt failure (key rotation, AAD mismatch, row corruption),
     * unlike {@link #getNvdApiKey(Long)} below. The Claude key gates real API spend and pipeline
     * accuracy, and a decrypt failure here can also be the detection signal for tampered ciphertext
     * (AAD mismatch) — silently swallowing it would hide both a cost-relevant misconfiguration and
     * a potential integrity problem. Callers (Stage1/Stage4) are expected to let this fail the job
     * rather than silently fall back to a shared/unkeyed path (task-backlog item 248).
     */
    public Optional<String> getClaudeApiKey(Long userId) {
        return userSecretRepository.findByUserIdAndProvider(userId, UserSecret.PROVIDER_CLAUDE)
                .map(secret -> secretEncryptionService.decrypt(
                        secret.getEncryptedKey(), userId, UserSecret.PROVIDER_CLAUDE));
    }

    /**
     * NVD keys are free (no billing) and only unlock a higher client-side rate limit, so unlike
     * the Claude key there's no cost reason to gate this — it's simply "does this user have one
     * registered", used by whichever job/admin action happens to be running as them.
     *
     * <p>Also falls back to {@link Optional#empty()} (logging a warning with only {@code userId},
     * never the ciphertext/key/exception detail, to avoid leaking secret material into logs) if
     * decryption itself fails — e.g. a key rotation, AAD mismatch, or row corruption, matching
     * {@link #getAdminNvdApiKey()}'s existing fail-soft design below. Before this fix, a decrypt
     * failure here propagated all the way up through {@code Stage1IdentificationService},
     * {@code NvdVulnerabilitySource}, {@code NvdKeywordVulnerabilitySource}, and
     * {@code AdminController}, aborting the entire pipeline over what is only a rate-limit
     * optimization — confirmed in practice via an {@code AEADBadTagException} on keys registered
     * before the 2026-08-28 encryption key rotation (task-backlog item 248).
     *
     * <p>Only the first failure of an ongoing episode for a given {@code userId} logs at WARN —
     * every later one (this method is called once per job item, up to twice per item across its
     * different callers) downgrades to DEBUG, since repeating the same WARN up to 2,000 times for
     * one 1,000-item job added nothing but noise (task-backlog item 274). The {@code catch} below
     * covers both a permanent decrypt failure (key rotation, AAD mismatch, row corruption) AND a
     * transient failure from {@link UserSecretRepository#findByUserIdAndProvider} itself (e.g. a
     * {@code DataAccessResourceFailureException} from a connection blip or pool exhaustion) — both
     * degrade to unkeyed the same way for this one call. A success — whether it resolves an actual
     * key or simply finds none registered — clears the {@code userId} from {@link
     * #nvdKeyDecryptFailureWarnedUserIds} before returning, so the dedup above only ever suppresses
     * repeats of the SAME ongoing failure episode, never every future failure for that user (REVISE
     * round 2, senior-reviewer 2026-09-04, PR#188): the first version of this dedup never cleared
     * the flag, so a single transient repository blip that happened to resolve itself could
     * permanently downgrade a later, genuinely new, actionable decrypt failure (e.g. from key
     * rotation) to DEBUG for the rest of the process's lifetime — exactly the failure this dedup
     * exists to surface. See {@link #nvdKeyDecryptFailureWarnedUserIds}'s own javadoc.
     */
    public Optional<String> getNvdApiKey(Long userId) {
        try {
            Optional<String> key = userSecretRepository.findByUserIdAndProvider(userId, UserSecret.PROVIDER_NVD)
                    .map(secret -> secretEncryptionService.decrypt(
                            secret.getEncryptedKey(), userId, UserSecret.PROVIDER_NVD));
            nvdKeyDecryptFailureWarnedUserIds.remove(userId);
            return key;
        } catch (Exception e) {
            if (nvdKeyDecryptFailureWarnedUserIds.add(userId)) {
                log.warn("Failed to decrypt NVD API key for userId={} — falling back to unkeyed", userId);
            } else {
                log.debug("Failed to decrypt NVD API key for userId={} — falling back to unkeyed "
                        + "(already logged at WARN for this user)", userId);
            }
            return Optional.empty();
        }
    }

    /**
     * Resolves the admin user's own registered NVD key for non-interactive callers that have no
     * logged-in user context of their own (task-backlog item 142) — currently only {@link
     * CpeDictionaryScheduledResync}, which otherwise runs the weekly full CPE resync unkeyed and
     * so rate-limited to 5 req/30s instead of 50 req/30s. That per-request limit is 10x lower
     * unkeyed, but {@code NvdCpeSyncService}'s full sync is only ~182 requests (10,000
     * results/page), so the actual difference in total sync time is the per-request wait gap
     * times 182 requests — roughly 18 minutes, not 10x the ~103-minute keyed baseline
     * (task-backlog item 161).
     *
     * <p>Falls back to {@link Optional#empty()}, matching the existing "works fine without a key,
     * just slower" design, for every way this can be unconfigured: {@code ADMIN_EMAIL} unset or
     * blank, no user registered under that email, or that user simply hasn't registered an NVD
     * key. None of these are errors — an operator who hasn't set both up yet just gets the
     * unkeyed (slower) behavior that already existed before this method. Each of these three
     * "not configured" cases is logged at WARN (distinguishing which one it was, but never the
     * key/email lookup result itself beyond the already-configured {@code adminEmail} value) so a
     * misconfiguration doesn't silently degrade to the ~18-minutes-slower unkeyed path with
     * nothing in the logs to explain why (task-backlog item 142 REVISE R2).
     *
     * <p>Both {@code AuthController#register} and migration V36 normalize stored {@code
     * users.email} rows to lowercase (task-backlog item 148), so this method looks the admin user
     * up the same way {@code AppUserDetailsService} grants ROLE_ADMIN: {@code adminEmail} is
     * lowercased with {@link Locale#ROOT} and compared for an exact match via {@link
     * UserRepository#findByEmail}. Using the same normalization rule as the ROLE_ADMIN check (and
     * not Postgres {@code upper()}-based case-insensitive matching, which folds Unicode characters
     * like long s U+017F "ſ" differently and could resolve a row {@code AppUserDetailsService}
     * would correctly reject) is what task-backlog item 148 REVISE R3 fixed.
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
            Optional<User> admin = userRepository.findByEmail(adminEmail.toLowerCase(Locale.ROOT));
            if (admin.isEmpty()) {
                log.warn("ADMIN_EMAIL is set to '{}' but no registered user matches it — "
                        + "running unkeyed against NVD (slower)", adminEmail);
                return Optional.empty();
            }
            Optional<String> key = getNvdApiKey(admin.get().getId());
            if (key.isEmpty()) {
                log.warn("Admin user '{}' has no NVD API key registered — running unkeyed against NVD (slower)",
                        adminEmail);
            }
            return key;
        } catch (Exception e) {
            log.warn("Failed to resolve the admin's NVD key — falling back to unkeyed", e);
            return Optional.empty();
        }
    }
}
