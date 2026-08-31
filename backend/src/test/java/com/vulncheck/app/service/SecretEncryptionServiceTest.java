package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

class SecretEncryptionServiceTest {

    private static final byte[] RAW_KEY_BYTES = new byte[32];
    private static final String RAW_KEY = Base64.getEncoder().encodeToString(RAW_KEY_BYTES);

    // Arbitrary valid 32-byte AES-256 key for tests — not the real app default.
    private final SecretEncryptionService service = new SecretEncryptionService(RAW_KEY);

    @Test
    void encryptThenDecryptRoundTripsToTheOriginalPlaintext() {
        String plaintext = "sk-ant-api03-super-secret-value";

        String encrypted = service.encrypt(plaintext, 42L, "claude");

        assertThat(encrypted).doesNotContain(plaintext);
        assertThat(service.decrypt(encrypted, 42L, "claude")).isEqualTo(plaintext);
    }

    @Test
    void encryptingTheSamePlaintextTwiceProducesDifferentCiphertext() {
        // A fresh random IV per call is required for GCM safety — two encryptions of the same
        // plaintext must not produce identical ciphertext.
        String plaintext = "same-value";

        String first = service.encrypt(plaintext, 1L, "claude");
        String second = service.encrypt(plaintext, 1L, "claude");

        assertThat(first).isNotEqualTo(second);
        assertThat(service.decrypt(first, 1L, "claude")).isEqualTo(plaintext);
        assertThat(service.decrypt(second, 1L, "claude")).isEqualTo(plaintext);
    }

    @Test
    void encryptedValueIsPrefixedWithTheKeyVersion() {
        String encrypted = service.encrypt("some-secret", 1L, "claude");

        assertThat(encrypted).startsWith("v1:");
    }

    @Test
    void decryptingWithADifferentUserIdFailsBecauseAadNoLongerMatches() {
        String encrypted = service.encrypt("some-secret", 1L, "claude");

        assertThatThrownBy(() -> service.decrypt(encrypted, 2L, "claude"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void decryptingWithADifferentProviderFailsBecauseAadNoLongerMatches() {
        String encrypted = service.encrypt("some-secret", 1L, "claude");

        assertThatThrownBy(() -> service.decrypt(encrypted, 1L, "nvd")).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void ciphertextCopiedFromAnotherRowFailsToDecryptUnderItsNewRowsIdentity() {
        // Simulates an attacker (or a bug) copying one row's encrypted_key value into another
        // row: same key, but the AAD (user_id|provider) baked in at encryption time belongs to a
        // different row, so the AEAD tag check must fail rather than silently returning
        // user 1's plaintext under user 2's identity.
        String userOnesCiphertext = service.encrypt("user-1-secret", 1L, "claude");

        assertThatThrownBy(() -> service.decrypt(userOnesCiphertext, 2L, "claude"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void legacyUnprefixedCiphertextWithoutAadStillDecrypts() throws Exception {
        // Existing user_secrets rows written before this change have no "v1:" prefix and were
        // encrypted with no AAD at all — those must keep decrypting, regardless of what
        // userId/provider is now passed in (there's nothing to check them against).
        String legacyCiphertext = encryptLegacyFormat("sk-ant-api03-old-value");

        assertThat(legacyCiphertext).doesNotStartWith("v1:");
        assertThat(service.decrypt(legacyCiphertext, 7L, "claude")).isEqualTo("sk-ant-api03-old-value");
        // No AAD was ever bound for legacy ciphertext, so any userId/provider combination decrypts it.
        assertThat(service.decrypt(legacyCiphertext, 999L, "nvd")).isEqualTo("sk-ant-api03-old-value");
    }

    @Test
    void constructorFailsFastWhenKeyIsBlank() {
        assertThatThrownBy(() -> new SecretEncryptionService(""))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("is not set");

        assertThatThrownBy(() -> new SecretEncryptionService(null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("is not set");
    }

    @Test
    void constructorFailsFastWhenKeyMatchesADenyListedHash() {
        // Deliberately does NOT use the real retired production literal (never reproduce it in
        // source, see SecretEncryptionService's javadoc) — instead exercises the exact same
        // hash-then-look-up code path via the package-private test seam, with a synthetic value.
        String arbitraryKey = "this-is-not-a-real-secret-just-a-test-fixture";
        Set<String> syntheticDenyList = Set.of(SecretEncryptionService.sha256Hex(arbitraryKey));

        assertThatThrownBy(() -> new SecretEncryptionService(arbitraryKey, syntheticDenyList))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("retired default");
    }

    @Test
    void constructorAllowsAKeyNotOnTheDenyList() {
        String key = Base64.getEncoder().encodeToString(new byte[32]);
        Set<String> unrelatedDenyList = Set.of(SecretEncryptionService.sha256Hex("some-other-value"));

        // Should not throw.
        new SecretEncryptionService(key, unrelatedDenyList);
    }

    @Test
    void constructorFailsFastWhenKeyIsNotValidBase64() {
        assertThatThrownBy(() -> new SecretEncryptionService("not-valid-base64!!!"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void constructorFailsFastWhenDecodedKeyIsNot32Bytes() {
        String tooShort = Base64.getEncoder().encodeToString(new byte[16]);

        assertThatThrownBy(() -> new SecretEncryptionService(tooShort))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("32 bytes");
    }

    /**
     * Hand-rolled equivalent of the pre-versioning/pre-AAD {@code encrypt} (bare
     * {@code base64(iv) + ":" + base64(ciphertext+tag)}, no version prefix, no AAD) — used only to
     * fabricate a legacy-format fixture for the backward-compat test, since {@link
     * SecretEncryptionService#encrypt} itself no longer produces this format.
     */
    private static String encryptLegacyFormat(String plaintext) throws Exception {
        byte[] iv = new byte[12];
        // Fixed (not random) IV is fine here — this is a one-off test fixture, not real traffic,
        // and GCM's uniqueness requirement is per-key, not relevant to fabricating one sample.
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(RAW_KEY_BYTES, "AES"),
                new GCMParameterSpec(128, iv));
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(ciphertext);
    }
}
