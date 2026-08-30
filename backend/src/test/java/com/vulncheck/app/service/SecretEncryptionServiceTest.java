package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Base64;
import java.util.Set;
import org.junit.jupiter.api.Test;

class SecretEncryptionServiceTest {

    // Arbitrary valid 32-byte AES-256 key for tests — not the real app default.
    private final SecretEncryptionService service =
            new SecretEncryptionService(Base64.getEncoder().encodeToString(new byte[32]));

    @Test
    void encryptThenDecryptRoundTripsToTheOriginalPlaintext() {
        String plaintext = "sk-ant-api03-super-secret-value";

        String encrypted = service.encrypt(plaintext);

        assertThat(encrypted).doesNotContain(plaintext);
        assertThat(service.decrypt(encrypted)).isEqualTo(plaintext);
    }

    @Test
    void encryptingTheSamePlaintextTwiceProducesDifferentCiphertext() {
        // A fresh random IV per call is required for GCM safety — two encryptions of the same
        // plaintext must not produce identical ciphertext.
        String plaintext = "same-value";

        String first = service.encrypt(plaintext);
        String second = service.encrypt(plaintext);

        assertThat(first).isNotEqualTo(second);
        assertThat(service.decrypt(first)).isEqualTo(plaintext);
        assertThat(service.decrypt(second)).isEqualTo(plaintext);
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
}
