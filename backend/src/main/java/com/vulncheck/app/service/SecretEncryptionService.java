package com.vulncheck.app.service;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * AES-256-GCM at the application layer for {@code user_secrets.encrypted_key}, per the plan
 * ("アプリ層でAES-GCM暗号化"). Ciphertext is stored as {@code base64(iv) + ":" + base64(ciphertext+tag)}
 * — a fresh random 12-byte IV per encryption (GCM requires IV uniqueness per key, never reuse).
 *
 * <p>The encryption key itself comes from {@code app.secret-encryption-key} (env
 * {@code APP_SECRET_ENCRYPTION_KEY}), base64-encoded, 32 bytes. There is deliberately no default —
 * a prior committed dev-only default literal was found to be the key actually in effect in every
 * deployment (docker-compose.yml never wired the env var through), so anyone with the retired
 * literal could decrypt every stored API key. To make that class of mistake fail loudly instead of
 * silently, this service refuses to start if the configured key is blank, or if its SHA-256 hash
 * matches a known-retired default (see {@link #RETIRED_KEY_HASHES} — the retired literals
 * themselves are intentionally NOT reproduced here, only their hashes).
 */
@Service
public class SecretEncryptionService {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int IV_LENGTH_BYTES = 12;

    /**
     * SHA-256 hashes (hex, lowercase) of the raw {@code app.secret-encryption-key} string value of
     * retired defaults. Add a new hash here whenever a previously-shipped default is retired;
     * never add the literal key value itself.
     */
    private static final Set<String> RETIRED_KEY_HASHES = Set.of(
            // application.yml's dev-only default, in effect (unreachable via env, see class javadoc)
            // until the 2026-08-28 key rotation.
            "8cd720323b59119cfc3346d13dfe0bab11d37071ee6e7103f534e9fa7509f8a4");

    private final SecretKeySpec key;
    private final SecureRandom secureRandom = new SecureRandom();

    @Autowired
    public SecretEncryptionService(@Value("${app.secret-encryption-key:}") String base64Key) {
        this(base64Key, RETIRED_KEY_HASHES);
    }

    /**
     * Package-private seam so tests can exercise the deny-list mechanism (hash + membership check)
     * against a synthetic hash set, without ever needing to reproduce a real retired literal in
     * test source — see {@code SecretEncryptionServiceTest}.
     */
    SecretEncryptionService(String base64Key, Set<String> retiredKeyHashes) {
        if (base64Key == null || base64Key.isBlank()) {
            throw new IllegalStateException(
                    "app.secret-encryption-key (env APP_SECRET_ENCRYPTION_KEY) is not set. There is no "
                            + "default — generate one with `openssl rand -base64 32` and set it explicitly.");
        }
        if (retiredKeyHashes.contains(sha256Hex(base64Key))) {
            throw new IllegalStateException(
                    "app.secret-encryption-key matches a retired default value and must not be used. "
                            + "Generate a fresh key with `openssl rand -base64 32` and set "
                            + "APP_SECRET_ENCRYPTION_KEY to it.");
        }
        byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(base64Key);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("app.secret-encryption-key is not valid base64", e);
        }
        if (keyBytes.length != 32) {
            throw new IllegalStateException(
                    "app.secret-encryption-key must decode to 32 bytes (AES-256), got " + keyBytes.length);
        }
        this.key = new SecretKeySpec(keyBytes, "AES");
    }

    static String sha256Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    public String encrypt(String plaintext) {
        try {
            byte[] iv = new byte[IV_LENGTH_BYTES];
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            return Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to encrypt secret", e);
        }
    }

    public String decrypt(String stored) {
        try {
            String[] parts = stored.split(":", 2);
            byte[] iv = Base64.getDecoder().decode(parts[0]);
            byte[] ciphertext = Base64.getDecoder().decode(parts[1]);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            byte[] plaintext = cipher.doFinal(ciphertext);

            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to decrypt secret", e);
        }
    }
}
