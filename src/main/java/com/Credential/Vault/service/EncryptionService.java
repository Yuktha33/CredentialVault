
package com.Credential.Vault.service;

import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class EncryptionService {

    private static final String TRANSFORMATION =
            "AES/GCM/NoPadding";

    private static final int NONCE_LENGTH = 12;
    private static final int TAG_LENGTH = 128;

    private final SecretKeySpec secretKey;
    private final SecureRandom secureRandom = new SecureRandom();

    public EncryptionService() {

        String keyValue = System.getenv("VAULT_ENCRYPTION_KEY");

        if (keyValue == null || keyValue.isBlank()) {
            throw new IllegalStateException(
                    "VAULT_ENCRYPTION_KEY is missing"
            );
        }

        byte[] keyBytes;

        try {
            keyBytes = Base64.getDecoder().decode(keyValue);
        } catch (IllegalArgumentException ex) {
            throw new IllegalStateException(
                    "Invalid Base64 encryption key", ex
            );
        }

        if (keyBytes.length != 32) {
            throw new IllegalStateException(
                    "AES-256 requires a 32-byte key"
            );
        }

        this.secretKey = new SecretKeySpec(keyBytes, "AES");
    }

    public String encrypt(String plainText) {

        if (plainText == null) {
            return null;
        }

        try {
            byte[] nonce = new byte[NONCE_LENGTH];
            secureRandom.nextBytes(nonce);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);

            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    secretKey,
                    new GCMParameterSpec(TAG_LENGTH, nonce)
            );

            byte[] encryptedData = cipher.doFinal(
                    plainText.getBytes(StandardCharsets.UTF_8)
            );

            ByteBuffer buffer = ByteBuffer.allocate(
                    nonce.length + encryptedData.length
            );

            buffer.put(nonce);
            buffer.put(encryptedData);

            return Base64.getEncoder()
                    .encodeToString(buffer.array());

        } catch (Exception ex) {
            throw new IllegalStateException("Encryption failed", ex);
        }
    }

    public String decrypt(String encryptedText) {

        if (encryptedText == null) {
            return null;
        }

        try {
            byte[] encryptedBytes =
                    Base64.getDecoder().decode(encryptedText);

            if (encryptedBytes.length < NONCE_LENGTH + 16) {
                throw new IllegalArgumentException(
                        "Invalid encrypted data"
                );
            }

            ByteBuffer buffer = ByteBuffer.wrap(encryptedBytes);

            byte[] nonce = new byte[NONCE_LENGTH];
            buffer.get(nonce);

            byte[] cipherText = new byte[buffer.remaining()];
            buffer.get(cipherText);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);

            cipher.init(
                    Cipher.DECRYPT_MODE,
                    secretKey,
                    new GCMParameterSpec(TAG_LENGTH, nonce)
            );

            byte[] decryptedData = cipher.doFinal(cipherText);

            return new String(
                    decryptedData,
                    StandardCharsets.UTF_8
            );

        } catch (Exception ex) {
            throw new IllegalStateException(
                    "Decryption failed: invalid or modified data",
                    ex
            );
        }
    }
}
