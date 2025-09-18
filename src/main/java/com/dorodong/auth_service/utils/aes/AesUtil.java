package com.dorodong.auth_service.utils.aes;

import com.dorodong.auth_service.exception.aes.CryptoConfigException;
import com.dorodong.auth_service.exception.aes.CryptoOperationException;
import com.dorodong.auth_service.exception.aes.InvalidCiphertextException;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

@Component
public class AesUtil {
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH_BIT = 128;
    private static final SecureRandom RNG = new SecureRandom();

    @Value("${aes.key}")
    private String privateKey;

    private SecretKeySpec key;

    @PostConstruct
    void init() {
        byte[] keyBytes = decodeKey(privateKey);
        if (!(keyBytes.length == 16 || keyBytes.length == 24 || keyBytes.length == 32)) {
            throw new CryptoConfigException("AES key의 길이는 반드시 16/24/32 bytes 이어야 합니다. 현재 길이 = " + keyBytes.length);
        }
        this.key = new SecretKeySpec(keyBytes, "AES");
    }

    private byte[] decodeKey(String privateKey) {
        try {
            return Base64.getDecoder().decode(privateKey);
        } catch (IllegalArgumentException ignore) {
            return privateKey.getBytes(StandardCharsets.UTF_8);
        }
    }

    public String aesGCMEncode(String plainText) {
        return aesGCMEncode(plainText, null);
    }

    public String aesGCMEncode(String plainText, byte[] aad) {
        try {
            byte[] iv = new byte[IV_LENGTH];
            RNG.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }

            byte[] cipherPlusTag = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            byte[] combined = new byte[iv.length + cipherPlusTag.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(cipherPlusTag, 0, combined, iv.length, cipherPlusTag.length);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(combined);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException e) {
            throw new CryptoConfigException("AES/GCM init failed", e);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoOperationException("Encryption failed", e);
        }
    }

    public String aesGCMDecode(String encryptedText) {
        return aesGCMDecode(encryptedText, null);
    }

    public String aesGCMDecode(String encryptedText, byte[] aad) {
        byte[] combined;

        try {
            combined = Base64.getUrlDecoder().decode(encryptedText);
        } catch (IllegalArgumentException e) {
            throw new InvalidCiphertextException("Invalid Base64 ciphertext", e);
        }
        if (combined.length < IV_LENGTH + 16) {
            throw new InvalidCiphertextException("Ciphertext too short: " + combined.length);
        }

        byte[] iv = Arrays.copyOfRange(combined, 0, IV_LENGTH);
        byte[] cipherPlusTag = Arrays.copyOfRange(combined, IV_LENGTH, combined.length);

        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }

            byte[] plain = cipher.doFinal(cipherPlusTag);
            return new String(plain, StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException e) {
            throw new CryptoConfigException("AES/GCM init failed", e);
        } catch (AEADBadTagException e) {
            throw new InvalidCiphertextException("GCM tag verification failed", e);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoOperationException("Encryption failed", e);
        }
    }
}
