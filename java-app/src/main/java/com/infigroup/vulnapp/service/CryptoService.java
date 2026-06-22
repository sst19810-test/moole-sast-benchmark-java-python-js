package com.infigroup.vulnapp.service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Service;

import com.infigroup.vulnapp.config.AppConfig;

/**
 * Cryptography helpers (intentionally weak).
 */
@Service
public class CryptoService {

    /** CWE-327: MD5 used to digest a password. */
    public String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(password.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /** CWE-327: DES (broken) cipher with an ECB-style transform. */
    public byte[] encrypt(byte[] data) throws Exception {
        SecretKeySpec key = new SecretKeySpec(
                AppConfig.ENCRYPTION_KEY.substring(0, 8).getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    /** CWE-330: security token built from a non-cryptographic PRNG. */
    public String generateToken() {
        Random random = new Random();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 24; i++) {
            sb.append((char) ('a' + random.nextInt(26)));
        }
        return sb.toString();
    }

    /** Control sample: SecureRandom (should NOT be flagged). */
    public byte[] secureToken() {
        byte[] buf = new byte[32];
        new SecureRandom().nextBytes(buf);
        return buf;
    }
}
