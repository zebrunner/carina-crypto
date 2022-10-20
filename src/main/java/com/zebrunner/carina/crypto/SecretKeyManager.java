package com.zebrunner.carina.crypto;

import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class SecretKeyManager {

    private SecretKeyManager() {
    }

    public static SecretKey generateKey(Algorithm algorithm, int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm.getType());
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }

    public static String generateKeyAsString(Algorithm algorithm, int keySize) throws NoSuchAlgorithmException {
        SecretKey secretKey = generateKey(algorithm, keySize);
        return new String(Base64.encodeBase64(secretKey.getEncoded()));
    }

    public static SecretKey getKeyFromString(Algorithm algorithm, String key) {
        byte[] decodedKey = Base64.decodeBase64(key);
        return new SecretKeySpec(decodedKey, algorithm.getType());
    }
}
