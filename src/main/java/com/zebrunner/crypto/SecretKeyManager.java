package com.zebrunner.crypto;

import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

class SecretKeyManager {

    private SecretKeyManager() {
    }

    public static SecretKey generateKey(String algorithmType, int size) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithmType);
        keyGenerator.init(size);
        return keyGenerator.generateKey();
    }

    public static String generateKeyAsString(String algorithmType, int size) throws NoSuchAlgorithmException {
        SecretKey secretKey = generateKey(algorithmType, size);
        return new String(Base64.encodeBase64(secretKey.getEncoded()));
    }

    public static SecretKey getKeyFromString(Algorithm algorithm, String key) {
        byte[] decodedKey = Base64.decodeBase64(key);
        return new SecretKeySpec(decodedKey, algorithm.getType());
    }
}
