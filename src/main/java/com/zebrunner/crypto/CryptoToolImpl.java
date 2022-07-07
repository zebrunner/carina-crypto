package com.zebrunner.crypto;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;

class CryptoToolImpl implements CryptoTool {

    protected Cipher cipher;
    protected final Key key;
    protected Algorithm algorithm;

    protected CryptoToolImpl(Algorithm algorithm, Key key) {
        initCipher(algorithm);
        this.algorithm = algorithm;
        this.key = key;
    }

    protected CryptoToolImpl(Algorithm algorithm, String key) {
        initCipher(algorithm);
        this.algorithm = algorithm;
        this.key = SecretKeyManager.getKeyFromString(algorithm, key);
    }

    private void initCipher(Algorithm algorithm) {
        try {
            this.cipher = Cipher.getInstance(algorithm.getName());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Algorithm " + algorithm.getName() + " is not supported", e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException("Padding of algorithm " + algorithm.getName() + " is not supported", e);
        }
    }

    @Override
    public String encrypt(String str) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return new String(Base64.encodeBase64(cipher.doFinal(Base64.encodeBase64(str.getBytes()))));
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(
                    "Error while encrypting, check your crypto key or length of string! Try to choose algorithm with bigger key size", e);
        }
    }

    @Override
    public String decrypt(String str) {
        try {
            cipher.init(Cipher.DECRYPT_MODE, key);
            return new String(Base64.decodeBase64(cipher.doFinal(Base64.decodeBase64(str.getBytes()))));
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Error while decrypting, check your crypto key! ", e);
        }
    }

    @Override
    public String encrypt(String str, String pattern) {
        return encrypt(str, pattern, "%s");
    }

    @Override
    public String decrypt(String str, String pattern) {
        return decrypt(str, pattern, "%s");
    }

    @Override
    public String encrypt(String str, String pattern, String wrapper) {
        validatePattern(pattern);
        Matcher matcher = Pattern.compile(pattern)
                .matcher(str);

        while (matcher.find()) {
            String dataToEncrypt = getDataGroup(matcher.group(), pattern);
            if (dataToEncrypt.isEmpty()) {
                continue;
            }
            str = StringUtils.replace(str, matcher.group(), String.format(wrapper, encrypt(dataToEncrypt)));
        }
        return str;
    }

    @Override
    public String decrypt(String str, String pattern, String wrapper) {
        validatePattern(pattern);
        Matcher matcher = Pattern.compile(pattern)
                .matcher(str);

        while (matcher.find()) {
            String dataToDecrypt = getDataGroup(matcher.group(), pattern);
            if (dataToDecrypt.isEmpty()) {
                continue;
            }
            str = StringUtils.replace(str, matcher.group(), String.format(wrapper, decrypt(dataToDecrypt)));
        }
        return str;
    }

    public boolean hasMatch(String str, String pattern) {
        validatePattern(pattern);
        Matcher matcher = Pattern.compile(pattern)
                .matcher(str);
        if (!matcher.find()) {
            return false;
        }
        return true;
    }

    private String getDataGroup(String str, String pattern) {
        Matcher matcher = Pattern.compile(pattern)
                .matcher(str);
        matcher.find();
        return matcher.group("data");
    }

    private void validatePattern(String pattern) {
        // Check is pattern contains data group
        if (!pattern.contains("(?<data>")) {
            throw new RuntimeException("There are no data group in pattern: " + pattern);
        }
    }
}
