package com.zebrunner.crypto;

import java.lang.invoke.MethodHandles;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class CryptoToolImpl implements CryptoTool {

    private static final Logger LOGGER = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    // private static final Pattern ENCRYPTED_DATA_PATTERN = Pattern.compile("[{](?<wildcard>.+)[:](?<data>.+)[}]");
    private Cipher cipher;
    private final Key key;

    CryptoToolImpl(Algorithm algorithm, Key key) {
        initCipher(algorithm);
        this.key = key;
    }

    CryptoToolImpl(Algorithm algorithm, String key) {
        initCipher(algorithm);
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
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(new byte[16]));
            return new String(Base64.encodeBase64(cipher.doFinal(Base64.encodeBase64(str.getBytes()))));
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Error while encrypting, check your crypto key! ", e);
        }

    }

    @Override
    public String decrypt(String str) {
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(new byte[16]));
            return new String(Base64.decodeBase64(cipher.doFinal(Base64.decodeBase64(str.getBytes()))));
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Error while decrypting, check your crypto key! ", e);
        }
    }

    /**
     * Encrypt data by pattern
     * You can use any pattern, but it should have group named data
     * Return clean encrypted data without wrapper
     */
    @Override
    public String encrypt(String str, Pattern pattern) {
        // encrypt without wrapper
        return encrypt(str, pattern, "%s");
    }

    @Override
    public String decrypt(String str, Pattern pattern) {
        // decrypt without wrapper
        return decrypt(str, pattern, "%s");
    }

    // wrapper - use String.format agreement
    @Override
    public String encrypt(String str, Pattern pattern, String wrapper) {
        Matcher matcher = pattern.matcher(str);
        while (matcher.find()) {
            String dataToEncrypt = getDataGroup(matcher.group(), pattern);
            if (dataToEncrypt.isEmpty()) {
                continue;
            }
            str = StringUtils.replace(str, matcher.group(), String.format(wrapper, encrypt(dataToEncrypt)));
        }
        return str;
    }

    // wrapper - by String.format agreement
    @Override
    public String decrypt(String str, Pattern pattern, String wrapper) {
        Matcher matcher = pattern.matcher(str);
        while (matcher.find()) {
            String dataToDecrypt = getDataGroup(matcher.group(), pattern);
            if (dataToDecrypt.isEmpty()) {
                continue;
            }
            str = StringUtils.replace(str, matcher.group(), String.format(wrapper, decrypt(dataToDecrypt)));
        }
        return str;
    }

    // todo rename
    // check is string contains pattern - if yes, it need to be encrypted
    public boolean isMarkedByPattern(String str, Pattern pattern) {
        Matcher matcher = pattern.matcher(str);

        try {
            matcher.group("data");
        } catch (IllegalArgumentException e) {
            LOGGER.debug("There are no data group in pattern: {}", pattern);
            return false;
        }

        return matcher.find();
    }

    private String getDataGroup(String str, Pattern pattern) {
        if (!isMarkedByPattern(str, pattern)) {
            LOGGER.warn("Data {} does not match pattern: {}", str, pattern);
            return StringUtils.EMPTY;
        }
        Matcher matcher = pattern.matcher(str);
        return matcher.group("data");
    }
}
