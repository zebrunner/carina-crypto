package com.zebrunner.carina.crypto;

import java.lang.invoke.MethodHandles;
import java.security.Key;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CryptoToolBuilder {

    private static final Logger LOGGER = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private Key key;
    private String keyAsString;
    private Algorithm algorithm;

    private CryptoToolBuilder() {
        keyAsString = StringUtils.EMPTY;
    }

    public static CryptoToolBuilder builder() {
        return new CryptoToolBuilder();
    }

    public CryptoToolBuilder chooseAlgorithm(Algorithm algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    public CryptoToolBuilder setKey(Key key) {
        this.key = key;
        return this;
    }

    public CryptoToolBuilder setKey(String key) {
        this.keyAsString = key;
        return this;
    }

    public CryptoTool build() {
        validate();
        if (key != null) {
            if (!keyAsString.isEmpty()) {
                LOGGER.warn("Key as object has high priority over key as string. Choose one of the key transfer methods");
            }
            return new CryptoToolImpl(algorithm, key);
        }
        return new CryptoToolImpl(algorithm, keyAsString);

    }

    private void validate() {
        if (key == null && (keyAsString == null || keyAsString.isEmpty())) {
            throw new IllegalArgumentException("The key must be passed!");
        }
        if (algorithm == null) {
            throw new IllegalArgumentException(("The algorithm must be chosen!"));
        }
    }

}
