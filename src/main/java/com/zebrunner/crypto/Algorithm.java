package com.zebrunner.crypto;

public enum Algorithm {

    AES_CBC_NO_PADDING("AES/CBC/NoPadding"),
    AES_CBC_PKCS5_PADDING("AES/CBC/PKCS5Padding"),
    AES_ECB_NO_PADDING("AES/ECB/NoPadding"),
    AES_ECB_PKCS5_PADDING("AES/ECB/PKCS5Padding"),
    DES_CBC_NO_PADDING("DES/CBC/NoPadding"),
    DES_CBC_PKCS5_PADDING("DES/CBC/PKCS5Padding"),
    DES_ECB_NO_PADDING("DES/ECB/NoPadding"),
    DES_ECB_PKCS5_PADDING("DES/ECB/PKCS5Padding"),
    DESEDE_CBC_NO_PADDING("DESede/CBC/NoPadding"),
    DESEDE_CBC_PKCS5_PADDING("DESede/CBC/PKCS5Padding"),
    DESEDE_ECB_NO_PADDING("DESede/ECB/NoPadding"),
    DESEDE_ECB_PKCS5_PADDING("DESede/ECB/PKCS5Padding"),
    RSA_ECB_PKCS1_PADDING("RSA/ECB/PKCS1Padding"),
    RSA_ECB_OAEP_WITH_SHA_1_AND_MGF1_PADDING("RSA/ECB/OAEPWithSHA-1AndMGF1Padding"),
    RSA_ECB_OAEP_WITH_SHA_256_AND_MGF1_PADDING("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

    private final String name;

    Algorithm(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public static Algorithm fromString(String algorithmAsText) {
        for (Algorithm algorithm : Algorithm.values()) {
            if (algorithm.name.equalsIgnoreCase(algorithmAsText)) {
                return algorithm;
            }
        }
        throw new RuntimeException("There are no crypto algorithm with name: " + algorithmAsText);
    }
}
