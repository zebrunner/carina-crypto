package com.zebrunner.crypto;

public enum Algorithm {

    AES_CBC_NO_PADDING("AES/CBC/NoPadding", 128),
    AES_CBC_PKCS5_PADDING("AES/CBC/PKCS5Padding", 128),
    AES_ECB_NO_PADDING("AES/ECB/NoPadding", 128),
    AES_ECB_PKCS5_PADDING("AES/ECB/PKCS5Padding", 128),
    DES_CBC_NO_PADDING("DES/CBC/NoPadding", 56),
    DES_CBC_PKCS5_PADDING("DES/CBC/PKCS5Padding", 56),
    DES_ECB_NO_PADDING("DES/ECB/NoPadding", 56),
    DES_ECB_PKCS5_PADDING("DES/ECB/PKCS5Padding", 56),
    DESEDE_CBC_NO_PADDING("DESede/CBC/NoPadding", 168),
    DESEDE_CBC_PKCS5_PADDING("DESede/CBC/PKCS5Padding", 168),
    DESEDE_ECB_NO_PADDING("DESede/ECB/NoPadding", 168),
    DESEDE_ECB_PKCS5_PADDING("DESede/ECB/PKCS5Padding", 168),
    RSA_ECB_PKCS1_PADDING("RSA/ECB/PKCS1Padding", 2048),
    RSA_ECB_OAEP_PADDING("RSA/ECB/OAEPPadding", 2048);

    private final String name;
    private final int size;

    Algorithm(String name, int size) {
        this.name = name;
        this.size = size;
    }

    public String getName() {
        return name;
    }

    public int getSize() {
        return size;
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
