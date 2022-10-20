package com.zebrunner.carina.crypto;

public enum Algorithm {
    AES_ECB_NO_PADDING("AES/ECB/NoPadding", "AES"),
    AES_ECB_PKCS5_PADDING("AES/ECB/PKCS5Padding", "AES"),
    AES_ECB_ISO10126PADDING("AES/ECB/ISO10126Padding", "AES"),
    DES_ECB_PKS5_PADDING("DES/ECB/PKCS5Padding", "DES"),
    DES_ECB_ISO10126PADDING("DES/ECB/ISO10126Padding", "DES"),
    DES_ECB_NO_PADDING("DES/ECB/NoPadding", "DES"),
    DESEDE_ECB_PKS5_PADDING("DESede/ECB/PKCS5Padding", "DESede"),
    DESEDE_ECB_NO_PADDING("DESede/ECB/NoPadding", "DESede"),
    DESEDE_ECB_ISO10126PADDING("DESede/ECB/ISO10126Padding", "DESede"),
    RC2("RC2", "RC2"),
    ARCFOUR("ARCFOUR", "ARCFOUR");

    private final String name;
    private final String type;

    Algorithm(String name, String type) {
        this.name = name;
        this.type = type;
    }

    public String getName() {
        return name;
    }

    public String getType() {
        return type;
    }

    public static Algorithm find(String algorithmAsText) {
        for (Algorithm algorithm : Algorithm.values()) {
            if (algorithm.name.equalsIgnoreCase(algorithmAsText)) {
                return algorithm;
            }
        }
        throw new IllegalArgumentException(String.format("There are no crypto algorithm with name: %s", algorithmAsText));
    }
}
