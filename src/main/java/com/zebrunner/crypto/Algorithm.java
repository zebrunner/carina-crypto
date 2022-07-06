package com.zebrunner.crypto;

public enum Algorithm {
    AES_ECB_PKCS5_PADDING("AES/ECB/PKCS5Padding", "AES", 128),  // tested
    AES_ECB_NO_PADDING("AES/ECB/NoPadding", "AES", 128),
    AES_ECB_ISO10126PADDING("AES/ECB/ISO10126Padding", "AES", 128),
    AES_ECB_PKCS1PADDING("AES/ECB/PKCS1Padding", "AES", 128),

    DES_ECB_PKS5_PADDING("DES/ECB/PKCS5Padding", "DES", 56),    // tested
    DES_ECB_ISO10126PADDING("DES/ECB/ISO10126Padding", "DES", 56),    // tested
    DES_ECB_PKCS1PADDING("DES/ECB/PKCS1Padding", "DES", 56),
    DES_ECB_NO_PADDING("DES/ECB/NoPadding", "DES", 56), // tested

    DESEDE_ECB_PKS5_PADDING("DESede/ECB/PKCS5Padding", "DESede", 168),
    DESEDE_ECB_NO_PADDING("DESede/ECB/NoPadding", "DESede", 168),
    DESEDE_ECB_ISO10126PADDING("DESede/ECB/ISO10126Padding", "DESede", 168),
    DESEDE_ECB_PKCS1PADDING("DESede/ECB/PKCS1Padding", "DESede", 168),
    RC2_ECB_PKCS1PADDING("RC2", "RC2", 168),// tested

    ARCFOUR("ARCFOUR", "ARCFOUR", 128); // tested

    private final String name;
    private final int size;
    private final String type;

    Algorithm(String name, String type, int size) {
        this.name = name;
        this.type = type;
        this.size = size;
    }

    public String getName() {
        return name;
    }

    public String getType() {
        return type;
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
