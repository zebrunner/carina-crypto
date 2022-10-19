package com.zebrunner.carina.crypto;

public enum Algorithm {

    AES_128_ECB_NO_PADDING("AES/ECB/NoPadding", "AES", 128),
    AES_128_ECB_PKCS5_PADDING("AES/ECB/PKCS5Padding", "AES", 128),
    AES_128_ECB_ISO10126PADDING("AES/ECB/ISO10126Padding", "AES", 128),
    AES_256_ECB_NO_PADDING("AES/ECB/NoPadding", "AES", 256),
    AES_256_ECB_PKCS5_PADDING("AES/ECB/PKCS5Padding", "AES", 256),

    DES_56_ECB_PKS5_PADDING("DES/ECB/PKCS5Padding", "DES", 56),
    DES_56_ECB_ISO10126PADDING("DES/ECB/ISO10126Padding", "DES", 56),
    DES_56_ECB_NO_PADDING("DES/ECB/NoPadding", "DES", 56),

    DESEDE_168_ECB_PKS5_PADDING("DESede/ECB/PKCS5Padding", "DESede", 168),
    DESEDE_168_ECB_NO_PADDING("DESede/ECB/NoPadding", "DESede", 168),
    DESEDE_168_ECB_ISO10126PADDING("DESede/ECB/ISO10126Padding", "DESede", 168),

    RC2_168("RC2", "RC2", 168),
    ARCFOUR_128("ARCFOUR", "ARCFOUR", 128);

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

    public static Algorithm find(String algorithmAsText, int keySize) {
        for (Algorithm algorithm : Algorithm.values()) {
            if (algorithm.name.equalsIgnoreCase(algorithmAsText) && algorithm.size == keySize) {
                return algorithm;
            }
        }
        throw new IllegalArgumentException(String.format("There are no crypto algorithm with name: %s and key size %d", algorithmAsText, keySize));
    }
}
