package com.zebrunner.crypto;

public enum Algorithm {

    //AES_CBC_NO_PADDING("AES/CBC/NoPadding", "AES", 128),
    AES_CBC_PKCS5_PADDING("AES/CBC/PKCS5Padding", "AES", 128),
    //AES_ECB_NO_PADDING("AES/ECB/NoPadding", "AES", 128),
    AES_ECB_PKCS5_PADDING("AES/ECB/PKCS5Padding", "AES", 128),
    //DES_CBC_NO_PADDING("DES/CBC/NoPadding", "DES", 56),
    DES_CBC_PKCS5_PADDING("DES/CBC/PKCS5Padding", "DES", 56),
    //DES_ECB_NO_PADDING("DES/ECB/NoPadding", "DES", 56),
    DES_ECB_PKCS5_PADDING("DES/ECB/PKCS5Padding", "DES", 56),
    //DESEDE_CBC_NO_PADDING("DESede/CBC/NoPadding", "DESede", 168),
    DESEDE_CBC_PKCS5_PADDING("DESede/CBC/PKCS5Padding", "DESede", 168),
    //DESEDE_ECB_NO_PADDING("DESede/ECB/NoPadding", "DESede", 168),
    DESEDE_ECB_PKCS5_PADDING("DESede/ECB/PKCS5Padding", "DESede", 168);
    // todo investigate to use KeyPairGenerator
    // RSA_ECB_PKCS1_PADDING("RSA/ECB/PKCS1Padding", "RSA", 2048),
    // RSA_ECB_OAEP_PADDING("RSA/ECB/OAEPPadding", "RSA", 2048);

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
