package com.zebrunner.crypto;

public enum Algorithm {
    AES("AES", "AES", 128),
    DES("DES", "DES", 56),
    DESEDE("DESede", "DESede", 168);

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
