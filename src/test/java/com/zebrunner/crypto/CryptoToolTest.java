package com.zebrunner.crypto;

import org.testng.Assert;
import org.testng.annotations.Test;

public class CryptoToolTest {
    private static final Algorithm CRYPTO_ALGORITHM = Algorithm.AES_ECB_PKCS5_PADDING;
    private static final String KEY = "3oIL3VN01Cs/r1dLiFrugw==";
    private static final String STR_TO_ENCRYPT = "Zebrunner";
    private static final String PATTERN = "(?<data>.+)";
    private static final CryptoTool CRYPTO_TOOL = CryptoToolBuilder.builder()
            .chooseAlgorithm(Algorithm.AES_ECB_PKCS5_PADDING)
            .setKey(KEY)
            .build();

    @Test
    public static void encryptTest() {
        String encryptedStr = "Gy1n4N2oIy/iUfFeCNgjKA==";
        Assert.assertEquals(encryptedStr, CRYPTO_TOOL.encrypt(STR_TO_ENCRYPT));
    }

    @Test
    public static void encryptTestWithCustomPattern() {
        String str = "{zebrunner:Zebrunner}";
        String pattern = "\\{zebrunner:(?<data>.+)\\}";
        String encryptedStr = "Gy1n4N2oIy/iUfFeCNgjKA==";
        Assert.assertEquals(CRYPTO_TOOL.encrypt(str, pattern), encryptedStr);
    }

    @Test
    public static void encryptTestWithValidWrapperAndValidStrAnd() {
        String str = "{zebrunner:Zebrunner}";
        String pattern = "\\{zebrunner:(?<data>.+)\\}";
        String encryptedStr = "Gy1n4N2oIy/iUfFeCNgjKA==";
        Assert.assertEquals(CRYPTO_TOOL.encrypt(str, pattern), encryptedStr);
    }


}
