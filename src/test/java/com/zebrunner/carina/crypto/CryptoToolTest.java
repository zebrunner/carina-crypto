package com.zebrunner.carina.crypto;

import java.security.NoSuchAlgorithmException;

import org.testng.Assert;
import org.testng.annotations.Test;

public class CryptoToolTest {

    @Test
    public static void encryptTest() {
        Algorithm algorithm = Algorithm.AES_ECB_PKCS5_PADDING;
        String secretKey = "3oIL3VN01Cs/r1dLiFrugw==";
        CryptoTool CRYPTO_TOOL = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();

        String encryptedStr = "fDuqYu8s19RgDcCl0Gwyqw==";
        Assert.assertEquals(CRYPTO_TOOL.encrypt("Zebrunner"), encryptedStr);
    }

    @Test
    public static void encryptTestWithCustomPattern() {
        Algorithm algorithm = Algorithm.AES_ECB_PKCS5_PADDING;
        String secretKey = "3oIL3VN01Cs/r1dLiFrugw==";
        CryptoTool CRYPTO_TOOL = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();
        Assert.assertEquals(CRYPTO_TOOL.encrypt("{zebrunner:Zebrunner}", "\\{zebrunner:(?<data>.+)\\}"),
                "fDuqYu8s19RgDcCl0Gwyqw==");
    }

    @Test
    public static void encryptTestWithWrapper() {
        Algorithm algorithm = Algorithm.AES_ECB_PKCS5_PADDING;
        String secretKey = "3oIL3VN01Cs/r1dLiFrugw==";
        CryptoTool CRYPTO_TOOL = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();

        Assert.assertEquals(CRYPTO_TOOL.encrypt("{zebrunner:Zebrunner}", "\\{zebrunner:(?<data>.+)\\}", "[crypted-by-zebrunner:%s]"),
                "[crypted-by-zebrunner:fDuqYu8s19RgDcCl0Gwyqw==]");
    }

    @Test(expectedExceptions = { RuntimeException.class })
    public static void encryptTestWithPatternWithoutDataGroup() {
        Algorithm algorithm = Algorithm.AES_ECB_PKCS5_PADDING;
        String secretKey = "3oIL3VN01Cs/r1dLiFrugw==";
        CryptoTool CRYPTO_TOOL = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();

        Assert.assertEquals(CRYPTO_TOOL.encrypt("{zebrunner:Zebrunner}", "\\{zebrunner:(.+)\\}", "[crypted-by-zebrunner:%s]"),
                "[crypted-by-zebrunner:Gy1n4N2oIy/iUfFeCNgjKA==]");
    }

    @Test
    public static void encyptDecryptWithAES_128_ECB_NO_PADDINGTest() throws NoSuchAlgorithmException {
        Algorithm algorithm = Algorithm.AES_ECB_NO_PADDING;
        String srtToEncrypt = "2022-08-07-11:35 ABCDEFJ TEST TEST TEST TEsT tEsT TEST TEST TEST TEsT TETEsTTEsTTEsTTEsTTEsTTEsT";
        String secretKey = SecretKeyManager.generateKeyAsString(algorithm, 128);
        CryptoTool cryptoTool = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();
        String encryptedStr = cryptoTool.encrypt(srtToEncrypt);
        Assert.assertEquals(cryptoTool.decrypt(encryptedStr), srtToEncrypt);
    }

    @Test
    public static void encyptDecryptWithAES_128_ECB_PKCS5_PADDING() throws NoSuchAlgorithmException {
        Algorithm algorithm = Algorithm.AES_ECB_PKCS5_PADDING;
        String srtToEncrypt = "2022-08-07-11:35 TEST TEST TEST TEsT tEsT TEST TEST TEST TEsT tEsT TEST TEST TEST TEsT tEsT TEST TEST TEST TEsT tEsT";
        String secretKey = SecretKeyManager.generateKeyAsString(algorithm, 128);
        CryptoTool cryptoTool = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();
        String encryptedStr = cryptoTool.encrypt(srtToEncrypt);
        Assert.assertEquals(cryptoTool.decrypt(encryptedStr), srtToEncrypt);
    }

    @Test
    public static void encyptDecryptWithAES_128_ECB_ISO10126PADDINGTest() throws NoSuchAlgorithmException {
        Algorithm algorithm = Algorithm.AES_ECB_ISO10126PADDING;
        String srtToEncrypt = "2022-08-07-11:35 AES_128_ECB_ISO10126PADDING";
        String secretKey = SecretKeyManager.generateKeyAsString(algorithm, 128);
        CryptoTool cryptoTool = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();
        String encryptedStr = cryptoTool.encrypt(srtToEncrypt);
        Assert.assertEquals(cryptoTool.decrypt(encryptedStr), srtToEncrypt);
    }

    @Test
    public static void encyptDecryptWithAES_256_ECB_NO_PADDINGTest() throws NoSuchAlgorithmException {
        Algorithm algorithm = Algorithm.AES_ECB_NO_PADDING;
        String srtToEncrypt = "TESTTESTTESTTEST";
        String secretKey = SecretKeyManager.generateKeyAsString(algorithm, 256);
        CryptoTool cryptoTool = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();
        String encryptedStr = cryptoTool.encrypt(srtToEncrypt);
        Assert.assertEquals(cryptoTool.decrypt(encryptedStr), srtToEncrypt);
    }

    @Test
    public static void encyptDecryptWithDES_56_ECB_PKS5_PADDINGTest() throws NoSuchAlgorithmException {
        Algorithm algorithm = Algorithm.DES_ECB_PKS5_PADDING;
        String srtToEncrypt = "2022-08-07-11:35 DES_56_ECB_PKS5_PADDING";
        String secretKey = SecretKeyManager.generateKeyAsString(algorithm, 56);
        CryptoTool cryptoTool = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();
        String encryptedStr = cryptoTool.encrypt(srtToEncrypt);
        Assert.assertEquals(cryptoTool.decrypt(encryptedStr), srtToEncrypt);
    }

    @Test
    public static void encyptDecryptWithDES_56_ECB_ISO10126PADDINGTest() throws NoSuchAlgorithmException {
        Algorithm algorithm = Algorithm.DES_ECB_ISO10126PADDING;
        String srtToEncrypt = "2022-08-07-11:35 DES_56_ECB_ISO10126PADDING";
        String secretKey = SecretKeyManager.generateKeyAsString(algorithm, 56);
        CryptoTool cryptoTool = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();
        String encryptedStr = cryptoTool.encrypt(srtToEncrypt);
        Assert.assertEquals(cryptoTool.decrypt(encryptedStr), srtToEncrypt);
    }

    @Test
    public static void encyptDecryptWithDES_56_ECB_NO_PADDINGTest() throws NoSuchAlgorithmException {
        Algorithm algorithm = Algorithm.DES_ECB_NO_PADDING;
        String srtToEncrypt = "2022-08-07-11:35";
        String secretKey = SecretKeyManager.generateKeyAsString(algorithm, 56);
        CryptoTool cryptoTool = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();
        String encryptedStr = cryptoTool.encrypt(srtToEncrypt);
        Assert.assertEquals(cryptoTool.decrypt(encryptedStr), srtToEncrypt);
    }

    @Test
    public static void encyptDecryptWithDESEDE_168_ECB_NO_PADDINGTest() throws NoSuchAlgorithmException {
        Algorithm algorithm = Algorithm.DESEDE_ECB_NO_PADDING;
        String srtToEncrypt = "2022-08-07-11:35 DESEDE_168_ECB_";
        String secretKey = SecretKeyManager.generateKeyAsString(algorithm, 168);
        CryptoTool cryptoTool = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();
        String encryptedStr = cryptoTool.encrypt(srtToEncrypt);
        Assert.assertEquals(cryptoTool.decrypt(encryptedStr), srtToEncrypt);
    }

    @Test
    public static void encyptDecryptWithDESEDE_168_ECB_ISO10126PADDINGTest() throws NoSuchAlgorithmException {
        Algorithm algorithm = Algorithm.DESEDE_ECB_ISO10126PADDING;
        String srtToEncrypt = "2022-08-07-11:35 DESEDE_168_ECB_ISO10126PADDING";
        String secretKey = SecretKeyManager.generateKeyAsString(algorithm, 168);
        CryptoTool cryptoTool = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();
        String encryptedStr = cryptoTool.encrypt(srtToEncrypt);
        Assert.assertEquals(cryptoTool.decrypt(encryptedStr), srtToEncrypt);
    }

    @Test
    public static void encyptDecryptWithRC2_168Test() throws NoSuchAlgorithmException {
        Algorithm algorithm = Algorithm.RC2;
        String srtToEncrypt = "2022-08-07-11:35 RC2_168";
        String secretKey = SecretKeyManager.generateKeyAsString(algorithm, 168);
        CryptoTool cryptoTool = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();
        String encryptedStr = cryptoTool.encrypt(srtToEncrypt);
        Assert.assertEquals(cryptoTool.decrypt(encryptedStr), srtToEncrypt);
    }

    @Test
    public static void encyptDecryptWithARCFOUR_128Test() throws NoSuchAlgorithmException {
        Algorithm algorithm = Algorithm.ARCFOUR;
        String srtToEncrypt = "2022-08-07-11:35 ARCFOUR_128";
        String secretKey = SecretKeyManager.generateKeyAsString(algorithm, 128);
        CryptoTool cryptoTool = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();
        String encryptedStr = cryptoTool.encrypt(srtToEncrypt);
        Assert.assertEquals(cryptoTool.decrypt(encryptedStr), srtToEncrypt);
    }
}
