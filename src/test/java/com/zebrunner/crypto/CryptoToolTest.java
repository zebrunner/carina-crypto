package com.zebrunner.crypto;

import java.security.NoSuchAlgorithmException;

import com.zebrunner.carina.crypto.Algorithm;
import com.zebrunner.carina.crypto.CryptoTool;
import com.zebrunner.carina.crypto.CryptoToolBuilder;
import com.zebrunner.carina.crypto.SecretKeyManager;
import org.testng.Assert;
import org.testng.annotations.Test;

public class CryptoToolTest {

    @Test
    public static void encryptTest() throws NoSuchAlgorithmException {
        Algorithm algorithm = Algorithm.AES_128_ECB_PKCS5_PADDING;
        String secretKey = "3oIL3VN01Cs/r1dLiFrugw==";
        CryptoTool CRYPTO_TOOL = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();

        String encryptedStr = "Gy1n4N2oIy/iUfFeCNgjKA==";
        Assert.assertEquals(encryptedStr, CRYPTO_TOOL.encrypt("Zebrunner"));
    }

    @Test
    public static void encryptTestWithCustomPattern() {
        Algorithm algorithm = Algorithm.AES_128_ECB_PKCS5_PADDING;
        String secretKey = "3oIL3VN01Cs/r1dLiFrugw==";
        CryptoTool CRYPTO_TOOL = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();
        Assert.assertEquals(CRYPTO_TOOL.encrypt("{zebrunner:Zebrunner}", "\\{zebrunner:(?<data>.+)\\}"),
                "Gy1n4N2oIy/iUfFeCNgjKA==");
    }

    @Test
    public static void encryptTestWithWrapper() {
        Algorithm algorithm = Algorithm.AES_128_ECB_PKCS5_PADDING;
        String secretKey = "3oIL3VN01Cs/r1dLiFrugw==";
        CryptoTool CRYPTO_TOOL = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();

        Assert.assertEquals(CRYPTO_TOOL.encrypt("{zebrunner:Zebrunner}", "\\{zebrunner:(?<data>.+)\\}", "[crypted-by-zebrunner:%s]"),
                "[crypted-by-zebrunner:Gy1n4N2oIy/iUfFeCNgjKA==]");
    }

    @Test(expectedExceptions = { RuntimeException.class })
    public static void encryptTestWithPatternWithoutDataGroup() {
        Algorithm algorithm = Algorithm.AES_128_ECB_PKCS5_PADDING;
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
        Algorithm algorithm = Algorithm.AES_128_ECB_NO_PADDING;
        String srtToEncrypt = "2022-08-07-11:35 ABCDEFJ TEST TEST TEST TEsT tEsT TEST TEST TEST TEsT TETEsTTEsTTEsTTEsTTEsTTEsT";
        String secretKey = SecretKeyManager.generateKeyAsString(algorithm);
        CryptoTool cryptoTool = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();
        String encryptedStr = cryptoTool.encrypt(srtToEncrypt);
        Assert.assertEquals(cryptoTool.decrypt(encryptedStr), srtToEncrypt);
    }

    @Test
    public static void encyptDecryptWithAES_128_ECB_PKCS5_PADDING() throws NoSuchAlgorithmException {
        Algorithm algorithm = Algorithm.AES_128_ECB_PKCS5_PADDING;
        String srtToEncrypt = "2022-08-07-11:35 TEST TEST TEST TEsT tEsT TEST TEST TEST TEsT tEsT TEST TEST TEST TEsT tEsT TEST TEST TEST TEsT tEsT";
        String secretKey = SecretKeyManager.generateKeyAsString(algorithm);
        CryptoTool cryptoTool = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();
        String encryptedStr = cryptoTool.encrypt(srtToEncrypt);
        Assert.assertEquals(cryptoTool.decrypt(encryptedStr), srtToEncrypt);
    }

    @Test
    public static void encyptDecryptWithAES_128_ECB_ISO10126PADDINGTest() throws NoSuchAlgorithmException {
        Algorithm algorithm = Algorithm.AES_128_ECB_ISO10126PADDING;
        String srtToEncrypt = "2022-08-07-11:35 AES_128_ECB_ISO10126PADDING";
        String secretKey = SecretKeyManager.generateKeyAsString(algorithm);
        CryptoTool cryptoTool = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();
        String encryptedStr = cryptoTool.encrypt(srtToEncrypt);
        Assert.assertEquals(cryptoTool.decrypt(encryptedStr), srtToEncrypt);
    }

    @Test
    public static void encyptDecryptWithAES_256_ECB_NO_PADDINGTest() throws NoSuchAlgorithmException {
        Algorithm algorithm = Algorithm.AES_256_ECB_NO_PADDING;
        String srtToEncrypt = "2022-08-07-11:35 AES_256_E AES_256_E AES_256_E AES_256_E A ";
        String secretKey = SecretKeyManager.generateKeyAsString(algorithm);
        CryptoTool cryptoTool = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();
        String encryptedStr = cryptoTool.encrypt(srtToEncrypt);
        Assert.assertEquals(cryptoTool.decrypt(encryptedStr), srtToEncrypt);
    }

    @Test
    public static void encyptDecryptWithDES_56_ECB_PKS5_PADDINGTest() throws NoSuchAlgorithmException {
        Algorithm algorithm = Algorithm.DES_56_ECB_PKS5_PADDING;
        String srtToEncrypt = "2022-08-07-11:35 DES_56_ECB_PKS5_PADDING";
        String secretKey = SecretKeyManager.generateKeyAsString(algorithm);
        CryptoTool cryptoTool = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();
        String encryptedStr = cryptoTool.encrypt(srtToEncrypt);
        Assert.assertEquals(cryptoTool.decrypt(encryptedStr), srtToEncrypt);
    }

    @Test
    public static void encyptDecryptWithDES_56_ECB_ISO10126PADDINGTest() throws NoSuchAlgorithmException {
        Algorithm algorithm = Algorithm.DES_56_ECB_ISO10126PADDING;
        String srtToEncrypt = "2022-08-07-11:35 DES_56_ECB_ISO10126PADDING";
        String secretKey = SecretKeyManager.generateKeyAsString(algorithm);
        CryptoTool cryptoTool = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();
        String encryptedStr = cryptoTool.encrypt(srtToEncrypt);
        Assert.assertEquals(cryptoTool.decrypt(encryptedStr), srtToEncrypt);
    }

    @Test
    public static void encyptDecryptWithDES_56_ECB_NO_PADDINGTest() throws NoSuchAlgorithmException {
        Algorithm algorithm = Algorithm.DES_56_ECB_NO_PADDING;
        String srtToEncrypt = "2022-08-07-11:35 DES_56";
        String secretKey = SecretKeyManager.generateKeyAsString(algorithm);
        CryptoTool cryptoTool = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();
        String encryptedStr = cryptoTool.encrypt(srtToEncrypt);
        Assert.assertEquals(cryptoTool.decrypt(encryptedStr), srtToEncrypt);
    }

    @Test
    public static void encyptDecryptWithDESEDE_168_ECB_NO_PADDINGTest() throws NoSuchAlgorithmException {
        Algorithm algorithm = Algorithm.DESEDE_168_ECB_NO_PADDING;
        String srtToEncrypt = "2022-08-07-11:35 DESEDE_168_ECB_NO_PADDING";
        String secretKey = SecretKeyManager.generateKeyAsString(algorithm);
        CryptoTool cryptoTool = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();
        String encryptedStr = cryptoTool.encrypt(srtToEncrypt);
        Assert.assertEquals(cryptoTool.decrypt(encryptedStr), srtToEncrypt);
    }

    @Test
    public static void encyptDecryptWithDESEDE_168_ECB_ISO10126PADDINGTest() throws NoSuchAlgorithmException {
        Algorithm algorithm = Algorithm.DESEDE_168_ECB_ISO10126PADDING;
        String srtToEncrypt = "2022-08-07-11:35 DESEDE_168_ECB_ISO10126PADDING";
        String secretKey = SecretKeyManager.generateKeyAsString(algorithm);
        CryptoTool cryptoTool = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();
        String encryptedStr = cryptoTool.encrypt(srtToEncrypt);
        Assert.assertEquals(cryptoTool.decrypt(encryptedStr), srtToEncrypt);
    }

    @Test
    public static void encyptDecryptWithRC2_168Test() throws NoSuchAlgorithmException {
        Algorithm algorithm = Algorithm.RC2_168;
        String srtToEncrypt = "2022-08-07-11:35 RC2_168";
        String secretKey = SecretKeyManager.generateKeyAsString(algorithm);
        CryptoTool cryptoTool = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();
        String encryptedStr = cryptoTool.encrypt(srtToEncrypt);
        Assert.assertEquals(cryptoTool.decrypt(encryptedStr), srtToEncrypt);
    }

    @Test
    public static void encyptDecryptWithARCFOUR_128Test() throws NoSuchAlgorithmException {
        Algorithm algorithm = Algorithm.ARCFOUR_128;
        String srtToEncrypt = "2022-08-07-11:35 ARCFOUR_128";
        String secretKey = SecretKeyManager.generateKeyAsString(algorithm);
        CryptoTool cryptoTool = CryptoToolBuilder.builder()
                .chooseAlgorithm(algorithm)
                .setKey(secretKey)
                .build();
        String encryptedStr = cryptoTool.encrypt(srtToEncrypt);
        Assert.assertEquals(cryptoTool.decrypt(encryptedStr), srtToEncrypt);
    }
}
