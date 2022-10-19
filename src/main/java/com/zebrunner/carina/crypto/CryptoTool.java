package com.zebrunner.carina.crypto;

public interface CryptoTool {

    public static final String DEFAULT_PATTERN = "\\{crypt:(?<data>.+?)\\}";
    public static final String DEFAULT_WRAPPER = "{crypt:%s}";

    /**
     * Encrypts data
     *
     * @param str data to encrypt
     * @return encrypted data
     */
    String encrypt(String str);

    /**
     * Decrypts data
     *
     * @param srt encrypted data
     * @return decrypted data
     */
    String decrypt(String srt);

    /**
     * Encrypts all matches of text by pattern
     * A prerequisite is the presence of the data group in the pattern,
     * which indicates the data to be encrypted
     *
     * @param str data to encrypt
     * @param pattern the pattern by which text sections will be searched for encryption. Must contains group data
     * @return encrypted text
     * @see "https://docs.oracle.com/javase/8/docs/api/java/util/regex/Pattern.html#groupname"
     */
    String encrypt(String str, String pattern);

    /**
     * Decrypts all matches of text by pattern
     * A prerequisite is the presence of the data group in the pattern,
     * which indicates the data to be decrypted
     *
     * @param str data to decrypt
     * @param pattern the pattern by which text sections will be searched for decryption. Must contains group data
     * @return decrypted text
     * @see "https://docs.oracle.com/javase/8/docs/api/java/util/regex/Pattern.html#groupname"
     */
    String decrypt(String str, String pattern);

    /**
     * Encrypts all matches of text by pattern. Encrypted sections are wrapped according
     * to wrapper
     * A prerequisite is the presence of the data group in the pattern,
     * which indicates the data to be encrypted
     *
     * @param str data to encrypt
     * @param pattern the pattern by which text sections will be searched for encryption. Must contains group data
     * @param wrapper wrapper for encrypted text according to Formatter convention
     * @return encrypted text
     * @see "https://docs.oracle.com/javase/8/docs/api/java/util/Formatter.html"
     * @see "https://docs.oracle.com/javase/8/docs/api/java/util/regex/Pattern.html#groupname"
     */
    String encrypt(String str, String pattern, String wrapper);

    /**
     * Decrypts all matches of text by pattern. Decrypted sections are wrapped according
     * * to wrapper
     * A prerequisite is the presence of the data group in the pattern,
     * which indicates the data to be decrypted
     *
     * @param str data to decrypt
     * @param pattern the pattern by which text sections will be searched for decryption. Must contains group data
     * @param wrapper wrapper for decrypted text according to Formatter convention
     * @return decrypted text
     * @see "https://docs.oracle.com/javase/8/docs/api/java/util/regex/Pattern.html#groupname"
     */
    String decrypt(String str, String pattern, String wrapper);

    /**
     * Checks for at least one match of text according to the pattern
     *
     * @param str text
     * @param pattern patter. Must contain named group data
     * @return true if there are at least one match of text according to the pattern,
     *         and this pattern contains named group data, false otherwise
     */
    boolean hasMatch(String str, String pattern);
}
