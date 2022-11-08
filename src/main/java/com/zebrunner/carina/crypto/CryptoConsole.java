package com.zebrunner.carina.crypto;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CryptoConsole {

    private static final Logger LOGGER = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private static final String DEFAULT_PATTERN = "\\{crypt:(?<data>.+?)\\}";
    private static final String DEFAULT_WRAPPER = "{crypt:%s}";

    private static final String ENCRYPTED_FILE_POSTFIX = "_encrypted.";

    private static final String HELP_ARG = "help";
    private static final String ENCRYPT_ARG = "encrypt";
    private static final String DECRYPT_ARG = "decrypt";
    private static final String GENERATE_KEY_ARG = "generate";
    private static final String ALGORITHM = "algorithm";
    private static final String FILE_ARG = "file";
    private static final String STRING_ARG = "string";
    private static final String KEY_ARG = "key";
    private static final String KEY_SIZE = "keysize";
    private static final String WRAPPER = "wrapper";
    private static final String PATTERN = "pattern";

    public static void main(String[] args) {
        CommandLineParser parser = new DefaultParser();
        Options options = getOptions();
        try {
            CommandLine line = parser.parse(options, args);

            if (line.hasOption(HELP_ARG)) {
                HelpFormatter helpFormatter = new HelpFormatter();
                helpFormatter.printHelp("CryptoConsole", options);
                return;
            }

            if (line.hasOption(GENERATE_KEY_ARG)) {
                Algorithm algorithm = parseAlgorithm(line);
                int keySize = parseKeySize(line);
                String secretKey = SecretKeyManager.generateKeyAsString(algorithm, keySize);
                LOGGER.info("Secret key was successfully generated. Copy it:   {}", secretKey);
                return;
            }

            if (!line.hasOption(KEY_ARG)) {
                throw new IllegalCommandLineOptions(String.format("For encryption and decryption an option '%s' must be used to specify the key", KEY_ARG));
            }

            CryptoTool cryptoTool = CryptoToolBuilder.builder()
                    .chooseAlgorithm(parseAlgorithm(line))
                    .setKey(line.getOptionValue(KEY_ARG))
                    .build();

            if (line.hasOption(FILE_ARG)) {
                if (line.hasOption(ENCRYPT_ARG)) {
                    encryptFile(line, cryptoTool);
                } else if (line.hasOption(DECRYPT_ARG)) {
                    decryptFile(line, cryptoTool);
                } else {
                    throw new IllegalCommandLineOptions(String.format("Should be specified '%s' or '%s' options", ENCRYPT_ARG, DECRYPT_ARG));
                }
                return;
            }

            if (line.hasOption(STRING_ARG)) {
                if (line.hasOption(ENCRYPT_ARG)) {
                    LOGGER.info("Passed string: {}", line.getOptionValue(STRING_ARG));
                    String encryptedString = cryptoTool.encrypt(line.getOptionValue(STRING_ARG));
                    LOGGER.info("Encrypted string: {}", encryptedString);

                } else if (line.hasOption(DECRYPT_ARG)) {
                    LOGGER.info("Passed encrypted string: {}", line.getOptionValue(STRING_ARG));
                    String decryptedString = cryptoTool.decrypt(line.getOptionValue(STRING_ARG));
                    LOGGER.info("Decrypted string: {}", decryptedString);
                }
            }
        } catch (IOException | ParseException | NoSuchAlgorithmException e) {
            LOGGER.error(e.getMessage());
            LOGGER.info("Usage examples: \n"
                    + "com.zebrunner.carina.crypto.CryptoConsole -help \n"
                    + "com.zebrunner.carina.crypto.CryptoConsole -generate -algorithm \"algorithm\" -keysize=\"key size\" \n"
                    + "com.zebrunner.carina.crypto.CryptoConsole -encrypt -algorithm \"algorithm\" -keysize=\"key size\" -key=\"key\" -string=\"string_to_encrypt\" \n"
                    + "com.zebrunner.carina.crypto.CryptoConsole -encrypt -algorithm \"algorithm\" -keysize=\"key size\" -key=\"key\" -string=\"string_to_encrypt\"  \n"
                    + "com.zebrunner.carina.crypto.CryptoConsole -encrypt -algorithm \"algorithm\" -keysize=\"key size\" -key=\"key\" -pattern=\"pattern\" -string=\"string_to_encrypt\"  \n"
                    + "com.zebrunner.carina.crypto.CryptoConsole -encrypt -algorithm \"algorithm\" -keysize=\"key size\" -key=\"key\" -wrapper=\"wrapper\" -string=\"string_to_encrypt\"  \n"
                    + "com.zebrunner.carina.crypto.CryptoConsole -encrypt -algorithm \"algorithm\" -keysize=\"key size\" -key=\"key\" -pattern=\"pattern\" -wrapper=\"wrapper\" -string=\"string_to_encrypt\"  \n"
                    + "com.zebrunner.carina.crypto.CryptoConsole -decrypt -algorithm \"algorithm\" -keysize=\"key size\" -key=\"key\" -string=\"string_to_encrypt\" \n"
                    + "com.zebrunner.carina.crypto.CryptoConsole -decrypt -algorithm \"algorithm\" -keysize=\"key size\" -key=\"key\" -string=\"string_to_encrypt\"  \n"
                    + "com.zebrunner.carina.crypto.CryptoConsole -decrypt -algorithm \"algorithm\" -keysize=\"key size\" -key=\"key\" -pattern=\"pattern\" -string=\"string_to_encrypt\"  \n"
                    + "com.zebrunner.carina.crypto.CryptoConsole -decrypt -algorithm \"algorithm\" -keysize=\"key size\" -key=\"key\" -wrapper=\"wrapper\" -string=\"string_to_encrypt\"  \n"
                    + "com.zebrunner.carina.crypto.CryptoConsole -decrypt -algorithm \"algorithm\" -keysize=\"key size\" -key=\"key\" -pattern=\"pattern\" -wrapper=\"wrapper\" -string=\"string_to_encrypt\"  \n"
                    + "com.zebrunner.carina.crypto.CryptoConsole -encrypt -algorithm \"algorithm\" -keysize=\"key size\" -key=\"key\" -file=\"path_to_file_to_encrypt\" \n"
                    + "com.zebrunner.carina.crypto.CryptoConsole -decrypt -algorithm \"algorithm\" -keysize=\"key size\" -key=\"key\" -file=\"path_to_file_to_encrypt\" \n");
        }
    }

    private static void encryptFile(CommandLine line, CryptoTool cryptoTool) throws IOException {
        File inFile = new File(line.getOptionValue(FILE_ARG));
        if (!inFile.exists()) {
            throw new FileNotFoundException(
                    String.format("The file specified via the '%s' option does not exists. Path to file provided via option: %s",
                            FILE_ARG, line.getOptionValue(FILE_ARG)));
        }

        if (inFile.getName().contains(ENCRYPTED_FILE_POSTFIX)) {
            LOGGER.warn("File located on the path '{}'  contains '{}' in it's filename. There is a possibility that it was already encrypted",
                    inFile.getAbsolutePath(), ENCRYPTED_FILE_POSTFIX);
        }

        // todo implement replacement only in the file name, not in the entire path
        File outFile = new File(StringUtils.replace(inFile.getAbsolutePath(), ".", ENCRYPTED_FILE_POSTFIX));
        if (outFile.exists()) {
            LOGGER.warn("The file located on the path: '{}' already exists. The existing file will be deleted", outFile.getAbsolutePath());
            if (!outFile.delete()) {
                throw new IOException(
                        String.format("The file specified via the '%s' option cannot be deleted. Path to file provided via option: %s",
                                FILE_ARG, line.getOptionValue(FILE_ARG)));
            }
        }
        boolean isCreated = outFile.createNewFile();
        if (!isCreated) {
            throw new IOException("Something went wrong when try to create new file");
        }

        FileUtils.writeByteArrayToFile(outFile,
                cryptoTool.encrypt(new String(FileUtils.readFileToByteArray(inFile)),
                        parsePattern(line),
                        parseWrapper(line))
                        .getBytes());
        LOGGER.info("Encrypted file saved by path: {}", outFile.getAbsolutePath());
    }

    private static void decryptFile(CommandLine line, CryptoTool cryptoTool) throws IOException {
        File inFile = new File(line.getOptionValue(FILE_ARG));
        if (!inFile.exists()) {
            throw new FileNotFoundException(
                    String.format("The file specified via the '%s' option does not exists. Path to file provided via option: %s",
                            FILE_ARG, line.getOptionValue(FILE_ARG)));
        }

        if (!inFile.getName().contains(ENCRYPTED_FILE_POSTFIX)) {
            LOGGER.warn("File located on the path '{}' is not contains '{}' in it's filename. There is a possibility that it was not encrypted",
                    inFile.getAbsolutePath(), ENCRYPTED_FILE_POSTFIX);
        }

        // fixme implement replacement only in the file name, not in the entire path
        File outFile = new File(StringUtils.replace(inFile.getAbsolutePath(), ENCRYPTED_FILE_POSTFIX, "."));
        if (outFile.exists()) {
            LOGGER.warn("The file located on the path: '{}' already exists. The existing file will be deleted", outFile.getAbsolutePath());
            if (!outFile.delete()) {
                throw new IOException(
                        String.format("The file specified via the '%s' option cannot be deleted. Path to file provided via option: %s",
                                FILE_ARG, line.getOptionValue(FILE_ARG)));
            }
        }
        boolean isCreated = outFile.createNewFile();
        if (!isCreated) {
            throw new IOException("Something went wrong when try to create new file");
        }

        FileUtils.writeByteArrayToFile(outFile,
                cryptoTool.decrypt(
                        new String(FileUtils.readFileToByteArray(inFile)),
                        parsePattern(line),
                        parseWrapper(line))
                        .getBytes());
        LOGGER.info("Decrypted file saved by path: {}", outFile.getAbsolutePath());
    }

    private static Algorithm parseAlgorithm(CommandLine line) {
        if (!line.hasOption(ALGORITHM)) {
            throw new IllegalCommandLineOptions("The algorithm is not specified. To specify algorithm, use the option " + ALGORITHM);
        }
        return Algorithm.find(line.getOptionValue(ALGORITHM));
    }

    private static int parseKeySize(CommandLine line) {
        if (!line.hasOption(KEY_SIZE)) {
            throw new IllegalCommandLineOptions("The key size is not specified. To specify key size, use the option " + KEY_SIZE);
        }
        return Integer.parseInt(line.getOptionValue(KEY_SIZE));
    }

    private static String parseWrapper(CommandLine line) {
        if (!line.hasOption(WRAPPER)) {
            LOGGER.warn("The wrapper is not specified. The default wrapper will be used: '{}'. To specify wrapper, use the option '{}'",
                    DEFAULT_WRAPPER, WRAPPER);
        }
        return line.hasOption(WRAPPER) ? line.getOptionValue(WRAPPER) : DEFAULT_WRAPPER;
    }

    private static String parsePattern(CommandLine line) {
        if (!line.hasOption(PATTERN)) {
            LOGGER.warn("The pattern is not specified. The default pattern will be used: '{}'. To specify pattern, use the option '{}'",
                    DEFAULT_PATTERN, PATTERN);
        }
        return line.hasOption(PATTERN) ? line.getOptionValue(PATTERN) : DEFAULT_PATTERN;
    }

    private static Options getOptions() {
        Options options = new Options();
        options.addOption(HELP_ARG, false, "usage information");
        options.addOption(Option.builder().hasArg(false).argName(ENCRYPT_ARG).longOpt(ENCRYPT_ARG).desc("action for encrypt").build());
        options.addOption(Option.builder().hasArg(false).argName(DECRYPT_ARG).longOpt(DECRYPT_ARG).desc("action for decrypt").build());
        options.addOption(Option.builder().hasArg(false).argName(GENERATE_KEY_ARG).longOpt(GENERATE_KEY_ARG).desc("action to generate key").build());
        options.addOption(Option.builder().hasArg(true).numberOfArgs(1).argName(ALGORITHM).longOpt(ALGORITHM)
                .desc("algorithm to encrypt/decrypt/generate key").build());
        options.addOption(
                Option.builder().hasArg(true).numberOfArgs(1).argName(FILE_ARG).longOpt(FILE_ARG).hasArg().desc("file to encrypt/decrypt").build());
        options.addOption(Option.builder().hasArg(true).numberOfArgs(1).argName(STRING_ARG).longOpt(STRING_ARG).hasArg()
                .desc("string to encrypt/decrypt").build());
        options.addOption(Option.builder().hasArg(true).numberOfArgs(1).argName(KEY_ARG).longOpt(KEY_ARG).hasArg().desc("secret key").build());
        options.addOption(Option.builder().hasArg(true).numberOfArgs(1).argName(WRAPPER).longOpt(WRAPPER).hasArg()
                .desc("wrapper for encrypted/decrypted text according to Formatter convention").build());
        options.addOption(Option.builder().hasArg(true).numberOfArgs(1).argName(PATTERN).longOpt(PATTERN).hasArg()
                .desc("the pattern by which text sections will be searched for encryption/decryption. Must contains group data").build());
        options.addOption(Option.builder().hasArg(true).numberOfArgs(1).argName(KEY_SIZE).longOpt(KEY_SIZE).hasArg().desc("key size").build());

        return options;
    }
}
