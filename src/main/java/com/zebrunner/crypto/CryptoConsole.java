package com.zebrunner.crypto;

import java.io.File;
import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Pattern;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.config.Configurator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CryptoConsole {

    private static final Logger LOGGER = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    public static final Algorithm DEFAULT_ALGORITHM = Algorithm.AES;
    public static final Pattern DEFAULT_PATTERN = Pattern.compile("[{]crypt[:](?<data>.+)[}]");
    public static final String DEFAULT_WRAPPER = "{crypto:%s}";

    private static final String HELP_ARG = "help";
    private static final String ENCRYPT_ARG = "encrypt";
    private static final String DECRYPT_ARG = "decrypt";
    private static final String GENERATE_KEY_ARG = "generate";
    private static final String ALGORITHM = "algorithm";
    private static final String FILE_ARG = "file";
    private static final String STRING_ARG = "string";
    private static final String KEY_ARG = "key";
    private static final String WRAPPER = "wrapper";
    private static final String PATTERN = "pattern";

    public static void main(String[] args) {
        Configurator.setRootLevel(Level.INFO);

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
                String secretKey = SecretKeyManager.generateKeyAsString(algorithm.getType(), algorithm.getSize());
                LOGGER.info("Secret key was successfully generated. Copy it:   {}", secretKey);
                return;
            }

            if (!line.hasOption(KEY_ARG)) {
                throw new RuntimeException(String.format("For encryption and decryption an option '%s' must be used to specify the key", KEY_ARG));
            }

            CryptoTool cryptoTool = CryptoToolBuilder.builder()
                    .chooseAlgorithm(parseAlgorithm(line))
                    .setKey(line.getOptionValue(KEY_ARG))
                    .build();

            if (line.hasOption(FILE_ARG)) {
                File inFile = new File(line.getOptionValue(FILE_ARG));
                if (!inFile.exists()) {
                    throw new RuntimeException(
                            String.format("The file specified via the '%s' option does not exists. Path to file provided via option: %s",
                                    FILE_ARG, line.getOptionValue(FILE_ARG)));
                }

                // todo refactor
                File outFile = new File(StringUtils.replace(inFile.getAbsolutePath(), ".", "_encrypted."));
                if (outFile.exists()) {
                    if (!outFile.delete()) {
                        throw new RuntimeException(
                                String.format("The file specified via the '%s' option cannot be deleted. Path to file provided via option: %s",
                                        FILE_ARG, line.getOptionValue(FILE_ARG)));
                    }
                }
                outFile.createNewFile();

                if (line.hasOption(ENCRYPT_ARG)) {
                    FileUtils.writeByteArrayToFile(outFile,
                            cryptoTool.encrypt(
                                    new String(FileUtils.readFileToByteArray(inFile)),
                                    parsePattern(line),
                                    parseWrapper(line)).getBytes());
                    LOGGER.info("Encrypted file saved by path: {}", outFile.getAbsolutePath());
                } else if (line.hasOption(DECRYPT_ARG)) {
                    FileUtils.writeByteArrayToFile(outFile,
                            cryptoTool.decrypt(
                                    new String(FileUtils.readFileToByteArray(inFile)),
                                    parsePattern(line),
                                    parseWrapper(line)).getBytes());
                    LOGGER.info("Decrypted file saved by path: {}", outFile.getAbsolutePath());
                } else {
                    throw new RuntimeException(String.format("Should be specified '%s' or '%s' options", ENCRYPT_ARG, DECRYPT_ARG));
                }
                return;
            }

            if (line.hasOption(STRING_ARG)) {
                if (line.hasOption(ENCRYPT_ARG)) {
                    LOGGER.info("Passed string: {}", line.getOptionValue(STRING_ARG));
                    LOGGER.info("Encrypted string: {}", cryptoTool.encrypt(line.getOptionValue(STRING_ARG)));

                } else if (line.hasOption(DECRYPT_ARG)) {
                    LOGGER.info("Passed encrypted string: {}", line.getOptionValue(STRING_ARG));
                    LOGGER.info("Decrypted string: {}", cryptoTool.decrypt(line.getOptionValue(STRING_ARG)));
                }
                return;
            }
        } catch (IOException | ParseException | NoSuchAlgorithmException e) {
            LOGGER.error(e.getMessage());
            // todo change examples
            LOGGER.info("Usage examples: \n"
                    + "com.zebrunner.crypto.CryptoConsole -generate -key_file \"file_path_to_save_key\" \n"
                    + "com.zebrunner.crypto.CryptoConsole -encrypt -string \"string_to_encrypt\" -key_file \"key_file_path\" \n"
                    + "com.zebrunner.crypto.CryptoConsole -decrypt -string \"string_to_decrypt\" -key_file \"key_file_path\" \n"
                    + "com.zebrunner.crypto.CryptoConsole -encrypt -file \"csv_file_to_encrypt\" -key_file \"key_file_path\" \n"
                    + "com.zebrunner.crypto.CryptoConsole -decrypt -file \"csv_file_to_decrypt\" -key_file \"key_file_path\" \n");

        }
    }

    private static Algorithm parseAlgorithm(CommandLine line) {
        if (!line.hasOption(ALGORITHM)) {
            LOGGER.warn("The pattern is not specified. The default algorithm will be used: '{}'. To specify algorithm, use the option '{}'",
                    DEFAULT_ALGORITHM, ALGORITHM);
        }
        return line.hasOption(ALGORITHM) ? Algorithm.fromString(line.getOptionValue(ALGORITHM)) : DEFAULT_ALGORITHM;
    }

    private static String parseWrapper(CommandLine line) {
        if (!line.hasOption(WRAPPER)) {
            LOGGER.warn("The wrapper is not specified. The default wrapper will be used: '{}'. To specify wrapper, use the option '{}'",
                    DEFAULT_WRAPPER, WRAPPER);
        }
        return line.hasOption(WRAPPER) ? line.getOptionValue(WRAPPER) : DEFAULT_WRAPPER;
    }

    private static Pattern parsePattern(CommandLine line) {
        if (!line.hasOption(PATTERN)) {
            LOGGER.warn("The pattern is not specified. The default pattern will be used: '{}'. To specify pattern, use the option '{}'",
                    DEFAULT_PATTERN, PATTERN);
        }
        return line.hasOption(PATTERN) ? Pattern.compile(line.getOptionValue(PATTERN)) : DEFAULT_PATTERN;

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
        options.addOption(Option.builder().hasArg(true).numberOfArgs(1).argName(WRAPPER).longOpt(WRAPPER).hasArg().desc("wrapper").build());
        options.addOption(Option.builder().hasArg(true).numberOfArgs(1).argName(PATTERN).longOpt(PATTERN).hasArg().desc("pattern").build());
        return options;
    }
}
