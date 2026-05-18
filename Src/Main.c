#include "AES.h"
#include "ByteBuffer.h"
#include "KDF.h"
#include "Password.h"

#define REQUIRED_ARGS                                                          \
    REQUIRED_CHAR_ARG(                                                         \
        operation,                                                             \
        "operation",                                                           \
        "Operation to perform: 'e' for encrypt, 'd' for decrypt"               \
    )                                                                          \
    REQUIRED_STRING_ARG(                                                       \
        inputFilePath, "input file", "Input file path. Use '-' for stdin"      \
    )

#define OPTIONAL_ARGS                                                          \
    OPTIONAL_STRING_ARG(                                                       \
        outputFilePath,                                                        \
        "",                                                                    \
        "-o",                                                                  \
        "output file",                                                         \
        "Output file path. Use '-' for stdout"                                 \
    )                                                                          \
    OPTIONAL_STRING_ARG(                                                       \
        passwordFilePath, "", "-p", "password file", "Password file path"      \
    )                                                                          \
    OPTIONAL_STRING_ARG(                                                       \
        symmetricAlgorithm,                                                    \
        "aes-256-cbc",                                                         \
        "-s",                                                                  \
        "symmetric algorithm",                                                 \
        "Symmetric encryption algorithm to use"                                \
    )                                                                          \
    OPTIONAL_STRING_ARG(                                                       \
        keyDerivationFunction,                                                 \
        "zeropad",                                                             \
        "-k",                                                                  \
        "key derivation function",                                             \
        "Key derivation function to use"                                       \
    )

#define BOOLEAN_ARGS BOOLEAN_ARG(help, "-h", "Show help")

#include <easyargs.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    args_t args = make_default_args();

    if (!parse_args(argc, argv, &args) || args.help) {
        print_help(argv[0]);
        printf("\nSYMMETRIC ALGORITHMS:\n");
        printf(
            "    aes-256-cbc: AES encryption in CBC mode with 256-bit keys\n"
        );
        printf("\nKEY DERIVATION FUNCTIONS:\n");
        printf(
            "    zeropad: Derive key by padding password with zeros or "
            "truncating to fit key size\n"
        );
        return 1;
    }

    if (!strcmp(args.inputFilePath, "-") && !args.passwordFilePath) {
        fprintf(
            stderr,
            "Error: --password-file is required when input file is '-'.\n"
        );
        return 1;
    } else if (strcmp(args.outputFilePath, "-") && !args.passwordFilePath) {
        fprintf(
            stderr,
            "Error: --password-file is required when output file is '-'.\n"
        );
        return 1;
    }

    if (!strcmp(args.outputFilePath, "")) {
        if (!strcmp(args.inputFilePath, "-")) {
            args.outputFilePath = "-";
        } else {
            args.outputFilePath = (char *) malloc(
                (strlen(args.inputFilePath) + 5) * sizeof(char)
            );
            if (!args.outputFilePath) {
                fprintf(
                    stderr, "Failed to allocate memory for output file path.\n"
                );
                return 1;
            }
            sprintf(
                args.outputFilePath,
                "%s.%s",
                args.inputFilePath,
                args.operation == 'e' ? "enc" : "dec"
            );
        }
    }

    char *password;
    size_t passwordSizeInBytes;
    if (args.passwordFilePath && strcmp(args.passwordFilePath, "")) {
        FILE *passwordFileHandle = fopen(args.passwordFilePath, "rb");
        if (!passwordFileHandle) {
            fprintf(
                stderr,
                "Failed to open password file: %s\n",
                args.passwordFilePath
            );
            return 1;
        }

        passwordSizeInBytes =
            ReadFileToBuffer(passwordFileHandle, (void **) &password);
        fclose(passwordFileHandle);

        if (!passwordSizeInBytes) {
            fprintf(
                stderr,
                "Failed to read password from file: %s\n",
                args.passwordFilePath
            );
            return 1;
        }
    } else {
        password = PromptForPassword(args.operation == 'e');
        if (!password) {
            return 1;
        }
        passwordSizeInBytes = strlen(password);
    }

    FILE *inputFileHandle = strcmp(args.inputFilePath, "-")
                                ? fopen(args.inputFilePath, "rb")
                                : stdin;
    if (!inputFileHandle) {
        fprintf(stderr, "Failed to open input file: %s\n", args.inputFilePath);
        return 1;
    }

    FILE *outputFileHandle = strcmp(args.outputFilePath, "-")
                                 ? fopen(args.outputFilePath, "wb")
                                 : stdout;
    if (!outputFileHandle) {
        fprintf(
            stderr, "Failed to open output file: %s\n", args.outputFilePath
        );
        return 1;
    }

    unsigned char *inputBytes;
    size_t inputBytesSizeInBytes =
        ReadFileToBuffer(inputFileHandle, (void **) &inputBytes);
    if (!inputBytesSizeInBytes) {
        return 1;
    }

    size_t keySizeInBytes = 0;
    if (!strcmp(args.symmetricAlgorithm, "aes-256-cbc")) {
        keySizeInBytes = AES_KEY_SIZE_IN_BYTES;
    } else {
        fprintf(
            stderr,
            "Unsupported symmetric algorithm: %s\n",
            args.symmetricAlgorithm
        );
        return 1;
    }

    unsigned char *key;
    if (!strcmp(args.keyDerivationFunction, "zeropad")) {
        key = KDFPadWithZeros(password, passwordSizeInBytes, keySizeInBytes);
    } else {
        fprintf(
            stderr,
            "Unsupported key derivation function: %s\n",
            args.keyDerivationFunction
        );
        return 1;
    }

    unsigned char *outputBytes;
    size_t outputBytesSizeInBytes;

    if (args.operation == 'e') {
        unsigned char *iv;
        outputBytesSizeInBytes = AES256CBCEncrypt(
            inputBytes, inputBytesSizeInBytes, key, &iv, &outputBytes
        );

        fwrite(
            iv, sizeof(unsigned char), AES_IV_SIZE_IN_BYTES, outputFileHandle
        );

        free(iv);

    } else {
        if (inputBytesSizeInBytes < AES_IV_SIZE_IN_BYTES) {
            fprintf(stderr, "Invalid input file: too small to contain IV.\n");
            return 1;
        }

        unsigned char *iv = (unsigned char *) malloc(
            AES_IV_SIZE_IN_BYTES * sizeof(unsigned char)
        );
        memcpy(iv, inputBytes, AES_IV_SIZE_IN_BYTES);

        outputBytesSizeInBytes = AES256CBCDecrypt(
            inputBytes + AES_IV_SIZE_IN_BYTES,
            inputBytesSizeInBytes - AES_IV_SIZE_IN_BYTES,
            key,
            iv,
            &outputBytes
        );

        free(iv);
    }

    fwrite(
        outputBytes,
        sizeof(unsigned char),
        outputBytesSizeInBytes,
        outputFileHandle
    );

    free(key);
    free(outputBytes);

    return 0;
}
