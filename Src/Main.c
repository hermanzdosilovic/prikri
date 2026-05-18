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
#include <openssl/evp.h>
#include <openssl/rand.h>

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

    const EVP_CIPHER *cipher;
    if (!strcmp(args.symmetricAlgorithm, "aes-256-cbc")) {
        cipher = EVP_aes_256_cbc();
    } else if (!strcmp(args.symmetricAlgorithm, "des-cbc")) {
        cipher = EVP_des_cbc();
    } else if (!strcmp(args.symmetricAlgorithm, "3des-cbc")) {
        cipher = EVP_des_ede3_cbc();
    } else {
        fprintf(
            stderr,
            "Unsupported symmetric algorithm: %s\n",
            args.symmetricAlgorithm
        );
        return 1;
    }

    size_t keySizeInBytes =
        EVP_CIPHER_key_length(cipher) * sizeof(unsigned char);
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

    size_t ivSizeInBytes = EVP_CIPHER_iv_length(cipher) * sizeof(unsigned char);
    unsigned char *iv = (unsigned char *) malloc(ivSizeInBytes);
    if (!iv) {
        fprintf(stderr, "Failed to allocate memory for IV.\n");
        return 1;
    }

    unsigned char *outputBytes;
    size_t outputBytesSizeInBytes = 0;

    if (args.operation == 'e') {
        RAND_bytes(iv, ivSizeInBytes);

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX_init(ctx);

        EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);

        outputBytes = (unsigned char *) malloc(
            (inputBytesSizeInBytes + EVP_CIPHER_block_size(cipher)) *
            sizeof(unsigned char)
        );
        if (!outputBytes) {
            fprintf(stderr, "Failed to allocate memory for output bytes.\n");
            return 1;
        }

        int outLen = 0;
        EVP_EncryptUpdate(
            ctx, outputBytes, &outLen, inputBytes, inputBytesSizeInBytes
        );

        outputBytesSizeInBytes = outLen;
        EVP_EncryptFinal_ex(ctx, outputBytes + outLen, &outLen);
        outputBytesSizeInBytes += outLen;

        EVP_CIPHER_CTX_free(ctx);

        fwrite(iv, sizeof(unsigned char), ivSizeInBytes, outputFileHandle);

        free(iv);
    } else {
        memcpy(iv, inputBytes, ivSizeInBytes);

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX_init(ctx);

        EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);

        outputBytes = (unsigned char *) malloc(
            (inputBytesSizeInBytes - ivSizeInBytes +
             EVP_CIPHER_block_size(cipher)) *
            sizeof(unsigned char)
        );

        int outLen = 0;
        EVP_DecryptUpdate(
            ctx,
            outputBytes,
            &outLen,
            inputBytes + ivSizeInBytes,
            inputBytesSizeInBytes - ivSizeInBytes
        );

        outputBytesSizeInBytes = outLen;
        EVP_DecryptFinal_ex(ctx, outputBytes + outLen, &outLen);
        outputBytesSizeInBytes += outLen;

        EVP_CIPHER_CTX_free(ctx);

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
