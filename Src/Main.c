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
        symmetricCipher,                                                       \
        "aes-256-cbc",                                                         \
        "-s",                                                                  \
        "symmetric cipher",                                                    \
        "Symmetric cipher to use"                                              \
    )                                                                          \
    OPTIONAL_STRING_ARG(                                                       \
        keyDerivationFunction,                                                 \
        "sha3-256",                                                            \
        "-k",                                                                  \
        "key derivation function",                                             \
        "Key derivation function to use"                                       \
    )

#define BOOLEAN_ARGS BOOLEAN_ARG(help, "-h", "Show help")

#include <easyargs.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

int main(int argc, char **argv) {
    args_t args = make_default_args();

    if (!parse_args(argc, argv, &args) || args.help) {
        print_help(argv[0]);
        printf("\nSUPPORTED SYMMETRIC CIPHERS:\n");
        printf(
            "    aes-256-cbc: AES encryption in CBC mode with 256-bit keys\n"
            "    des-cbc: DES encryption in CBC mode\n"
            "    3des-cbc: Triple DES encryption in CBC mode\n"
        );
        printf("\nSUPPORTED KEY DERIVATION FUNCTIONS:\n");
        printf(
            "    zeropad: Derive key by padding password with zeros or "
            "truncating to fit key size\n"
            "    sha1: Derive key using SHA-1 hash function\n"
            "    sha224: Derive key using SHA-224 hash function\n"
            "    sha256: Derive key using SHA-256 hash function\n"
            "    sha384: Derive key using SHA-384 hash function\n"
            "    sha512: Derive key using SHA-512 hash function\n"
            "    sha512-224: Derive key using SHA-512/224 hash function\n"
            "    sha512-256: Derive key using SHA-512/256 hash function\n"
            "    sha3-224: Derive key using SHA3-224 hash function\n"
            "    sha3-256: Derive key using SHA3-256 hash function\n"
            "    sha3-384: Derive key using SHA3-384 hash function\n"
            "    sha3-512: Derive key using SHA3-512 hash function\n"
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

    if (!strcmp(args.inputFilePath, "-") &&
        !strcmp(args.passwordFilePath, "")) {
        fprintf(
            stderr,
            "Error: --password-file is required when input file is '-'.\n"
        );
        return 1;
    } else if (
        !strcmp(args.outputFilePath, "-") &&
        !strcmp(args.passwordFilePath, "")) {
        fprintf(
            stderr,
            "Error: --password-file is required when output file is '-'.\n"
        );
        return 1;
    }

    const EVP_CIPHER *cipher;
    if (!strcmp(args.symmetricCipher, "aes-256-cbc")) {
        cipher = EVP_aes_256_cbc();
    } else if (!strcmp(args.symmetricCipher, "des-cbc")) {
        cipher = EVP_des_cbc();
    } else if (!strcmp(args.symmetricCipher, "3des-cbc")) {
        cipher = EVP_des_ede3_cbc();
    } else {
        fprintf(
            stderr,
            "Unsupported symmetric algorithm: %s\n",
            args.symmetricCipher
        );
        return 1;
    }

    if (strcmp(args.keyDerivationFunction, "zeropad") &&
        !EVP_get_digestbyname(args.keyDerivationFunction)) {
        fprintf(
            stderr,
            "Unsupported key derivation function: %s\n",
            args.keyDerivationFunction
        );
        return 1;
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

    unsigned char *inputBytes;
    size_t inputBytesSizeInBytes =
        ReadFileToBuffer(inputFileHandle, (void **) &inputBytes);
    if (!inputBytesSizeInBytes) {
        return 1;
    }

    OSSL_PROVIDER *default_provider = OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER *legacy_provider = OSSL_PROVIDER_load(NULL, "legacy");

    if (default_provider == NULL || legacy_provider == NULL) {
        fprintf(stderr, "Failed to load OpenSSL providers\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    size_t keySizeInBytes =
        EVP_CIPHER_key_length(cipher) * sizeof(unsigned char);
    unsigned char *key;
    if (!strcmp(args.keyDerivationFunction, "zeropad")) {
        key = KDFPadWithZeros(password, passwordSizeInBytes, keySizeInBytes);
        if (!key) {
            fprintf(stderr, "Failed to derive key using zero padding KDF.\n");
            return 1;
        }
    } else if (!strncmp(args.keyDerivationFunction, "sha", 3)) {
        const EVP_MD *md = EVP_get_digestbyname(args.keyDerivationFunction);
        if (!md) {
            fprintf(
                stderr,
                "Unsupported key derivation function: %s\n",
                args.keyDerivationFunction
            );
            return 1;
        }

        key = KDFSHA(
            password,
            passwordSizeInBytes,
            keySizeInBytes,
            args.keyDerivationFunction
        );
        if (!key) {
            fprintf(stderr, "Failed to derive key using SHA KDF.\n");
            return 1;
        }
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
        if (RAND_bytes(iv, ivSizeInBytes) != 1) {
            fprintf(stderr, "Failed to generate random IV.\n");
            return 1;
        }

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            fprintf(stderr, "Failed to create cipher context.\n");
            return 1;
        }
        EVP_CIPHER_CTX_init(ctx);

        if (!EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)) {
            fprintf(stderr, "Failed to initialize encryption.\n");
            return 1;
        }

        outputBytes = (unsigned char *) malloc(
            (inputBytesSizeInBytes + EVP_CIPHER_block_size(cipher)) *
            sizeof(unsigned char)
        );
        if (!outputBytes) {
            fprintf(stderr, "Failed to allocate memory for output bytes.\n");
            return 1;
        }

        int outLen = 0;
        if (!EVP_EncryptUpdate(
                ctx, outputBytes, &outLen, inputBytes, inputBytesSizeInBytes
            )) {
            fprintf(stderr, "Failed to encrypt the input bytes.\n");
            return 1;
        }

        outputBytesSizeInBytes = outLen;
        if (!EVP_EncryptFinal_ex(ctx, outputBytes + outLen, &outLen)) {
            fprintf(stderr, "Failed to finalize encryption.\n");
            return 1;
        }
        outputBytesSizeInBytes += outLen;

        EVP_CIPHER_CTX_free(ctx);

        if (fwrite(
                iv, sizeof(unsigned char), ivSizeInBytes, outputFileHandle
            ) != ivSizeInBytes) {
            fprintf(stderr, "Failed to write IV to output file.\n");
            return 1;
        }

        free(iv);
    } else if (args.operation == 'd') {
        if (inputBytesSizeInBytes < ivSizeInBytes) {
            fprintf(
                stderr,
                "Invalid input file: too small to contain IV. Minimum size is "
                "%zu bytes.\n",
                ivSizeInBytes
            );
            return 1;
        }

        memcpy(iv, inputBytes, ivSizeInBytes);

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            fprintf(stderr, "Failed to create cipher context.\n");
            return 1;
        }
        EVP_CIPHER_CTX_init(ctx);

        if (!EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
            fprintf(stderr, "Failed to initialize decryption.\n");
            return 1;
        }

        outputBytes = (unsigned char *) malloc(
            (inputBytesSizeInBytes - ivSizeInBytes +
             EVP_CIPHER_block_size(cipher)) *
            sizeof(unsigned char)
        );
        if (!outputBytes) {
            fprintf(stderr, "Failed to allocate memory for output bytes.\n");
            return 1;
        }

        int outLen = 0;
        if (!EVP_DecryptUpdate(
                ctx,
                outputBytes,
                &outLen,
                inputBytes + ivSizeInBytes,
                inputBytesSizeInBytes - ivSizeInBytes
            )) {
            fprintf(stderr, "Failed to decrypt the input bytes.\n");
            return 1;
        }

        outputBytesSizeInBytes = outLen;
        if (!EVP_DecryptFinal_ex(ctx, outputBytes + outLen, &outLen)) {
            fprintf(stderr, "Failed to finalize decryption.\n");
            return 1;
        }
        outputBytesSizeInBytes += outLen;

        EVP_CIPHER_CTX_free(ctx);

        free(iv);
    } else {
        fprintf(stderr, "Invalid operation: %c\n", args.operation);
        return 1;
    }

    if (fwrite(
            outputBytes,
            sizeof(unsigned char),
            outputBytesSizeInBytes,
            outputFileHandle
        ) != outputBytesSizeInBytes) {
        fprintf(stderr, "Failed to write output bytes to file.\n");
        return 1;
    }

    if (strcmp(args.outputFilePath, "-")) {
        printf(
            "%scryption result written to %s\n",
            args.operation == 'e' ? "En" : "De",
            args.outputFilePath
        );
    }

    free(key);
    free(outputBytes);

    return 0;
}
