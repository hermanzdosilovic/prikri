#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#define AES_KEY_SIZE_IN_BYTES 32
#define AES_BLOCK_SIZE_IN_BYTES 16
#define AES_IV_SIZE_IN_BYTES 16

#define MAX_PASSWORD_SIZE_IN_BYTES 4096

#define READ_BLOCK_SIZE_IN_BYTES 1024
#define INITIAL_READ_BUFFER_CAPACITY_IN_BYTES 1024

typedef struct {
    int isEncryptionMode;
    char *inputFile;
    char *outputFile;
    FILE *inputFileHandle;
    FILE *outputFileHandle;
} ProgramArguments;

unsigned char *deriveEncryptionKeyPadWithZeros(
    char *userKey,
    size_t userKeySizeInBytes,
    size_t encryptionKeySizeInBytes
) {
    unsigned char *key = (unsigned char *) calloc(
        encryptionKeySizeInBytes, sizeof(unsigned char)
    );

    memcpy(
        key,
        userKey,
        userKeySizeInBytes < encryptionKeySizeInBytes ? userKeySizeInBytes
                                                      : encryptionKeySizeInBytes
    );
    return key;
}

size_t AES256CBCEncrypt(
    unsigned char *plainText,
    size_t plainTextSizeInBytes,
    unsigned char *encryptionKey,
    unsigned char **iv,
    unsigned char **cipherText
) {
    *iv =
        (unsigned char *) malloc(AES_IV_SIZE_IN_BYTES * sizeof(unsigned char));
    RAND_bytes(*iv, AES_IV_SIZE_IN_BYTES);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, encryptionKey, *iv);

    *cipherText = (unsigned char *) malloc(
        (plainTextSizeInBytes + AES_BLOCK_SIZE_IN_BYTES) * sizeof(unsigned char)
    );

    int outLen = 0;
    EVP_EncryptUpdate(
        ctx, *cipherText, &outLen, plainText, plainTextSizeInBytes
    );

    size_t cipherTextSizeInBytes = outLen;
    EVP_EncryptFinal_ex(ctx, *cipherText + outLen, &outLen);
    cipherTextSizeInBytes += outLen;

    EVP_CIPHER_CTX_free(ctx);

    return cipherTextSizeInBytes;
}

size_t AES256CBCDecrypt(
    unsigned char *cipherText,
    size_t cipherTextSizeInBytes,
    unsigned char *encryptionKey,
    unsigned char *iv,
    unsigned char **plainText
) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, encryptionKey, iv);

    *plainText = (unsigned char *) malloc(
        (cipherTextSizeInBytes + AES_BLOCK_SIZE_IN_BYTES) *
        sizeof(unsigned char)
    );

    int outLen = 0;
    EVP_DecryptUpdate(
        ctx, *plainText, &outLen, cipherText, cipherTextSizeInBytes
    );

    size_t plainTextSizeInBytes = outLen;
    EVP_DecryptFinal_ex(ctx, *plainText + outLen, &outLen);
    plainTextSizeInBytes += outLen;

    EVP_CIPHER_CTX_free(ctx);

    return plainTextSizeInBytes;
}

void showUsage(char **argv) {
    printf("Usage: %s [e|d] [input file|-] [output file|-]\n\n", argv[0]);
}

char *askForPassword(char *prompt) {
    printf("%s", prompt);

    char *password = (char *) malloc(MAX_PASSWORD_SIZE_IN_BYTES * sizeof(char));

    if (!fgets(password, MAX_PASSWORD_SIZE_IN_BYTES, stdin)) {
        return NULL;
    }

    size_t len = strlen(password);
    if (len > 0 && password[len - 1] == '\n') {
        password[len - 1] = 0;
    }

    return password;
}

ProgramArguments *parseProgramArguments(int argc, char **argv) {
    ProgramArguments *programArguments =
        (ProgramArguments *) malloc(sizeof(ProgramArguments));

    if (argc == 1) {
        showUsage(argv);
        return NULL;
    }

    if (strcmp(argv[1], "e") && strcmp(argv[1], "d")) {
        printf("Invalid mode: %s\n", argv[1]);
        showUsage(argv);
        return NULL;
    }

    programArguments->isEncryptionMode = argv[1][0] == 'e';

    if (argc >= 3) {
        programArguments->inputFile = argv[2];
    } else {
        programArguments->inputFile = "-";
    }

    if (argc >= 4) {
        programArguments->outputFile = argv[3];
    } else {
        if (!strcmp(programArguments->inputFile, "-")) {
            programArguments->outputFile = "-";
        } else {
            programArguments->outputFile = (char *) malloc(
                (strlen(programArguments->inputFile) + 5) * sizeof(char)
            );
            sprintf(
                programArguments->outputFile,
                "%s.%s",
                programArguments->inputFile,
                programArguments->isEncryptionMode ? "enc" : "dec"
            );
        }
    }

    programArguments->inputFileHandle =
        strcmp(programArguments->inputFile, "-")
            ? fopen(programArguments->inputFile, "rb")
            : stdin;
    if (!programArguments->inputFileHandle) {
        printf("Failed to open input file: %s\n", programArguments->inputFile);
        return NULL;
    }

    programArguments->outputFileHandle =
        strcmp(programArguments->outputFile, "-")
            ? fopen(programArguments->outputFile, "wb")
            : stdout;
    if (!programArguments->outputFileHandle) {
        printf(
            "Failed to open output file: %s\n", programArguments->outputFile
        );
        return NULL;
    }

    return programArguments;
}

size_t readFileToBuffer(FILE *fileHandle, unsigned char **buffer) {
    size_t bufferCapacityInBytes = INITIAL_READ_BUFFER_CAPACITY_IN_BYTES;
    size_t bufferSizeInBytes = 0;
    *buffer =
        (unsigned char *) malloc(bufferCapacityInBytes * sizeof(unsigned char));

    while (1) {
        while (bufferSizeInBytes + READ_BLOCK_SIZE_IN_BYTES >
               bufferCapacityInBytes) {
            bufferCapacityInBytes *= 2;
            *buffer = (unsigned char *) realloc(
                *buffer, bufferCapacityInBytes * sizeof(unsigned char)
            );
        }

        size_t bytesRead = fread(
            *buffer + bufferSizeInBytes,
            sizeof(unsigned char),
            READ_BLOCK_SIZE_IN_BYTES,
            fileHandle
        );
        bufferSizeInBytes += bytesRead;

        if (bytesRead < READ_BLOCK_SIZE_IN_BYTES) {
            break;
        }
    }

    return bufferSizeInBytes;
}

int main(int argc, char **argv) {
    ProgramArguments *programArguments = parseProgramArguments(argc, argv);
    if (!programArguments) {
        return 1;
    }

    char *password = askForPassword("Enter password: ");
    if (programArguments->isEncryptionMode) {
        char *confirm_password = askForPassword("Confirm password: ");
        if (strcmp(password, confirm_password)) {
            printf("Passwords do not match.\n");
            return 1;
        } else {
            printf("Passwords match.\n");
        }
    }

    unsigned char *inputBytes;
    size_t inputBytesSizeInBytes =
        readFileToBuffer(programArguments->inputFileHandle, &inputBytes);

    if (programArguments->isEncryptionMode) {
        unsigned char *key = deriveEncryptionKeyPadWithZeros(
            password, strlen(password), AES_KEY_SIZE_IN_BYTES
        );

        unsigned char *iv, *cipherText;
        size_t cipherTextSizeInBytes = AES256CBCEncrypt(
            inputBytes, inputBytesSizeInBytes, key, &iv, &cipherText
        );

        fwrite(
            iv,
            sizeof(unsigned char),
            AES_IV_SIZE_IN_BYTES,
            programArguments->outputFileHandle
        );
        fwrite(
            cipherText,
            sizeof(unsigned char),
            cipherTextSizeInBytes,
            programArguments->outputFileHandle
        );

        free(key);
        free(iv);
        free(cipherText);
    } else {
        if (inputBytesSizeInBytes < AES_IV_SIZE_IN_BYTES) {
            printf("Invalid input file: too small to contain IV.\n");
            return 1;
        }

        unsigned char *iv = (unsigned char *) malloc(
            AES_IV_SIZE_IN_BYTES * sizeof(unsigned char)
        );
        memcpy(iv, inputBytes, AES_IV_SIZE_IN_BYTES);

        unsigned char *cipherText = inputBytes + AES_IV_SIZE_IN_BYTES;
        size_t cipherTextSizeInBytes =
            inputBytesSizeInBytes - AES_IV_SIZE_IN_BYTES;

        unsigned char *key = deriveEncryptionKeyPadWithZeros(
            password, strlen(password), AES_KEY_SIZE_IN_BYTES
        );

        unsigned char *plainText;
        size_t plainTextSizeInBytes = AES256CBCDecrypt(
            cipherText, cipherTextSizeInBytes, key, iv, &plainText
        );

        fwrite(
            plainText,
            sizeof(unsigned char),
            plainTextSizeInBytes,
            programArguments->outputFileHandle
        );

        free(key);
        free(iv);
        free(plainText);
    }

    return 0;
}
