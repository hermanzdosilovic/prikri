#include "ByteBuffer.h"
#include "KDF.h"
#include "Password.h"
#include "ProgramArguments.h"
#include "Usage.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#define AES_KEY_SIZE_IN_BYTES 32
#define AES_BLOCK_SIZE_IN_BYTES 16
#define AES_IV_SIZE_IN_BYTES 16

size_t AES256CBCEncrypt(
    unsigned char *plainBytes,
    size_t plainBytesSizeInBytes,
    unsigned char *encryptionKey,
    unsigned char **iv,
    unsigned char **cipherBytes
) {
    *iv =
        (unsigned char *) malloc(AES_IV_SIZE_IN_BYTES * sizeof(unsigned char));
    RAND_bytes(*iv, AES_IV_SIZE_IN_BYTES);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, encryptionKey, *iv);

    *cipherBytes = (unsigned char *) malloc(
        (plainBytesSizeInBytes + AES_BLOCK_SIZE_IN_BYTES) *
        sizeof(unsigned char)
    );

    int outLen = 0;
    EVP_EncryptUpdate(
        ctx, *cipherBytes, &outLen, plainBytes, plainBytesSizeInBytes
    );

    size_t cipherBytesSizeInBytes = outLen;
    EVP_EncryptFinal_ex(ctx, *cipherBytes + outLen, &outLen);
    cipherBytesSizeInBytes += outLen;

    EVP_CIPHER_CTX_free(ctx);

    return cipherBytesSizeInBytes;
}

size_t AES256CBCDecrypt(
    unsigned char *cipherBytes,
    size_t cipherBytesSizeInBytes,
    unsigned char *encryptionKey,
    unsigned char *iv,
    unsigned char **plainBytes
) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, encryptionKey, iv);

    *plainBytes = (unsigned char *) malloc(
        (cipherBytesSizeInBytes + AES_BLOCK_SIZE_IN_BYTES) *
        sizeof(unsigned char)
    );

    int outLen = 0;
    EVP_DecryptUpdate(
        ctx, *plainBytes, &outLen, cipherBytes, cipherBytesSizeInBytes
    );

    size_t plainBytesSizeInBytes = outLen;
    EVP_DecryptFinal_ex(ctx, *plainBytes + outLen, &outLen);
    plainBytesSizeInBytes += outLen;

    EVP_CIPHER_CTX_free(ctx);

    return plainBytesSizeInBytes;
}

int main(int argc, char **argv) {
    ProgramArguments *programArguments = ParseProgramArguments(argc, argv);
    if (!programArguments) {
        return 1;
    }

    unsigned char *inputBytes;
    size_t inputBytesSizeInBytes =
        ReadFileToBuffer(programArguments->inputFileHandle, &inputBytes);
    if (!inputBytesSizeInBytes) {
        return 1;
    }

    char *password = PromptForPassword(programArguments->isEncryptionMode);
    if (!password) {
        return 1;
    }

    if (programArguments->isEncryptionMode) {
        unsigned char *key =
            KDFPadWithZeros(password, strlen(password), AES_KEY_SIZE_IN_BYTES);

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

        unsigned char *key =
            KDFPadWithZeros(password, strlen(password), AES_KEY_SIZE_IN_BYTES);

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
