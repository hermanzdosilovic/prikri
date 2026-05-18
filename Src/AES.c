#include "AES.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

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
