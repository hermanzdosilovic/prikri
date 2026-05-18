#ifndef PRIKRI_AES_H
#define PRIKRI_AES_H

#include <stddef.h>

#define AES_KEY_SIZE_IN_BYTES 32
#define AES_BLOCK_SIZE_IN_BYTES 16
#define AES_IV_SIZE_IN_BYTES 16

size_t AES256CBCEncrypt(
    unsigned char *plainBytes,
    size_t plainBytesSizeInBytes,
    unsigned char *encryptionKey,
    unsigned char **iv,
    unsigned char **cipherBytes
);

size_t AES256CBCDecrypt(
    unsigned char *cipherBytes,
    size_t cipherBytesSizeInBytes,
    unsigned char *encryptionKey,
    unsigned char *iv,
    unsigned char **plainBytes
);

#endif
