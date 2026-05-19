#include "KDF.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

unsigned char *KDFPadWithZeros(
    char *userKey,
    size_t userKeySizeInBytes,
    size_t encryptionKeySizeInBytes
) {
    unsigned char *key = (unsigned char *) calloc(
        encryptionKeySizeInBytes, sizeof(unsigned char)
    );
    if (!key) {
        fprintf(stderr, "Failed to allocate memory for encryption key.\n");
        return NULL;
    }

    memcpy(
        key,
        userKey,
        userKeySizeInBytes < encryptionKeySizeInBytes ? userKeySizeInBytes
                                                      : encryptionKeySizeInBytes
    );

    return key;
}

unsigned char *KDFSHA(
    char *userKey,
    size_t userKeySizeInBytes,
    size_t encryptionKeySizeInBytes,
    char *algorithm
) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create message digest context.\n");
        return NULL;
    }

    const EVP_MD *md = EVP_get_digestbyname(algorithm);
    if (!md) {
        fprintf(
            stderr, "Failed to get message digest by name: %s\n", algorithm
        );
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    unsigned char *digest =
        (unsigned char *) malloc(EVP_MD_size(md) * sizeof(unsigned char));
    if (!digest) {
        fprintf(stderr, "Failed to allocate memory for message digest.\n");
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    unsigned int digestSizeInBytes = 0;
    if (!EVP_DigestInit_ex(ctx, md, NULL) ||
        !EVP_DigestUpdate(ctx, userKey, userKeySizeInBytes) ||
        !EVP_DigestFinal_ex(ctx, digest, &digestSizeInBytes)) {
        fprintf(stderr, "Failed to compute message digest.\n");
        free(digest);
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    EVP_MD_CTX_free(ctx);
    return KDFPadWithZeros(
        (char *) digest, digestSizeInBytes, encryptionKeySizeInBytes
    );
}
