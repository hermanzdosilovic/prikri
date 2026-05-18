#include "KDF.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char *KDFPadWithZeros(
    char *userKey,
    size_t userKeySizeInBytes,
    size_t encryptionKeySizeInBytes
) {
    unsigned char *key = (unsigned char *) calloc(
        encryptionKeySizeInBytes, sizeof(unsigned char)
    );
    if (!key) {
        printf("Failed to allocate memory for encryption key.\n");
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
