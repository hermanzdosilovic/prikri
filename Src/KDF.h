#ifndef PRIKRI_KDF_H
#define PRIKRI_KDF_H

#include <stddef.h>

unsigned char *KDFPadWithZeros(
    char *userKey,
    size_t userKeySizeInBytes,
    size_t encryptionKeySizeInBytes
);

unsigned char *KDFSHA(
    char *userKey,
    size_t userKeySizeInBytes,
    size_t encryptionKeySizeInBytes,
    char *algorithm
);

#endif
