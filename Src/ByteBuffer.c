#include "ByteBuffer.h"

#include <stdlib.h>

#define READ_BUFFER_BLOCK_SIZE_IN_BYTES 1024
#define READ_BUFFER_INITIAL_CAPACITY_IN_BYTES 1024
#define READ_BUFFER_CAPACITY_MULTIPLIER 2
#define READ_BUFFER_MAX_CAPACITY_IN_BYTES (1024 * 1024 * 1024 * 128)

size_t ReadFileToBuffer(FILE *fileHandle, unsigned char **buffer) {
    size_t bufferCapacityInBytes = READ_BUFFER_INITIAL_CAPACITY_IN_BYTES;
    size_t bufferSizeInBytes = 0;

    *buffer =
        (unsigned char *) malloc(bufferCapacityInBytes * sizeof(unsigned char));
    if (!*buffer) {
        fprintf(stderr, "Failed to allocate memory for file buffer.\n");
        return 0;
    }

    while (1) {
        while (bufferSizeInBytes + READ_BUFFER_BLOCK_SIZE_IN_BYTES >
               bufferCapacityInBytes) {
            bufferCapacityInBytes *= READ_BUFFER_CAPACITY_MULTIPLIER;
            *buffer = (unsigned char *) realloc(
                *buffer, bufferCapacityInBytes * sizeof(unsigned char)
            );
            if (!*buffer) {
                fprintf(
                    stderr, "Failed to reallocate memory for file buffer.\n"
                );
                free(*buffer);
                return 0;
            }
        }

        size_t bytesRead = fread(
            *buffer + bufferSizeInBytes,
            sizeof(unsigned char),
            READ_BUFFER_BLOCK_SIZE_IN_BYTES,
            fileHandle
        );
        bufferSizeInBytes += bytesRead;

        if (bytesRead < READ_BUFFER_BLOCK_SIZE_IN_BYTES) {
            break;
        }
    }

    return bufferSizeInBytes;
}
