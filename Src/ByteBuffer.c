#include "ByteBuffer.h"

#include <stdlib.h>

#define READ_BUFFER_BLOCK_SIZE_IN_BYTES 1024
#define READ_BUFFER_INITIAL_CAPACITY_IN_BYTES 1024
#define READ_BUFFER_CAPACITY_MULTIPLIER 2
#define READ_BUFFER_MAX_CAPACITY_IN_BYTES (1024 * 1024 * 1024 * 128)

size_t ReadFileToBuffer(FILE *fileHandle, void **buffer) {
    size_t bufferCapacityInBytes = READ_BUFFER_INITIAL_CAPACITY_IN_BYTES;
    size_t bufferSizeInBytes = 0;

    *buffer = (void *) malloc(bufferCapacityInBytes);
    if (!*buffer) {
        fprintf(stderr, "Failed to allocate memory for file buffer.\n");
        return 0;
    }

    while (1) {
        while (bufferSizeInBytes + READ_BUFFER_BLOCK_SIZE_IN_BYTES >
               bufferCapacityInBytes) {
            bufferCapacityInBytes *= READ_BUFFER_CAPACITY_MULTIPLIER;
            *buffer = (void *) realloc(*buffer, bufferCapacityInBytes);
            if (!*buffer) {
                fprintf(
                    stderr, "Failed to reallocate memory for file buffer.\n"
                );
                free(*buffer);
                return 0;
            }
        }

        size_t bytesRead = fread(
            (char *) *buffer + bufferSizeInBytes,
            sizeof(char),
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
