#include "AES.h"
#include "ByteBuffer.h"
#include "KDF.h"
#include "Password.h"
#include "ProgramArguments.h"
#include "Usage.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
            fprintf(stderr, "Invalid input file: too small to contain IV.\n");
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
