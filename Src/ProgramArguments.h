#ifndef PRIKRI_PROGRAM_ARGUMENTS_H
#define PRIKRI_PROGRAM_ARGUMENTS_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef struct ProgramArguments {
    bool isEncryptionMode;
    char *inputFilePath;
    char *outputFilePath;
    FILE *inputFileHandle;
    FILE *outputFileHandle;
} ProgramArguments;

ProgramArguments *parseProgramArguments(int argc, char **argv);

#endif
