#include "ProgramArguments.h"
#include "Usage.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

ProgramArguments *ParseProgramArguments(int argc, char **argv) {
    ProgramArguments *programArguments =
        (ProgramArguments *) malloc(sizeof(ProgramArguments));
    if (!programArguments) {
        printf("Failed to allocate memory for program arguments.\n");
        return NULL;
    }

    if (argc == 1) {
        PrintUsage(argv);
        return NULL;
    }

    if (strcmp(argv[1], "e") && strcmp(argv[1], "d")) {
        printf("Invalid mode: %s\n", argv[1]);
        PrintUsage(argv);
        return NULL;
    }

    programArguments->isEncryptionMode = argv[1][0] == 'e';

    if (argc >= 3) {
        programArguments->inputFilePath = argv[2];
    } else {
        printf("Input file is required.\n");
        PrintUsage(argv);
        return NULL;
    }

    if (argc >= 4) {
        programArguments->outputFilePath = argv[3];
    } else {
        programArguments->outputFilePath = (char *) malloc(
            (strlen(programArguments->inputFilePath) + 5) * sizeof(char)
        );
        if (programArguments->outputFilePath == NULL) {
            printf("Failed to allocate memory for output file name.\n");
            return NULL;
        }

        sprintf(
            programArguments->outputFilePath,
            "%s.%s",
            programArguments->inputFilePath,
            programArguments->isEncryptionMode ? "enc" : "dec"
        );
    }

    programArguments->inputFileHandle =
        fopen(programArguments->inputFilePath, "rb");
    if (!programArguments->inputFileHandle) {
        printf(
            "Failed to open input file: %s\n", programArguments->inputFilePath
        );
        return NULL;
    }

    programArguments->outputFileHandle =
        fopen(programArguments->outputFilePath, "wb");
    if (!programArguments->outputFileHandle) {
        printf(
            "Failed to open output file: %s\n", programArguments->outputFilePath
        );
        return NULL;
    }

    return programArguments;
}
