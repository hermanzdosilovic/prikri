#include "Usage.h"

#include <stdio.h>

void printUsage(char **argv) {
    printf("Usage: %s [e|d] <input file> [output file]\n", argv[0]);
}
