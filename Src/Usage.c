#include "Usage.h"

#include <stdio.h>

void PrintUsage(char **argv) {
    fprintf(stderr, "Usage: %s [e|d] <input file> [output file]\n", argv[0]);
}
