#include "Password.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PASSWORD_SIZE_IN_BYTES 256

char *ReadPassword(char *prompt) {
    printf("%s", prompt);

    char *password = (char *) malloc(MAX_PASSWORD_SIZE_IN_BYTES * sizeof(char));
    if (!password) {
        fprintf(stderr, "Failed to allocate memory for password.\n");
        return NULL;
    }

    if (!fgets(password, MAX_PASSWORD_SIZE_IN_BYTES, stdin)) {
        free(password);
        return NULL;
    }

    size_t len = strlen(password);
    if (len > 0 && password[len - 1] == '\n') {
        password[len - 1] = '\0';
    }

    return password;
}

char *PromptForPassword(bool confirm) {
    char *password = ReadPassword("Enter password: ");
    if (!password) {
        return NULL;
    }

    if (confirm) {
        char *confirmedPassword = ReadPassword("Confirm password: ");
        if (!confirmedPassword) {
            free(password);
            return NULL;
        }

        if (strcmp(password, confirmedPassword)) {
            fprintf(stderr, "Passwords do not match.\n");

            free(password);
            free(confirmedPassword);

            return NULL;
        }

        free(confirmedPassword);
    }

    return password;
}
