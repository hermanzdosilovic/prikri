#include "Password.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PASSWORD_SIZE_IN_BYTES 256

char *readPassword(char *prompt) {
    printf("%s", prompt);

    char *password = (char *) malloc(MAX_PASSWORD_SIZE_IN_BYTES * sizeof(char));
    if (!password) {
        printf("Failed to allocate memory for password.\n");
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

char *promptForPassword(bool confirm) {
    char *password = readPassword("Enter password: ");
    if (!password) {
        return NULL;
    }

    if (confirm) {
        char *confirm_password = readPassword("Confirm password: ");
        if (!confirm_password) {
            free(password);
            return NULL;
        }

        if (strcmp(password, confirm_password)) {
            printf("Passwords do not match.\n");

            free(password);
            free(confirm_password);

            return NULL;
        } else {
            printf("Passwords match.\n");
        }

        free(confirm_password);
    }

    return password;
}
