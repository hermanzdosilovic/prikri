#ifndef PRIKRI_PASSWORD_H
#define PRIKRI_PASSWORD_H

#include <stdbool.h>

char *readPassword(char *prompt);
char *promptForPassword(bool confirm);

#endif
