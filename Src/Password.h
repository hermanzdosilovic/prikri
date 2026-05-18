#ifndef PRIKRI_PASSWORD_H
#define PRIKRI_PASSWORD_H

#include <stdbool.h>

char *ReadPassword(char *prompt);
char *PromptForPassword(bool confirm);

#endif
