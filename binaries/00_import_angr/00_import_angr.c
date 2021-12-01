/* import_angr.c
 * Demo C program for loading with angr. We'll use more realistic binaries for
 * learning how to do "classic CTF" style things as well as more advanced program
 * analysis techniques, but this will do for now.
 */

#include <stdio.h>
#include <stdlib.h>

#define ERROR (1)
#define OK (0)

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <message>\n", argv[0]);
        return ERROR;
    }

    printf("%s\n", argv[1]);
    return OK;
}
