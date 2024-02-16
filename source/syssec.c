/*
 * SYSSEC.C
 * 
 * This is version 20240216T12045ZSB
 *
 * Stephan Baerwolf (matrixstorm@gmx.de), Rudolstadt 2024
 * (please contact me at least before commercial use)
 */

#define SYSSEC_C_752cc330d90543e0b2dd218a522b389e 	1

#include "syssec.h"

#include <stdlib.h>
#include <stdbool.h>

static int __syssec_initialized = false;

int syssec_initialize(void) {
    if (!(__syssec_initialized)) {
        __syssec_initialized=true;
        return EXIT_SUCCESS;
    }
    return EXIT_FAILURE;
}

int syssec_finalize(void) {
    if (__syssec_initialized) {
        __syssec_initialized=false;
        return EXIT_SUCCESS;
    }
    return EXIT_FAILURE;
}
