/*
 * SYSSEC.H
 * 
 * This is version 20240216T12045ZSB
 *
 * Stephan Baerwolf (matrixstorm@gmx.de), Rudolstadt 2024
 * (please contact me at least before commercial use)
 */

#ifndef SYSSEC_H_752cc330d90543e0b2dd218a522b389e
#define SYSSEC_H_752cc330d90543e0b2dd218a522b389e 	1

#ifdef SYSSECINCLUDEDEFINES
#	include "defines.h"
#endif

#ifdef SYSSEC_C_752cc330d90543e0b2dd218a522b389e
#	define SYSSECPUBLIC
#else
#	define SYSSECPUBLIC	extern
#endif

SYSSECPUBLIC int syssec_initialize(void);
SYSSECPUBLIC int syssec_finalize(void);


#endif
