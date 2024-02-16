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

#include <string.h>

static int __syssec_initialized = false;
static struct syscall_info plattformsyscalls[] = {
#include "../build/plattform.syscalls"
  {.str="", .nr=SYSCALLEOL},
};


static int initandcheck(void) {
    int result=EXIT_FAILURE;
    size_t len=sizeof(plattformsyscalls)/sizeof(plattformsyscalls[0]);

    if (len > 1) {
        long max,min;
        size_t i;

        min=__LONG_MAX__;
        max=-min;

        len--;
        for (i=0;i<len;i++) {
            if (plattformsyscalls[i].nr > max) max=plattformsyscalls[i].nr;
            if (plattformsyscalls[i].nr < min) min=plattformsyscalls[i].nr;
        }

        if (max < __NR_syscalls) result=EXIT_SUCCESS;
    }

    return result;
}

int syssec_initialize(void) {
    if (!(__syssec_initialized)) {
        if (initandcheck() == EXIT_SUCCESS) {
            __syssec_initialized=true;
            return EXIT_SUCCESS;
        }
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

#ifndef AUDIT_ARCH_UNKNOWN
#define AUDIT_ARCH_UNKNOWN (-1)
#endif
//modified from https://stackoverflow.com/questions/152016/detecting-cpu-architecture-compile-time
const int syssec_getBuildArch(void) { //Get current architecture, detectx nearly every architecture. Coded by Freak
    #if defined(__x86_64__) || defined(_M_X64)
    return AUDIT_ARCH_X86_64;
    #elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
    return AUDIT_ARCH_I386;
    #elif defined(__ARM_ARCH_2__)
    return AUDIT_ARCH_UNKNOWN;
    #elif defined(__ARM_ARCH_3__) || defined(__ARM_ARCH_3M__)
    return AUDIT_ARCH_UNKNOWN;
    #elif defined(__ARM_ARCH_4T__) || defined(__TARGET_ARM_4T)
    return AUDIT_ARCH_UNKNOWN;
    #elif defined(__ARM_ARCH_5_) || defined(__ARM_ARCH_5E_)
    return AUDIT_ARCH_UNKNOWN;
    #elif defined(__ARM_ARCH_6T2_) || defined(__ARM_ARCH_6T2_)
    return AUDIT_ARCH_UNKNOWN;
    #elif defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__)
    return AUDIT_ARCH_ARM;
    #elif defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
    return AUDIT_ARCH_ARM;
    #elif defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
    return AUDIT_ARCH_ARM;
    #elif defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
    return AUDIT_ARCH_ARM;
    #elif defined(__ARM_ARCH_7M__)
    return AUDIT_ARCH_ARM;
    #elif defined(__ARM_ARCH_7S__)
    return AUDIT_ARCH_ARM;
    #elif defined(__aarch64__) || defined(_M_ARM64)
    return AUDIT_ARCH_AARCH64;
    #elif defined(mips) || defined(__mips__) || defined(__mips)
    return AUDIT_ARCH_UNKNOWN;
    #elif defined(__sh__)
    return AUDIT_ARCH_UNKNOWN;
    #elif defined(__powerpc) || defined(__powerpc__) || defined(__powerpc64__) || defined(__POWERPC__) || defined(__ppc__) || defined(__PPC__) || defined(_ARCH_PPC)
    return AUDIT_ARCH_UNKNOWN;
    #elif defined(__PPC64__) || defined(__ppc64__) || defined(_ARCH_PPC64)
    return AUDIT_ARCH_UNKNOWN;
    #elif defined(__sparc__) || defined(__sparc)
    return AUDIT_ARCH_UNKNOWN;
    #elif defined(__m68k__)
    return AUDIT_ARCH_UNKNOWN;
    #else
    return AUDIT_ARCH_UNKNOWN;
    #endif
}

const char *syssec_syscallname(const long SYS_nr) {
    const char *result=NULL;
    size_t i, len=sizeof(plattformsyscalls)/sizeof(plattformsyscalls[0]);

    if (SYS_nr!=SYSCALLEOL) {
        for (i=0;i<len;i++) {
            if (plattformsyscalls[i].nr!=SYSCALLEOL) {
                if (plattformsyscalls[i].nr==SYS_nr) {
                    result=plattformsyscalls[i].str;
                    break;
                }
            } else break;
        }
    } else result="SYSCALLEOL";

    return result;
}

const long syssec_syscallnr(const char *SYS_name) {
    long result=SYSCALLEOL;
    size_t i, len=sizeof(plattformsyscalls)/sizeof(plattformsyscalls[0]);

    for (i=0;i<len;i++) {
        if (plattformsyscalls[i].nr!=SYSCALLEOL) {
            if (strncasecmp(plattformsyscalls[i].str, SYS_name, sizeof(plattformsyscalls[0].str)-1)==0) {
                result=plattformsyscalls[i].nr;
                break;
            }
        } else break;
    }

    return result;
}
