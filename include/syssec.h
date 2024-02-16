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

#include <linux/audit.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <sys/prctl.h>
#include <unistd.h>

#include <syscall.h>

#define SYSCALLEOL          (-(__LONG_MAX__))
#ifndef __NR_syscalls
#   if 0
#       define __NR_syscalls (sizeof(plattformsyscalls)/sizeof(struct syscall_info))
#   else
#    define __NR_syscalls (65536)
#   endif
#endif

#define _h(y,x) (y|((y)>>(x)))
#define getmask(x) (_h(_h(_h(_h(_h(x-1,1),2),4),8),16))

#define SYSCALLCOUNT        ((2*(__NR_syscalls))+1)
#define SYSCALLMASK         (getmask(SYSCALLCOUNT))

#define SYSCALLEXTRABITS    ((__LONG_MAX__ / 8)+1)
#define SYSCALL_ne          (SYSCALLEXTRABITS<<0)  /*not equal*/
#define SYSCALL_geq         (SYSCALLEXTRABITS<<1)  /*greater or equal*/

#if (SYSCALLMASK>(__LONG_MAX__ / 8))
#error CAN NOT COMPILE ON ABI WITH TOO MANY SYSCALLS
#endif

#define assigned(x) (x!=NULL)

struct syscall_info {
    const char str[32];
    const long nr;
};



SYSSECPUBLIC int syssec_initialize(void);
SYSSECPUBLIC int syssec_finalize(void);

SYSSECPUBLIC int syssec_install(void *bpfprog);

SYSSECPUBLIC const int syssec_getBuildArch(void);

SYSSECPUBLIC const char *syssec_syscallname(const long SYS_nr);
SYSSECPUBLIC const long syssec_syscallnr(const char *SYS_name);

SYSSECPUBLIC void *syssec_allocateprog(void);
SYSSECPUBLIC void syssec_freeprog(void* bpfprog);

SYSSECPUBLIC void syssec_freebpf(/*struct sock_fprog*/void *bpfprog);
SYSSECPUBLIC int syssec_buildbpf(/*struct sock_fprog*/void *bpfprog, long *SYS_list, int supported_arch, int seccompreturn);



#endif
