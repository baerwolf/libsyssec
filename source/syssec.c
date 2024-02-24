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
#include <stddef.h>

#include <string.h>
#include <errno.h>

#ifdef CONFIG_WITHCAPABILITIES
//also needs linking with "-lcap"
#   include <sys/capability.h>
#endif

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



ssize_t SYSCALL_LIST_getlen(long *list) {
    ssize_t result=0;
    if assigned(list) {
        while (list[result]>=0) { result++; }
    }
    return result;
}

static int SYSCALL_LIST_cmpelemet(const void *p1, const void *p2) {
    long *a=(void*)p1;
    long *b=(void*)p2;
    if (((*a)&SYSCALLMASK)<((*b)&SYSCALLMASK)) {
        return -1;
    } else {
        if (((*a)&SYSCALLMASK)>((*b)&SYSCALLMASK)) {
            return 1;
        }
    }
    return 0;
}

static size_t SYSCALL_LIST_uniq(long *list) {
    size_t l, i, result, j=SYSCALL_LIST_getlen(list);

    qsort(list, j, sizeof(long), &SYSCALL_LIST_cmpelemet);
    l=0; result=0;
    for (i=1;i<j;i++) {
        if (list[l]==list[i]) {
            list[i]=__LONG_MAX__;
            result++;
        } else {l=i;}
    }
    qsort(list, j, sizeof(long), &SYSCALL_LIST_cmpelemet);

    return (j-result);
}

static size_t SYSCALL_LIST_merge(long *list) {
    size_t l, i, result, j=SYSCALL_LIST_uniq(list);
    bool inmerge;

    l=0; result=0; inmerge=false;
    for (i=0;i<j;i++) {
        if ((list[i]+1)==list[i+1]) {
            if (i==l) {
                list[l]|=(SYSCALL_ne|SYSCALL_geq);
                inmerge=true;
            } else {
                list[i]=__LONG_MAX__;
                result++;
            }
        } else {
            if (inmerge) list[i]|=SYSCALL_ne;
            l=i+1;
            inmerge=false;
        }
    }
    qsort(list, j, sizeof(long), &SYSCALL_LIST_cmpelemet);

    return (j-result);
}

#define BPFMAXLENGTH (256)
int bpf_add_opcode(void *bpfprog) {
    int result=-1;
    unsigned short i;
    struct sock_fprog *prog = bpfprog;

    if assigned(prog) {
        if assigned(prog->filter) {
            size_t newsize;
            i=prog->len;
            prog->len++;
            if ((prog->len)<BPFMAXLENGTH) {
                newsize=prog->len;
                newsize*=sizeof(struct sock_filter);
                prog->filter=realloc(prog->filter, newsize);
                if (assigned(prog->filter)) {
                    //basically an NOP: https://www.kernel.org/doc/html/v5.17/bpf/instruction-set.html
                    struct sock_filter f = BPF_STMT(BPF_ALU | BPF_OR | BPF_K, 0);
                    prog->filter[i]=f;
                    result=i;
                } else {
                    prog->len=0;
                }
            } else {
                free(prog->filter);
                prog->filter=NULL;
                prog->len=0;
            }
        }
    }
    return result;
}

static int compilebpf(struct sock_fprog *prog, long *list, size_t lower, size_t upper) {
    size_t pivot=upper+lower;
    int i,j;
    
    //ceil(pivot/2) -->
    pivot=(pivot>>1)+(pivot&1);

    if (list[pivot]&SYSCALL_ne) {
        //pivot belongs to some merged values
        if (list[pivot]&SYSCALL_geq) {
            //pivot starts interval
        } else {
            pivot++;
        }
    }

    i=bpf_add_opcode(prog);
    if (i<0) return EXIT_FAILURE;
//     printf("DEBUG: [%llu - %llu] (i=%i, pivot=%llu)\n", (unsigned long long)lower, (unsigned long long)upper, (int)i, (unsigned long long)pivot);
    if (upper-lower<1) {
        struct sock_filter hlpl = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, list[lower]&SYSCALLMASK, 0xff, 0xff);
        prog->filter[i]=hlpl;
        return EXIT_SUCCESS;
    } else if (upper-lower==1) {
        if (list[lower]&SYSCALL_ne) {
            //interval
            struct sock_filter hlpl = BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, list[lower]&SYSCALLMASK, 0x0, 0xff);
            struct sock_filter hlpu = BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, list[upper]&SYSCALLMASK, 0xff, 0xff);
            prog->filter[i]=hlpl;
            j=bpf_add_opcode(prog);
            if (j<0) return EXIT_FAILURE;
            prog->filter[j]=hlpu;
        } else {
            //two elements to be checked for equal
            struct sock_filter hlpl = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, list[lower]&SYSCALLMASK, 0xff, 0);
            struct sock_filter hlpu = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, list[upper]&SYSCALLMASK, 0xff, 0xff);
            prog->filter[i]=hlpl;
            j=bpf_add_opcode(prog);
            if (j<0) return EXIT_FAILURE;
            prog->filter[j]=hlpu;
        }
        return EXIT_SUCCESS;
    }
    
    if (pivot>lower)  compilebpf(prog, list, lower, pivot-1);
    j=prog->len;
    {
        struct sock_filter hlp = BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, list[pivot]&SYSCALLMASK, (j-(i+1)), 0);
        prog->filter[i]=hlp;
    }
    if (pivot<=upper) compilebpf(prog, list, pivot, upper);
        
    return EXIT_SUCCESS;
}

#define LINKBPF_FAILURE_LAST 0
static int linkbpfEx(struct sock_fprog *prog, long *list, size_t len, int seccompreturn, bool rejectlast) {
    int result = EXIT_FAILURE;
    
    result = compilebpf(prog, list, 0, len-1);
    if (result == EXIT_SUCCESS) {
        struct sock_filter bpfaccept = BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW);
        struct sock_filter bpfdeny   = BPF_STMT(BPF_RET + BPF_K, seccompreturn);
        unsigned short i,j=prog->len;
        int k;

        k=bpf_add_opcode(prog);
        if (k<0) return EXIT_FAILURE;
        k=bpf_add_opcode(prog);
        if (k<0) return EXIT_FAILURE;

    if (rejectlast) {
        //succesful exit - accept syscall
        prog->filter[j+0]=bpfaccept;
        //rejective exit - deny syscall
        prog->filter[j+1]=bpfdeny;
    } else {
        //rejective exit - deny syscall
        prog->filter[j+0]=bpfdeny;
        //succesful exit - accept syscall
        prog->filter[j+1]=bpfaccept;
    }
        
        for (i=0;i<j;i++) {
            if (rejectlast)  {
                if (BPF_CLASS(prog->filter[i].code)==BPF_JMP) {
                    if (BPF_OP(prog->filter[i].code)==BPF_JEQ) {
                        if (BPF_CLASS(prog->filter[i].jt==0xff)) {
                            prog->filter[i].jt=j-i;
                            if (BPF_CLASS(prog->filter[i].jf==0xff)) {
                                    prog->filter[i].jf=prog->filter[i].jt-1;
                            }
                        }
                    } else {
                        if (BPF_CLASS(prog->filter[i].jf==0xff)) {
                            prog->filter[i].jf=j-i;
                            if (BPF_CLASS(prog->filter[i].jt==0xff)) {
                                //end of interval - final decision
                                prog->filter[i].jt=prog->filter[i].jf-1;
                            } else {
                                //start of interval
                                prog->filter[i].jf--;
                            }
                        }
                    }
                }
            } else {
                if (BPF_CLASS(prog->filter[i].code)==BPF_JMP) {
                    if (BPF_OP(prog->filter[i].code)==BPF_JEQ) {
                        if (BPF_CLASS(prog->filter[i].jt==0xff)) {
                            prog->filter[i].jt=j-i-1;
                            if (BPF_CLASS(prog->filter[i].jf==0xff)) {
                                    prog->filter[i].jf=j-i;
                            }
                        }
                    } else {
                        if (BPF_CLASS(prog->filter[i].jf==0xff)) {
                            prog->filter[i].jf=j-i-1;
                            if (BPF_CLASS(prog->filter[i].jt==0xff)) {
                                //end of interval - final decision
                                prog->filter[i].jt=j-i;
                            } else {
                                //start of interval
                                prog->filter[i].jf=j-i;
                            }
                        }
                    }
                }
            }
        }
    }
    return result;
}

void syssec_freebpf(/*struct sock_fprog*/void *bpfprog) {
    struct sock_fprog *prog=bpfprog;
    if (assigned(prog->filter)) free(prog->filter);
    prog->filter=NULL; prog->len=0;
}

#define SYSSEC_HEADER_OPS (5)
int syssec_buildbpfEx(/*struct sock_fprog*/void *bpfprog, long *SYS_list, int supported_arch, int seccompreturn, bool rejectlast) {
    struct sock_fprog *prog=bpfprog;
    struct sock_filter header[] = {
        BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS, (offsetof(struct seccomp_data, arch))),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,    supported_arch, 2, 0),
        BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS,  0),
        BPF_STMT(BPF_RET | BPF_K            ,  SECCOMP_RET_TRAP | (ENOEXEC & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS, (offsetof(struct seccomp_data, nr))),
    };
    int result=EXIT_FAILURE;

    syssec_freebpf(prog);

    //we are a blacklist filter programm, we don't filter to return "SECCOMP_RET_ALLOW"
    if (seccompreturn!=SECCOMP_RET_ALLOW) {
        size_t i=SYSCALL_LIST_merge(SYS_list);
        if ((i>0)&&(i<__SHRT_MAX__)) {
            prog->filter=malloc(sizeof(header));
            if assigned(prog->filter) {
                prog->len=sizeof(header)/sizeof(header[0]);
                memcpy(prog->filter, header, sizeof(header));
                result=linkbpfEx(prog, SYS_list, i, seccompreturn, rejectlast);
            }
        }
    }
    return result;
}

int syssec_buildbpf(/*struct sock_fprog*/void *bpfprog, long *SYS_list, int supported_arch, int seccompreturn) {
    return syssec_buildbpfEx(bpfprog, SYS_list, supported_arch, seccompreturn, true);
}

void *syssec_allocateprog(void) {
    struct sock_fprog *result=malloc(sizeof(struct sock_fprog));
    if (assigned(result)) {
        memset(result, 0, sizeof(struct sock_fprog));
        result->len=0;
        result->filter=NULL;
    }
    return (void*)result;
}

void syssec_freeprog(void* bpfprog) {
    if (assigned(bpfprog)) {
        syssec_freebpf(bpfprog);
        free(bpfprog);
    }
}

int syssec_install(void *bpfprog) {
    return syssec_installEx(bpfprog, false);
}

int syssec_installEx(void *bpfprog, bool newprivs) {
    int result=EXIT_FAILURE;
    if (assigned(bpfprog)) {
        bool docontinue=false;

#ifdef CONFIG_WITHCAPABILITIES
        /* manual PRCTL(2) says unter "SECCOMP_MODE_FILTER"-errors
         *
            EACCES option  is  PR_SET_SECCOMP  and  arg2  is  SECCOMP_MODE_FILTER,  but  the  process  does not have the
            CAP_SYS_ADMIN  capability  or  has  not  set  the  no_new_privs  attribute  (see  the  discussion  of
            PR_SET_NO_NEW_PRIVS above).
         *
         */
        cap_value_t capvalue[1] = {CAP_SYS_ADMIN};
        bool  clearcapability=false;
        cap_t mycaps=NULL;

        if (newprivs) {
            mycaps = cap_get_proc();
            if (assigned(mycaps)) {
                cap_flag_value_t flagvalue;

                //check, if we have permissions
                if (cap_get_flag(mycaps, capvalue[0], CAP_EFFECTIVE, &flagvalue) != (-1)) {
                    if (flagvalue == CAP_SET) {
                        // we have effective CAP_SYS_ADMIN
                        docontinue=true;
                    } else {
                        //if we do not have effective capability, see if we are permitted in principle
                        if (cap_get_flag(mycaps, capvalue[0],  CAP_PERMITTED, &flagvalue) != (-1)) {
                            if (flagvalue == CAP_SET) {
                                // yes, CAP_SYS_ADMIN+p...
                                if (cap_set_flag(mycaps, CAP_EFFECTIVE, 1, capvalue, CAP_SET) != (-1)) {
                                    // ...try to set it effective...
                                    if (cap_set_proc(mycaps) != (-1)) {
                                        //done
                                        clearcapability=true;
                                        docontinue=true;
                                    }
                                }
                            }
                        }
                    }
                }
                if (!clearcapability) {
                    cap_free(mycaps);
                    mycaps=NULL;
                }
            }
        }
#endif
        if (newprivs) if (!docontinue) docontinue=(geteuid() == 0);

        // we need to lock "new privs" in order to avoid error 13 (EPERM)
        if (!docontinue) docontinue=(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)==0);
        /* manual PRCTL(2) says unter "PR_SET_NO_NEW_PRIVS"
         *
            Set  the  calling  thread's no_new_privs attribute to the value in arg2.  With no_new_privs set to 1,
            execve(2) promises not to grant privileges to do anything that could not have been done  without  the
            execve(2) call (for example, rendering the set-user-ID and set-group-ID mode bits, and file capabili‐
            ties non-functional).  Once set, the no_new_privs attribute cannot be unset.  The setting of this at‐
            tribute is inherited by children created by fork(2) and clone(2), and preserved across execve(2).

            Since  Linux  4.10,  the  value of a thread's no_new_privs attribute can be viewed via the NoNewPrivs
            field in the /proc/[pid]/status file.

            For more information, see the kernel  source  file  Documentation/userspace-api/no_new_privs.rst  (or
            Documentation/prctl/no_new_privs.txt before Linux 4.13).  See also seccomp(2).
         *
         */

        if (docontinue) {
            struct sock_fprog *prog=bpfprog;
            if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog)==0) {
                result=EXIT_SUCCESS;
            }
        }

#ifdef CONFIG_WITHCAPABILITIES
        if (clearcapability) {
            //we previously acquired effective capability...
            //...release it after its use!
            if (assigned(mycaps)) {
                if (cap_set_flag(mycaps, CAP_EFFECTIVE, 1, capvalue, CAP_CLEAR) != (-1)) {
                    //we do not care about the return - we couldn't do anything else
                    cap_set_proc(mycaps);
                }
                cap_free(mycaps);
                mycaps=NULL;
            }
        }
#endif

    }
    return result;
}

int syssec_combinebpf(/*struct sock_fprog*/void *appended_to, /*struct sock_fprog*/void *appended_from, bool skip_header) {
    int result=EXIT_FAILURE;
    short int skip = (skip_header)?(SYSSEC_HEADER_OPS):(0);
    if (assigned(appended_to)) {
        if (assigned(appended_from)) {
            struct sock_fprog *to   = appended_to;
            struct sock_fprog *from = appended_from;
            if (from->len <= skip) {
                //nothing to append
                result=EXIT_SUCCESS;
            } else {
                unsigned short len;
                if (to->len == 0) bpf_add_opcode(to);
                len=from->len;
                if (to->len > 0) {
                    unsigned short i=skip;
                    to->filter[to->len-1]=from->filter[i++];
                    for (;i<len;i++) {
                        if (bpf_add_opcode(to) < 0) return EXIT_FAILURE;
                        to->filter[to->len-1]=from->filter[i];
                    }
                    result=EXIT_SUCCESS;
                }
            }
        }
    }
    return result;
}

static int syssec_SECCOMP_helper(uint16_t returncode) {
    int result = returncode;
    result &= SECCOMP_RET_DATA;
    return result;
}

int syssec_SECCOMP_RET_ERRNO(uint16_t returncode) {
    return syssec_SECCOMP_helper(returncode) | SECCOMP_RET_ERRNO;
}

int syssec_SECCOMP_RET_TRAP(uint16_t returncode) {
    return syssec_SECCOMP_helper(returncode) | SECCOMP_RET_TRAP;
}

int syssec_SECCOMP_RET_KILL_PROCESS(void) {
    return SECCOMP_RET_KILL_PROCESS;
}
