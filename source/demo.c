//Version modified 20240128Z1756SB
#include "syssec.h"

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#include <errno.h>


int main(int argc, char** argv) {
    if (syssec_initialize()==EXIT_SUCCESS) {
        ssize_t i,j;
        long test[128];
        struct sock_fprog prog = {
            .len = 0,
            .filter = NULL,
        };

        for (i=0;i<(sizeof(test)/sizeof(test[0]));i++) test[i]=SYSCALLEOL;

        i=0;
        test[i]=syssec_syscallnr("SYS_ptrace");              if (test[i]!=SYSCALLEOL) {i++;}
        test[i]=syssec_syscallnr("SYS_syslog");              if (test[i]!=SYSCALLEOL) {i++;}
//      test[i]=syssec_syscallnr("SYS_unshare");             if (test[i]!=SYSCALLEOL) {i++;}
        test[i]=syssec_syscallnr("SYS_kexec_load");          if (test[i]!=SYSCALLEOL) {i++;}
        test[i]=syssec_syscallnr("SYS_kexec_file_load");     if (test[i]!=SYSCALLEOL) {i++;}
        test[i]=syssec_syscallnr("SYS_init_module");         if (test[i]!=SYSCALLEOL) {i++;}
        test[i]=syssec_syscallnr("SYS_reboot");              if (test[i]!=SYSCALLEOL) {i++;}
        test[i]=syssec_syscallnr("SYS_swapon");              if (test[i]!=SYSCALLEOL) {i++;}
        test[i]=syssec_syscallnr("SYS_capset");              if (test[i]!=SYSCALLEOL) {i++;}

        test[i]=syssec_syscallnr("SYS_setgid");              if (test[i]!=SYSCALLEOL) {i++;}
        test[i]=syssec_syscallnr("SYS_setuid");              if (test[i]!=SYSCALLEOL) {i++;}
        test[i]=syssec_syscallnr("SYS_setreuid");            if (test[i]!=SYSCALLEOL) {i++;}
        test[i]=syssec_syscallnr("SYS_setregid");            if (test[i]!=SYSCALLEOL) {i++;}
        test[i]=syssec_syscallnr("SYS_setfsuid");            if (test[i]!=SYSCALLEOL) {i++;}
        test[i]=syssec_syscallnr("SYS_setfsgid");            if (test[i]!=SYSCALLEOL) {i++;}

        test[i]=syssec_syscallnr("SYS_setgroups");           if (test[i]!=SYSCALLEOL) {i++;}

//      test[i]=syssec_syscallnr("SYS_nanosleep");           if (test[i]!=SYSCALLEOL) {i++;}
//      test[i]=syssec_syscallnr("SYS_clock_nanosleep");     if (test[i]!=SYSCALLEOL) {i++;}

#ifndef CONFIG_QUIETDEMO
        for (i=0;i<(sizeof(test)/sizeof(test[0]));i++) {
            printf("%s (0x%02lx), ", syssec_syscallname(test[i]), (long)test[i]);
            if (test[i]==SYSCALLEOL) break;
        }
        printf("\n\n");
#endif

        if (syssec_buildbpfEx(&prog, test, syssec_getBuildArch(), syssec_SECCOMP_RET_KILL_PROCESS(), false)==EXIT_SUCCESS) {
            int  exiterror = syssec_SECCOMP_RET_KILL_PROCESS();
            long syscallnr = SYSCALLEOL;
            int  interresult = EXIT_SUCCESS;

            //process individual "setresuid" - only allow setresuid(-1, geteuid(), -1)
            if (interresult == EXIT_SUCCESS) {
                syscallnr = syssec_syscallnr("SYS_setresuid");
                if (syscallnr != SYSCALLEOL) {
                        struct sock_filter sysfilter[] = {
                            BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS, (offsetof(struct seccomp_data, nr))),
                            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, syscallnr, 0, +9),

                            BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS, (offsetof(struct seccomp_data, args[0]))),
                            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K  , /*uid*/-1, 1, 0),
                            BPF_STMT(BPF_RET | BPF_K            ,  exiterror),
                            BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS, (offsetof(struct seccomp_data, args[1]))),
                            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K  , /*uid*/geteuid(), 1, 0),
                            BPF_STMT(BPF_RET | BPF_K            ,  exiterror),
                            BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS, (offsetof(struct seccomp_data, args[2]))),
                            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K  , /*uid*/-1, 1, 0),
                            BPF_STMT(BPF_RET | BPF_K            ,  exiterror),
                            BPF_STMT(BPF_RET | BPF_K            ,  SECCOMP_RET_ALLOW),
                        };
                        struct sock_fprog sysprog = {
                            .len = sizeof(sysfilter)/sizeof(sysfilter[0]),
                            .filter = sysfilter,
                        };

                        interresult=syssec_combinebpf(&prog, &sysprog, false);
                }
            }

            //process individual "setresgid" - only allow setresgid(-1, getegid(), -1)
            if (interresult == EXIT_SUCCESS) {
                syscallnr = syssec_syscallnr("SYS_setresgid");
                if (syscallnr != SYSCALLEOL) {
                        struct sock_filter sysfilter[] = {
                            BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS, (offsetof(struct seccomp_data, nr))),
                            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, syscallnr, 0, +9),

                            BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS, (offsetof(struct seccomp_data, args[0]))),
                            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K  , /*uid*/-1, 1, 0),
                            BPF_STMT(BPF_RET | BPF_K            ,  exiterror),
                            BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS, (offsetof(struct seccomp_data, args[1]))),
                            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K  , /*uid*/getegid(), 1, 0),
                            BPF_STMT(BPF_RET | BPF_K            ,  exiterror),
                            BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS, (offsetof(struct seccomp_data, args[2]))),
                            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K  , /*uid*/-1, 1, 0),
                            BPF_STMT(BPF_RET | BPF_K            ,  exiterror),
                            BPF_STMT(BPF_RET | BPF_K            ,  SECCOMP_RET_ALLOW),
                        };
                        struct sock_fprog sysprog = {
                            .len = sizeof(sysfilter)/sizeof(sysfilter[0]),
                            .filter = sysfilter,
                        };

                        interresult=syssec_combinebpf(&prog, &sysprog, false);
                }
            }

            if (interresult == EXIT_SUCCESS) {
    #ifndef CONFIG_QUIETDEMO
                if (assigned(prog.filter)) {
                    for (i=0;i<prog.len;i++) {
                        printf("%03i: code=0x%04"PRIx16", jt=0x%02"PRIx8", jf=0x%02"PRIx8", k=0x%08"PRIx32"\n", (int)i, prog.filter[i].code, prog.filter[i].jt, prog.filter[i].jf, prog.filter[i].k);
                    }
                }
    #endif

                if (syssec_install(&prog)==EXIT_SUCCESS) {
                    extern char **environ;
    #ifndef CONFIG_QUIETDEMO
                    fprintf(stderr, "filter installed!\n");
    #endif
                    if (argc > 1) execve(argv[1], &argv[1], environ);
                    fprintf(stderr, "error (%i): %s\n", errno, strerror(errno));
                } else fprintf(stderr, "error (%i): %s\n", errno, strerror(errno));
            } else fprintf(stderr, "error building filter program\n");
        }

        syssec_freebpf(&prog);
        syssec_finalize();
    } else fprintf(stderr, "error - too many syscalls on this plattform!\n");
    return EXIT_FAILURE;
}
