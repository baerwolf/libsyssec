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
        test[i]=syssec_syscallnr("SYS_unshare");             if (test[i]!=SYSCALLEOL) {i++;}
        test[i]=syssec_syscallnr("SYS_kexec_load");          if (test[i]!=SYSCALLEOL) {i++;}
        test[i]=syssec_syscallnr("SYS_reboot");              if (test[i]!=SYSCALLEOL) {i++;}
        test[i]=syssec_syscallnr("SYS_setuid");              if (test[i]!=SYSCALLEOL) {i++;}
        test[i]=syssec_syscallnr("SYS_setgroups");           if (test[i]!=SYSCALLEOL) {i++;}
        test[i]=syssec_syscallnr("SYS_swapon");              if (test[i]!=SYSCALLEOL) {i++;}
        test[i]=syssec_syscallnr("SYS_setns");               if (test[i]!=SYSCALLEOL) {i++;}
        test[i]=syssec_syscallnr("SYS_kexec_file_load");     if (test[i]!=SYSCALLEOL) {i++;}
        test[i]=syssec_syscallnr("__NR_setpriority");        if (test[i]!=SYSCALLEOL) {i++;}

        for (i=0;i<(sizeof(test)/sizeof(test[0]));i++) {
            printf("%s (0x%02lx), ", syssec_syscallname(test[i]), (long)test[i]);
            if (test[i]==SYSCALLEOL) break;
        }
        printf("\n\n");

        if (syssec_buildbpf(&prog, test, syssec_getBuildArch(), SECCOMP_RET_ERRNO | (EACCES & SECCOMP_RET_DATA))==EXIT_SUCCESS) {
            if (assigned(prog.filter)) {
                for (i=0;i<prog.len;i++) {
                    printf("%03i: code=0x%04"PRIx16", jt=0x%02"PRIx8", jf=0x%02"PRIx8", k=0x%08"PRIx32"\n", (int)i, prog.filter[i].code, prog.filter[i].jt, prog.filter[i].jf, prog.filter[i].k);
                }
            }

            if (syssec_install(&prog)==EXIT_SUCCESS) {
                extern char **environ;
                fprintf(stderr, "filter installed!\n");
                if (argc > 1) execve(argv[1], &argv[1], environ);
                fprintf(stderr, "error!\n");
            } else fprintf(stderr, "error (%i): %s\n", errno, strerror(errno));
        }

        syssec_freebpf(&prog);
        syssec_finalize();
    } else fprintf(stderr, "error - too many syscalls on this plattform!\n");
    return EXIT_FAILURE;
}
