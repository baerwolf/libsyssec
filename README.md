# libsyssec
A minimalistic library to utilize SECCOMP-BPF - VERSION 20240216T12045ZSB

Libsyssec is a very small and simplistic library to filter linux syscalls.

It offers multiple reject-codes and string-accessable syscall names.
It allows merging/combining multiple bpf-parts and autodetects current
platform (i.e. "AUDIT_ARCH_*").

Libsyssec also handles installation of the final filter-programm to the kernel.
Therefore it supports using "PR_SET_NO_NEW_PRIVS" in case of unpriviledged
users, but also is able to make use of "geteuid()" or "CAP_SYS_ADMIN+p"
(only compiled via 'make DEFINES="-DCONFIG_WITHCAPABILITIES" LDFLAGS="-lcap"').

For freepascal there is a wrapper-unit (syssec.pas) to utilize libsyssec also
in lazarus apps. (For example in webapps, where extra protection is paramount.)

Finally a small demo application (source/demo.c) can be used in order to fill
up and restrict namespaces for serverduty on an internet accessable machine...


by S. Bärwolf, Rudolstadt 2024
