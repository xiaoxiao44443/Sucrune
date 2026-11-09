#ifndef SUCRUNE_ELF_PROBE_H
#define SUCRUNE_ELF_PROBE_H
#include <stddef.h>
/* Trusted embedded ELF only, in a disposable process; not a sandbox API. */
int sucrune_elf_probe_run(char *report, size_t capacity);
#endif
