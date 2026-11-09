#ifndef SUCRUNE_PROBE_H
#define SUCRUNE_PROBE_H

#include <stddef.h>

#define SUCRUNE_PROBE_REPORT_CAPACITY 4096

/* Must only be called in a disposable, externally supervised process.
 * Installs the process-wide SIGSYS handler temporarily, but installs seccomp
 * only on a dedicated pthread. Returns 0 for a passed experiment, 1 otherwise.
 * No result asserts that a Linux runtime or security sandbox is implemented.
 */
int sucrune_probe_run(char *report, size_t capacity);

#endif
