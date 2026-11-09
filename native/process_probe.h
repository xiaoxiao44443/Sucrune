#ifndef SUCRUNE_PROCESS_PROBE_H
#define SUCRUNE_PROCESS_PROBE_H
#include <stddef.h>
/* Mechanism measurement only, not Linux guest fork/exec support. Run once in a
 * disposable isolated Service that owns no other child processes. The caller
 * must keep its JNI thread alive until return. Never invoke concurrently.
 * capacity >= 16384 is recommended. 0 means a complete JSON measurement;
 * individual denied capabilities remain explicit negative rc/errno results.
 * All children stay in a dedicated process group; actual wait + inherited lease
 * EOF are required before cleanup_verified can be true. No guest code executes. */
int sucrune_process_probe_spawn(const char *runner_path, char *report, size_t capacity);
/* Only dispatch from packaged runner main for the two documented private modes. */
int sucrune_process_probe_main(int argc, char **argv);
#endif
