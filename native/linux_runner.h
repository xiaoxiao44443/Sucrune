#ifndef SUCRUNE_LINUX_RUNNER_H
#define SUCRUNE_LINUX_RUNNER_H
#include <stddef.h>
int sucrune_linux_is_runner(void);
/* Standalone runner only. Send the truthful pre-exit report, then let the
 * kernel reclaim the entire guest thread group. The parent still waitpids. */
_Noreturn void sucrune_linux_exit_group(const char *report);

/* The Android worker supervises a fresh packaged Bionic PIE process. User
 * strings travel in a bounded SOCK_SEQPACKET message, never in exec argv/env.
 * broker/output/error_output are borrowed. owned_input is consumed on every
 * path; after fork the parent closes it before waiting for child startup.
 * Return only after waitpid proves the direct child exited, except ECHILD
 * (reported as failure, never described as confirmed cleanup). The Kotlin
 * worker's existing Binder/output/broker/feeder barriers still apply. */
int sucrune_linux_spawn(int broker, const char *path, size_t argc, const char *const *argv,
    size_t envc, const char *const *envp, const char *cwd,
    int output, int error_output, char *report, size_t capacity, int owned_input,
    int borrowed_stop); /* Pipe HUP requests supervised termination and reaping. */

/* Compile linux_runner.c with SUCRUNE_RUNNER_EXECUTABLE for the independently
 * linked PIE entry point. Its filename must be libsucrune_runner.so in the
 * installed/extracted nativeLibraryDir. This is an executable, not a dlopen SO. */
#define SUCRUNE_RUNNER_FILE "libsucrune_runner.so"
#define SUCRUNE_RUNNER_TEXT_LIMIT 65536U
#define SUCRUNE_RUNNER_REPORT_LIMIT 4096U
#endif
