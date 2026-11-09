#ifndef SUCRUNE_SHELL_RUNTIME_H
#define SUCRUNE_SHELL_RUNTIME_H
#include <stddef.h>
int sucrune_shell_run(int broker, const char *script, const char *cwd,
                     int output, int error_output, char *report, size_t capacity);
int sucrune_program_run(int broker, const char *program, size_t argc, const char *const *argv,
                       size_t envc, const char *const *envp, const char *cwd,
                       int output, int error_output, char *report, size_t capacity, int owned_input);
int sucrune_linux_run(int broker, const char *path, size_t argc, const char *const *argv,
                     size_t envc, const char *const *envp, const char *cwd,
                     int output, int error_output, char *report, size_t capacity, int owned_input);
#endif
