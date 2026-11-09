#ifndef SUCRUNE_PROGRAM_CATALOG_H
#define SUCRUNE_PROGRAM_CATALOG_H
#include <stddef.h>
struct sucrune_program {
    const char *id, *name, *version, *path;
    const unsigned char *start, *end;
    int static_program;
};
/* Only build-time embedded entries. An identifier is never a filesystem path. */
const struct sucrune_program *sucrune_program_find(const char *identifier);
/* Exact reserved executable names, independent of project files or PATH.
 * Includes the hidden freestanding shell, which is not a public program ID. */
const struct sucrune_program *sucrune_program_find_path(const char *path);
int sucrune_program_list(char *json, size_t capacity);
#endif
