#include "program_catalog.h"
#include <stdio.h>
#include <string.h>
#if defined(__aarch64__)
extern const unsigned char sucrune_musl_smoke_start[], sucrune_musl_smoke_end[];
extern const unsigned char sucrune_lua_start[], sucrune_lua_end[];
extern const unsigned char sucrune_shell_start[], sucrune_shell_end[];
#define PROGRAM_BYTES(name) sucrune_##name##_start, sucrune_##name##_end
#define EXECUTABLE "true"
#else
#define PROGRAM_BYTES(name) NULL, NULL
#define EXECUTABLE "false"
#endif
static const struct sucrune_program programs[] = {
    {"musl-smoke", "Linux libc validation", "1", "/bin/musl-smoke", PROGRAM_BYTES(musl_smoke), 1},
    {"lua", "Lua", "5.4.9", "/bin/lua", PROGRAM_BYTES(lua), 1},
};
static const struct sucrune_program shell_program = {
    "sucrune-sh", "Sucrune Shell", "1", "/bin/sucrune-sh", PROGRAM_BYTES(shell), 0
};
const struct sucrune_program *sucrune_program_find(const char *identifier) {
    if (identifier == NULL) return NULL;
    for (size_t i = 0; i < sizeof(programs) / sizeof(programs[0]); i++)
        if (strcmp(identifier, programs[i].id) == 0) return &programs[i];
    return NULL;
}
const struct sucrune_program *sucrune_program_find_path(const char *path) {
    if (path == NULL) return NULL;
    if (strcmp(path, shell_program.path) == 0) return &shell_program;
    for (size_t i = 0; i < sizeof(programs) / sizeof(programs[0]); i++)
        if (strcmp(path, programs[i].path) == 0) return &programs[i];
    return NULL;
}
int sucrune_program_list(char *json, size_t capacity) {
    if (json == NULL || capacity < 3U) return -1;
    size_t used = 1U; json[0] = '[';
    for (size_t i = 0; i < sizeof(programs) / sizeof(programs[0]); i++) {
        const struct sucrune_program *p = &programs[i];
        /* All text comes from this fixed catalog, never caller input. */
        int count = snprintf(json + used, capacity - used,
            "%s{\"program_id\":\"%s\",\"name\":\"%s\",\"version\":\"%s\",\"path\":\"%s\",\"abi\":\"arm64-v8a\",\"available\":%s}",
            i == 0U ? "" : ",", p->id, p->name, p->version, p->path, EXECUTABLE);
        if (count < 0 || (size_t)count >= capacity - used) return -1;
        used += (size_t)count;
    }
    if (capacity - used < 2U) return -1;
    json[used++] = ']'; json[used] = '\0'; return 0;
}
