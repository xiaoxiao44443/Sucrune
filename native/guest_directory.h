#ifndef SUCRUNE_GUEST_DIRECTORY_H
#define SUCRUNE_GUEST_DIRECTORY_H
#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>

/* A manager-owned directory tree. All strings are UTF-8 paths relative to its root.
 * No Android paths or URI grants cross the guest boundary. Methods return 0/-errno,
 * except open returns an owned descriptor. list transfers malloc-allocated UTF-8
 * strings and their array on success. Concurrent project processes may call methods. */
struct sucrune_guest_directory {
    void *context;
    void (*destroy)(void *);
    int (*stat)(void *, const char *, struct stat *);
    int (*list)(void *, const char *, char ***, size_t *);
    int (*open)(void *, const char *, int, mode_t);
    int (*mkdir)(void *, const char *);
    int (*remove)(void *, const char *, bool);
    int (*rename)(void *, const char *, const char *, unsigned int);
};
#endif
