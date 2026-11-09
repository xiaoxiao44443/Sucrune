#ifndef SUCRUNE_GUEST_DEVICES_H
#define SUCRUNE_GUEST_DEVICES_H

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>

/* These checks also run with guest TLS installed in a pre-exec fork child.
 * Only exact, allowlisted literals are returned to the native open/stat calls. */
static inline int sucrune_device_name(const unsigned char *name, const char *expected) {
    while (*name != 0U && *name == (unsigned char)*expected) { name++; expected++; }
    return *name == 0U && *expected == '\0';
}

static inline const char *sucrune_device_path(const unsigned char *path) {
    if (*path != '/') return 0;
    while (*path == '/') path++;
    if (*path++ != 'd' || *path++ != 'e' || *path++ != 'v' || *path++ != '/') return 0;
    while (*path == '/') path++;
    if (sucrune_device_name(path, "null")) return "/dev/null";
    if (sucrune_device_name(path, "urandom")) return "/dev/urandom";
    if (sucrune_device_name(path, "random")) return "/dev/random";
    return 0;
}

static inline int sucrune_device_readonly(const char *device) {
    return sucrune_device_name((const unsigned char *)device, "/dev/random");
}

static inline int sucrune_device_open_flags(const char *device, uint64_t flags) {
    const unsigned int allowed = O_ACCMODE | O_CLOEXEC | O_LARGEFILE | O_NONBLOCK | O_APPEND |
        O_NOCTTY | O_NOFOLLOW | O_DIRECTORY | O_CREAT | O_EXCL | O_TRUNC | O_PATH;
    if ((flags & ~((uint64_t)allowed)) != 0U || (flags & O_ACCMODE) == O_ACCMODE) return -EINVAL;
    if ((flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL)) return -EEXIST;
    if (sucrune_device_readonly(device) && ((flags & O_ACCMODE) != O_RDONLY || (flags & O_TRUNC))) return -EACCES;
    return ((int)flags & ~O_CREAT) | O_NOFOLLOW | O_CLOEXEC;
}

#endif
