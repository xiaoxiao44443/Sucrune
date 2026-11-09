#ifndef SUCRUNE_TRUSTED_EXEC_IMAGE_H
#define SUCRUNE_TRUSTED_EXEC_IMAGE_H
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/* An application may supply one static Linux executable for an exact guest
 * exec path. Ordinary opens still see project contents. Each execution opens
 * an independent description of the same sealed bytes. */
#define SUCRUNE_TRUSTED_IMAGE_LIMIT (16U * 1024U * 1024U)
struct sucrune_exec_image {
    atomic_uint references;
    int fd;
    char path[];
};

static inline int sucrune_exec_image_create(const char *path, const void *bytes, size_t size,
                                            struct sucrune_exec_image **out) {
    *out = NULL;
    if (!path || path[0] != '/' || strlen(path) >= 1024 || !bytes || size > SUCRUNE_TRUSTED_IMAGE_LIMIT)
        return -EINVAL;
    if (size < sizeof(Elf64_Ehdr)) return -ENOEXEC;
    Elf64_Ehdr elf;
    memcpy(&elf, bytes, sizeof(elf));
    if (memcmp(elf.e_ident, ELFMAG, SELFMAG) || elf.e_ident[EI_CLASS] != ELFCLASS64 ||
        elf.e_ident[EI_DATA] != ELFDATA2LSB || elf.e_machine != EM_AARCH64 ||
        (elf.e_type != ET_EXEC && elf.e_type != ET_DYN) || elf.e_phentsize != sizeof(Elf64_Phdr) ||
        !elf.e_phnum || elf.e_phoff > size || elf.e_phnum > (size - elf.e_phoff) / sizeof(Elf64_Phdr))
        return -ENOEXEC;
    for (size_t i = 0; i < elf.e_phnum; i++) {
        Elf64_Phdr ph;
        memcpy(&ph, (const char *)bytes + elf.e_phoff + i * sizeof(ph), sizeof(ph));
        if (ph.p_type == PT_INTERP || ph.p_type == PT_DYNAMIC) return -ENOEXEC;
    }
    /* These are interpreter input bytes. Android can disallow executable
     * memfds entirely; older kernels reject MFD_NOEXEC_SEAL with EINVAL. */
    const unsigned int flags = MFD_CLOEXEC | MFD_ALLOW_SEALING;
    const unsigned int noexec_seal = 0x0008U;
    int fd = (int)syscall(SYS_memfd_create, "sucrune-executable", flags | noexec_seal);
    if (fd < 0 && errno == EINVAL) fd = (int)syscall(SYS_memfd_create, "sucrune-executable", flags);
    if (fd < 0) return -errno;
    size_t pos = 0;
    int error = 0;
    while (pos < size) {
        ssize_t n = write(fd, (const char *)bytes + pos, size - pos);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { error = n < 0 ? errno : EIO; break; }
        pos += (size_t)n;
    }
    if (!error && fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) < 0) error = errno;
    struct sucrune_exec_image *image = NULL;
    if (!error) {
        image = malloc(sizeof(*image) + strlen(path) + 1);
        if (!image) error = ENOMEM;
    }
    if (error) { close(fd); return -error; }
    atomic_init(&image->references, 1U);
    strcpy(image->path, path);
    image->fd = fd;
    *out = image;
    return 0;
}
static inline void sucrune_exec_image_retain(struct sucrune_exec_image *image) {
    if (image) atomic_fetch_add(&image->references, 1U);
}
static inline void sucrune_exec_image_release(struct sucrune_exec_image *image) {
    if (image && atomic_fetch_sub(&image->references, 1U) == 1U) {
        close(image->fd);
        free(image);
    }
}
static inline int sucrune_exec_image_open(const struct sucrune_exec_image *image, const char *path) {
    if (!image || strcmp(image->path, path)) return -ENOENT;
    char pinned[48];
    (void)snprintf(pinned, sizeof(pinned), "/proc/self/fd/%d", image->fd);
    int fd = open(pinned, O_RDONLY | O_CLOEXEC);
    /* Only a path mismatch means "use the project executable". */
    if (fd < 0) return errno == ENOENT ? -EIO : -errno;
    return fd;
}
#endif
