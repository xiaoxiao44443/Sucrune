#ifndef SUCRUNE_ELF_LOADER_H
#define SUCRUNE_ELF_LOADER_H

#include <stddef.h>
#include <stdint.h>

#define SUCRUNE_ELF_MAX_LOADS 16U
#define SUCRUNE_ELF_MAX_PHDRS 32U
#define SUCRUNE_ELF_MAX_IMAGE (16U * 1024U * 1024U)

enum sucrune_elf_error {
    SUCRUNE_ELF_OK = 0,
    SUCRUNE_ELF_INVALID_ARGUMENT,
    SUCRUNE_ELF_BAD_HEADER,
    SUCRUNE_ELF_UNSUPPORTED,
    SUCRUNE_ELF_BAD_BOUNDS,
    SUCRUNE_ELF_BAD_ALIGNMENT,
    SUCRUNE_ELF_BAD_PERMISSIONS,
    SUCRUNE_ELF_OVERLAP,
    SUCRUNE_ELF_BAD_ENTRY,
    SUCRUNE_ELF_MAP_FAILED,
    SUCRUNE_ELF_PROTECT_FAILED
};

struct sucrune_elf_segment {
    size_t offset;
    size_t vaddr;
    size_t filesz;
    size_t memsz;
    size_t page_offset;
    size_t page_length;
    unsigned int flags; /* ELF PF_R/PF_W/PF_X, not mmap PROT values. */
};

struct sucrune_elf_plan {
    size_t page_size;
    size_t image_size;
    size_t alignment;
    uintptr_t virtual_base; /* Lowest PT_LOAD page; zero for fixture ET_DYN. */
    int fixed_address;
    size_t entry_offset;
    size_t phdr_offset;
    unsigned int phnum;
    unsigned int phentsize;
    int phdr_mapped;
    size_t segment_count;
    struct sucrune_elf_segment segments[SUCRUNE_ELF_MAX_LOADS];
};

struct sucrune_elf_range {
    uintptr_t start;
    size_t length;
    unsigned int flags;
};

struct sucrune_elf_image {
    void *reservation;
    size_t reservation_size;
    void *base;
    size_t size;
    uintptr_t load_bias;
    uintptr_t entry;
    uintptr_t phdr; /* Zero when the ELF program header table is not mapped. */
    unsigned int phnum;
    unsigned int phentsize;
    size_t segment_count;
    struct sucrune_elf_range segments[SUCRUNE_ELF_MAX_LOADS];
};

/* Narrow, trusted-fixture format: ELF64 little-endian AArch64 ET_DYN,
 * position-independent without PT_DYNAMIC, interpreter, TLS or relocations.
 * Lowest load page must be zero; image is bounded to 16 MiB. This is not a
 * validator or isolation boundary for hostile programs. Validation does not
 * map or execute memory, so it is also usable from x86_64 test processes. */
enum sucrune_elf_error sucrune_elf_validate(const void *bytes, size_t length,
                                          size_t page_size,
                                          struct sucrune_elf_plan *plan);
enum sucrune_elf_error sucrune_elf_load(const void *bytes, size_t length,
                                      struct sucrune_elf_image *image);
/* Separate trusted static-program profile: ARM64 ET_EXEC, PT_TLS and bounded
 * read-only metadata. No interpreter, dynamic section or runtime relocations.
 * Maps only if the exact linked address is free; never uses MAP_FIXED. */
enum sucrune_elf_error sucrune_elf_validate_program(const void *bytes, size_t length,
                                                  size_t page_size,
                                                  struct sucrune_elf_plan *plan);
enum sucrune_elf_error sucrune_elf_load_program(const void *bytes, size_t length,
                                              struct sucrune_elf_image *image);
void sucrune_elf_unload(struct sucrune_elf_image *image);
/* Pure bounded arithmetic; safe to call from the controlled signal handler.
 * A nonempty range must fit wholly within one readable PT_LOAD segment. */
int sucrune_elf_readable(const struct sucrune_elf_image *image,
                        uintptr_t address, size_t length);
const char *sucrune_elf_error_message(enum sucrune_elf_error error);

/* Validate the real fixture at 4/16 KiB, then reject mutated copies. Returns
 * number of negative cases passed, or zero on failure. Never maps or executes
 * mutated files. Defined in loader_tests.c. */
int sucrune_elf_selftest(const void *bytes, size_t length);
/* Synthetic static-program parser positives and mutations; never executes. */
int sucrune_elf_program_selftest(void);

#endif
