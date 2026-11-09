#ifndef SUCRUNE_GUEST_SPACE_H
#define SUCRUNE_GUEST_SPACE_H

#include <stddef.h>
#include <stdint.h>

#define SUCRUNE_SPACE_MAX_VMAS 1024U

struct sucrune_space_vma {
    uintptr_t start;
    size_t length;
    int protection;
    unsigned int file_snapshot;
    int shared_max_protection; /* Zero for private VMAs. */
};

/* A sparse virtual reservation, not an RSS quota. The caller serializes all
 * operations; no function allocates metadata or uses guest TLS. Each mmap or
 * MAP_FIXED operation stays inside this instance's owned reservation. */
struct sucrune_guest_space {
    uintptr_t base;
    size_t size, page_size, count;
    size_t mapped_bytes, accessible_bytes, peak_accessible_bytes;
    unsigned int allow_rwx;
    struct sucrune_space_vma areas[SUCRUNE_SPACE_MAX_VMAS];
    /* Preallocated transaction workspace keeps large arrays off signal stacks. */
    struct sucrune_space_vma pending[SUCRUNE_SPACE_MAX_VMAS];
};

/* Return 0 or negative errno. init_exact never uses MAP_FIXED: a colliding
 * hint is rejected and the unexpected host reservation immediately released. */
int sucrune_space_init(struct sucrune_guest_space *space, size_t size, size_t page_size);
int sucrune_space_init_exact(struct sucrune_guest_space *space, uintptr_t base,
                             size_t size, size_t page_size);
/* Extend an existing exact reservation for an ET_EXEC replacement. VMAs and
 * permissions survive preflight. Kernel mappings in either fringe cause a
 * collision; no host page may be replaced to acquire the new range. */
int sucrune_space_extend_exact(struct sucrune_guest_space *space, uintptr_t base,
                               size_t size, size_t max_span);
/* Explicit compatibility policy for anonymous JIT memory only; default is 0.
 * Call after init and before mapping. allow must be 0 or 1; live VMAs return
 * EBUSY. File snapshots always reject W+X. This is not a security boundary. */
int sucrune_space_set_rwx_policy(struct sucrune_guest_space *space, int allow);
int sucrune_space_destroy(struct sucrune_guest_space *space);
int sucrune_space_contains(const struct sucrune_guest_space *space,
                           uintptr_t address, size_t length);
int sucrune_space_access(const struct sucrune_guest_space *space,
                         uintptr_t address, size_t length, int write_access);

/* alignment is a power of two >= page_size, or 0 for page_size. Hint is a
 * preference; an unavailable hint falls back to the first aligned free gap.
 * A PROT_NONE VMA is occupied even though it commits no accessible bytes. */
int sucrune_space_find_gap(const struct sucrune_guest_space *space, uintptr_t hint,
                           size_t length, size_t alignment, uintptr_t *address);

/* Anonymous private mappings only for now. Flags may additionally include
 * MAP_FIXED, MAP_FIXED_NOREPLACE, MAP_NORESERVE and MAP_STACK. MAP_FIXED may
 * replace guest VMAs only. W+X requires explicit anonymous JIT policy; RW -> RX
 * transitions are supported under either policy.
 * Return the address or negative errno. The successful map is zero-filled. */
int64_t sucrune_space_map(struct sucrune_guest_space *space, uintptr_t hint,
                          size_t length, size_t alignment, int protection,
                          unsigned int flags);

/* Real file-backed MAP_SHARED, non-fixed and non-executable. fd must be an
 * admitted O_RDONLY or O_RDWR regular file. The mapping outlives the descriptor. */
int64_t sucrune_space_map_shared_file(struct sucrune_guest_space *space, uintptr_t hint,
                                       size_t length, int protection, int fd, uint64_t offset);

/* Register/protect already-populated bytes in the owned reservation, without
 * discarding them. Used by the ELF loader after its bounded copy. This does
 * not adopt an outside mapping or imply support for file-backed mmap. */
int sucrune_space_register(struct sucrune_guest_space *space, uintptr_t address,
                           size_t length, int protection);
/* Mark copied file/image bytes. Discard of any overlapping snapshot returns
 * ENOTSUP until a backing-aware reload implementation exists; it must not zero
 * these bytes as if they were anonymous memory. Marking an existing W+X range
 * returns EACCES without changing any of its VMAs. */
int sucrune_space_mark_file(struct sucrune_guest_space *space, uintptr_t address, size_t length);
int sucrune_space_protect(struct sucrune_guest_space *space, uintptr_t address,
                          size_t length, int protection);
/* Logical unmap restores anonymous PROT_NONE reservation; host mappings can
 * never occupy the freed range until destroy. Unmapped holes are accepted. */
int sucrune_space_unmap(struct sucrune_guest_space *space, uintptr_t address, size_t length);
/* MADV_DONTNEED only, for existing anonymous VMAs. Future file maps require a
 * backing-aware discard/reload path and must not reuse this blindly. */
int sucrune_space_discard(struct sucrune_guest_space *space, uintptr_t address, size_t length);
/* Validate flags, page alignment and complete logical mapping coverage, then
 * forward msync on shared mappings. Private changes never update the backing
 * file. PROT_NONE is mapped; reservation holes are not.
 * A page-aligned empty range succeeds even outside this space. Unlike Linux's
 * unsigned-wrap corner, page-rounding overflow is rejected with ENOMEM. */
int sucrune_space_sync(const struct sucrune_guest_space *space, uintptr_t address,
                       size_t length, unsigned int flags);

#endif
