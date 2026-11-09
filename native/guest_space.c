#include "guest_space.h"
#include <errno.h>
#include <limits.h>
#include <string.h>

#if defined(SUCRUNE_SPACE_TEST_BACKEND)
/* A Windows-only test adapter supplies equivalent reservation/protection
 * primitives. Production Android/Linux builds always use mmap below. */
#define PROT_NONE 0
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_PRIVATE 2U
#define MAP_FIXED 0x10U
#define MAP_ANONYMOUS 0x20U
#define MAP_NORESERVE 0x4000U
#define MAP_STACK 0x20000U
#define MAP_FIXED_NOREPLACE 0x100000U
extern size_t sucrune_space_os_page_size(void);
extern int64_t sucrune_space_os_reserve(uintptr_t, size_t);
extern int sucrune_space_os_replace(uintptr_t, size_t, int);
extern int sucrune_space_os_protect(uintptr_t, size_t, int);
extern int sucrune_space_os_release(uintptr_t, size_t);
extern int sucrune_space_os_discard(uintptr_t, size_t, int);
extern void sucrune_space_os_sync_code(uintptr_t, size_t);
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000U
#endif
#ifndef MAP_STACK
#define MAP_STACK 0x20000U
#endif
static size_t sucrune_space_os_page_size(void) {
    long value = sysconf(_SC_PAGESIZE);
    return value > 0 ? (size_t)value : 0U;
}
static int64_t sucrune_space_os_reserve(uintptr_t address, size_t length) {
    void *result = mmap((void *)address, length, PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    return result == MAP_FAILED ? -(int64_t)errno : (int64_t)(uintptr_t)result;
}
static int sucrune_space_os_replace(uintptr_t address, size_t length, int protection) {
    void *result = mmap((void *)address, length, protection,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_NORESERVE, -1, 0);
    if (result == MAP_FAILED) return -errno;
    return (uintptr_t)result == address ? 0 : -EFAULT;
}
static int sucrune_space_os_protect(uintptr_t address, size_t length, int protection) {
    return mprotect((void *)address, length, protection) == 0 ? 0 : -errno;
}
static int sucrune_space_os_release(uintptr_t address, size_t length) {
    return munmap((void *)address, length) == 0 ? 0 : -errno;
}
static int sucrune_space_os_discard(uintptr_t address, size_t length, int protection) {
    (void)protection;
    return madvise((void *)address, length, MADV_DONTNEED) == 0 ? 0 : -errno;
}
static void sucrune_space_os_sync_code(uintptr_t address, size_t length) {
    __builtin___clear_cache((char *)address, (char *)(address + length));
}
#endif

enum change { REPLACE, REPLACE_SHARED_READONLY, REPLACE_SHARED_READWRITE, REMOVE, PROTECT, MARK_FILE };
static int power_two(size_t value) { return value != 0U && (value & (value - 1U)) == 0U; }
static int writable_executable(int protection) {
    return (protection & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC);
}
static int valid_protection(const struct sucrune_guest_space *space, int protection) {
    return (protection & ~(PROT_READ | PROT_WRITE | PROT_EXEC)) == 0 &&
           (!writable_executable(protection) || space->allow_rwx != 0U);
}
static int rounded(const struct sucrune_guest_space *space, size_t length, size_t *result) {
    if (space == NULL || space->base == 0U || space->size == 0U ||
        !power_two(space->page_size) || length == 0U || length > SIZE_MAX - (space->page_size - 1U)) return -EINVAL;
    *result = (length + space->page_size - 1U) & ~(space->page_size - 1U);
    return *result <= space->size ? 0 : -ENOMEM;
}
static int align_up(uintptr_t value, size_t alignment, uintptr_t *result) {
    if (value > UINTPTR_MAX - (alignment - 1U)) return -ENOMEM;
    *result = (value + alignment - 1U) & ~(uintptr_t)(alignment - 1U);
    return 0;
}
int sucrune_space_contains(const struct sucrune_guest_space *space, uintptr_t address, size_t length) {
    return space != NULL && space->base != 0U && address >= space->base &&
           address - space->base <= space->size && length <= space->size - (address - space->base);
}
static int initialize(struct sucrune_guest_space *space, uintptr_t base, size_t size, size_t page, int exact) {
    if (space == NULL) return -EINVAL;
    memset(space, 0, sizeof(*space));
    if ((page != 4096U && page != 16384U) || page != sucrune_space_os_page_size() ||
        size == 0U || size % page != 0U || size > INTPTR_MAX ||
        (exact != 0 && (base == 0U || base % page != 0U || base > (uintptr_t)INTPTR_MAX - size))) return -EINVAL;
    int64_t reservation = sucrune_space_os_reserve(base, size);
    if (reservation < 0) return (int)reservation;
    uintptr_t result = (uintptr_t)reservation;
    if (result == 0U || result % page != 0U || result > (uintptr_t)INTPTR_MAX - size || (exact != 0 && result != base)) {
        (void)sucrune_space_os_release(result, size);
        return exact != 0 ? -EADDRINUSE : -ENOMEM;
    }
    space->base = result; space->size = size; space->page_size = page;
    return 0;
}
int sucrune_space_init(struct sucrune_guest_space *space, size_t size, size_t page_size) {
    return initialize(space, 0U, size, page_size, 0);
}
int sucrune_space_init_exact(struct sucrune_guest_space *space, uintptr_t base, size_t size, size_t page_size) {
    return initialize(space, base, size, page_size, 1);
}
#if !defined(SUCRUNE_SPACE_TEST_BACKEND)
static int reserve_exact_part(uintptr_t base, size_t size) {
    if (size == 0U) return 0;
    int64_t mapped = sucrune_space_os_reserve(base, size);
    if (mapped < 0) return (int)mapped;
    if ((uintptr_t)mapped == base) return 0;
    int released = sucrune_space_os_release((uintptr_t)mapped, size);
    return released == 0 ? -EADDRINUSE : released;
}
#endif
int sucrune_space_extend_exact(struct sucrune_guest_space *space, uintptr_t base, size_t size, size_t max_span) {
    if (space == NULL || space->base == 0U || space->page_size == 0U || base == 0U || size == 0U ||
        base % space->page_size != 0U || size % space->page_size != 0U ||
        size > (size_t)INTPTR_MAX || base > (uintptr_t)INTPTR_MAX - size) return -EINVAL;
    if (sucrune_space_contains(space, base, size)) return 0;
    uintptr_t start = base < space->base ? base : space->base;
    uintptr_t old_end = space->base + space->size, end = base + size;
    if (end < old_end) end = old_end;
    if (end - start > max_span) return -ENOMEM;
#if defined(SUCRUNE_SPACE_TEST_BACKEND)
    /* Windows VirtualFree cannot release separate reservations as one range. */
    return -ENOTSUP;
#else
    size_t prefix = space->base - start;
    int error = reserve_exact_part(start, prefix);
    if (error != 0) return error;
    error = reserve_exact_part(old_end, end - old_end);
    if (error != 0) {
        if (prefix != 0U) {
            int released = sucrune_space_os_release(start, prefix);
            if (released != 0) return released;
        }
        return error;
    }
    /* VMA entries use absolute addresses. A subsequent committed exec clears
     * the enlarged range, then installs its filter before guest re-entry. */
    space->base = start;
    space->size = end - start;
    return 0;
#endif
}
int sucrune_space_set_rwx_policy(struct sucrune_guest_space *space, int allow) {
    if (space == NULL || space->base == 0U || space->size == 0U ||
        !power_two(space->page_size) || (allow != 0 && allow != 1)) return -EINVAL;
    if (space->count != 0U) return -EBUSY;
    space->allow_rwx = (unsigned int)allow;
    return 0;
}
int sucrune_space_destroy(struct sucrune_guest_space *space) {
    if (space == NULL) return -EINVAL;
    if (space->base == 0U) return 0;
    int result = sucrune_space_os_release(space->base, space->size);
    if (result == 0) memset(space, 0, sizeof(*space));
    return result;
}
static int covered(const struct sucrune_guest_space *space, uintptr_t address, size_t length, int required) {
    if (!sucrune_space_contains(space, address, length)) return 0;
    if (length == 0U) return 1;
    uintptr_t cursor = address, end = address + length;
    for (size_t i = 0U; i < space->count && cursor < end; i++) {
        const struct sucrune_space_vma *area = &space->areas[i];
        uintptr_t stop = area->start + area->length;
        if (stop <= cursor) continue;
        if (area->start > cursor || (area->protection & required) != required) return 0;
        cursor = stop < end ? stop : end;
    }
    return cursor == end;
}
int sucrune_space_access(const struct sucrune_guest_space *space, uintptr_t address, size_t length, int write_access) {
    return covered(space, address, length, write_access != 0 ? PROT_WRITE : PROT_READ);
}
static int free_range(const struct sucrune_guest_space *space, uintptr_t address, size_t length) {
    if (!sucrune_space_contains(space, address, length)) return 0;
    uintptr_t end = address + length;
    for (size_t i = 0U; i < space->count; i++) {
        const struct sucrune_space_vma *area = &space->areas[i];
        if (area->start >= end) break;
        if (area->start + area->length > address) return 0;
    }
    return 1;
}
int sucrune_space_find_gap(const struct sucrune_guest_space *space, uintptr_t hint,
                           size_t length, size_t alignment, uintptr_t *address) {
    size_t bytes;
    int result = rounded(space, length, &bytes);
    if (result != 0 || address == NULL) return result != 0 ? result : -EINVAL;
    if (alignment == 0U) alignment = space->page_size;
    if (!power_two(alignment) || alignment < space->page_size) return -EINVAL;
    uintptr_t candidate;
    if (hint != 0U && align_up(hint, alignment, &candidate) == 0 && free_range(space, candidate, bytes)) {
        *address = candidate; return 0;
    }
    if (align_up(space->base, alignment, &candidate) != 0) return -ENOMEM;
    for (size_t i = 0U; i < space->count; i++) {
        const struct sucrune_space_vma *area = &space->areas[i];
        if (candidate <= area->start && bytes <= area->start - candidate) { *address = candidate; return 0; }
        if (candidate < area->start + area->length && align_up(area->start + area->length, alignment, &candidate) != 0) return -ENOMEM;
    }
    if (!sucrune_space_contains(space, candidate, bytes)) return -ENOMEM;
    *address = candidate; return 0;
}
static int append(struct sucrune_guest_space *space, size_t *count, struct sucrune_space_vma area) {
    if (area.length == 0U) return 0;
    if (*count != 0U) {
        struct sucrune_space_vma *previous = &space->pending[*count - 1U];
        if (previous->start + previous->length == area.start && previous->protection == area.protection &&
            previous->file_snapshot == area.file_snapshot && previous->shared_max_protection == area.shared_max_protection) {
            previous->length += area.length; return 0;
        }
    }
    if (*count == SUCRUNE_SPACE_MAX_VMAS) return -ENOMEM;
    space->pending[(*count)++] = area; return 0;
}
/* Construct the entire metadata update before any mapping can change. */
static int prepare(struct sucrune_guest_space *space, uintptr_t start, size_t length,
                   enum change change, int protection, size_t *count) {
    uintptr_t end = start + length;
    int replacing = change == REPLACE || change == REPLACE_SHARED_READONLY || change == REPLACE_SHARED_READWRITE;
    struct sucrune_space_vma replacement = { .start = start, .length = length, .protection = protection,
                                              .shared_max_protection = change == REPLACE_SHARED_READWRITE ? PROT_READ | PROT_WRITE :
                                                                       change == REPLACE_SHARED_READONLY ? PROT_READ : 0 };
    int inserted = 0, result;
    *count = 0U;
    for (size_t i = 0U; i < space->count; i++) {
        struct sucrune_space_vma area = space->areas[i];
        uintptr_t area_end = area.start + area.length;
        if (area_end <= start) { if ((result = append(space, count, area)) != 0) return result; continue; }
        if (area.start >= end) {
            if (replacing && inserted == 0) { if ((result = append(space, count, replacement)) != 0) return result; inserted = 1; }
            if ((result = append(space, count, area)) != 0) return result;
            continue;
        }
        if (area.start < start) {
            struct sucrune_space_vma prefix = area; prefix.length = start - area.start;
            if ((result = append(space, count, prefix)) != 0) return result;
        }
        if (replacing && inserted == 0) {
            if ((result = append(space, count, replacement)) != 0) return result;
            inserted = 1;
        } else if (change == PROTECT || change == MARK_FILE) {
            struct sucrune_space_vma overlap = area;
            overlap.start = area.start > start ? area.start : start;
            overlap.length = (area_end < end ? area_end : end) - overlap.start;
            if (change == PROTECT) overlap.protection = protection;
            else overlap.file_snapshot = 1U;
            if ((result = append(space, count, overlap)) != 0) return result;
        }
        if (area_end > end) {
            struct sucrune_space_vma suffix = area; suffix.start = end; suffix.length = area_end - end;
            if ((result = append(space, count, suffix)) != 0) return result;
        }
    }
    if (replacing && inserted == 0) return append(space, count, replacement);
    return 0;
}
static void commit(struct sucrune_guest_space *space, size_t count) {
    memcpy(space->areas, space->pending, count * sizeof(space->areas[0]));
    space->count = count; space->mapped_bytes = 0U; space->accessible_bytes = 0U;
    for (size_t i = 0U; i < count; i++) {
        space->mapped_bytes += space->areas[i].length;
        if (space->areas[i].protection != PROT_NONE) space->accessible_bytes += space->areas[i].length;
    }
    if (space->accessible_bytes > space->peak_accessible_bytes) space->peak_accessible_bytes = space->accessible_bytes;
}
static int range(struct sucrune_guest_space *space, uintptr_t address, size_t length, size_t *bytes) {
    int result = rounded(space, length, bytes);
    if (result != 0) return result;
    if (address % space->page_size != 0U || !sucrune_space_contains(space, address, *bytes)) return -EINVAL;
    return 0;
}
int64_t sucrune_space_map(struct sucrune_guest_space *space, uintptr_t hint, size_t length,
                          size_t alignment, int protection, unsigned int flags) {
    size_t bytes;
    int result = rounded(space, length, &bytes);
    if (result != 0) return result;
    if (!valid_protection(space, protection)) return -EACCES;
    const unsigned int allowed = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_FIXED_NOREPLACE | MAP_NORESERVE | MAP_STACK;
    if ((flags & ~allowed) != 0U || (flags & (MAP_PRIVATE | MAP_ANONYMOUS)) != (MAP_PRIVATE | MAP_ANONYMOUS)) return -EINVAL;
    if (alignment == 0U) alignment = space->page_size;
    if (!power_two(alignment) || alignment < space->page_size) return -EINVAL;
    uintptr_t address = hint;
    if ((flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) != 0U) {
        if (range(space, address, bytes, &bytes) != 0 || address % alignment != 0U) return -EINVAL;
        if ((flags & MAP_FIXED_NOREPLACE) != 0U && !free_range(space, address, bytes)) return -EEXIST;
    } else {
        result = sucrune_space_find_gap(space, hint, bytes, alignment, &address);
        if (result != 0) return result;
    }
    size_t count;
    result = prepare(space, address, bytes, REPLACE, protection, &count);
    if (result != 0) return result;
    result = sucrune_space_os_replace(address, bytes, protection);
    if (result != 0) return result;
    if ((protection & PROT_EXEC) != 0) sucrune_space_os_sync_code(address, bytes);
    commit(space, count); return (int64_t)address;
}
int64_t sucrune_space_map_shared_file(struct sucrune_guest_space *space, uintptr_t hint,
                                       size_t length, int protection, int fd, uint64_t offset) {
    if ((protection & ~(PROT_READ | PROT_WRITE)) != 0) return -EACCES;
    size_t bytes;
    int result = rounded(space, length, &bytes);
    if (result != 0) return result;
    if (offset % space->page_size != 0 || offset > INT64_MAX - bytes) return -EINVAL;
    uintptr_t address;
    result = sucrune_space_find_gap(space, hint, bytes, space->page_size, &address);
    if (result != 0) return result;
#if defined(SUCRUNE_SPACE_TEST_BACKEND)
    (void)fd;
    return -ENOTSUP;
#else
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) return -errno;
    int mode = flags & O_ACCMODE;
    if ((flags & O_PATH) || (mode != O_RDONLY && mode != O_RDWR) ||
        ((protection & PROT_WRITE) && mode != O_RDWR)) return -EACCES;
    size_t count;
    enum change change = mode == O_RDWR ? REPLACE_SHARED_READWRITE : REPLACE_SHARED_READONLY;
    result = prepare(space, address, bytes, change, protection, &count);
    if (result != 0) return result;
    /* Stage a real mapping before replacing part of our reservation. Linux
     * MAP_FIXED mmap failures can remove a destination even on failure. A
     * failed initial file/SELinux check here cannot punch an arena hole. */
    void *staged = mmap(NULL, bytes, protection, MAP_SHARED, fd, (off_t)offset);
    if (staged == MAP_FAILED) return -errno;
    if (mremap(staged, bytes, bytes, MREMAP_MAYMOVE | MREMAP_FIXED, (void *)address) == MAP_FAILED) {
        int error = errno;
        (void)munmap(staged, bytes);
        /* mremap can unmap a destination before discovering an error. We own
         * this free gap and must retain its reservation for future MAP_FIXED. */
        if (sucrune_space_os_replace(address, bytes, PROT_NONE) != 0) _exit(125);
        return -error;
    }
    commit(space, count);
    return (int64_t)address;
#endif
}
int sucrune_space_register(struct sucrune_guest_space *space, uintptr_t address, size_t length, int protection) {
    size_t bytes, count;
    int result = range(space, address, length, &bytes);
    if (result != 0) return result;
    if (!valid_protection(space, protection)) return -EACCES;
    /* Registration must not silently remove file-snapshot ownership. */
    if (!free_range(space, address, bytes)) return sucrune_space_protect(space, address, bytes, protection);
    result = prepare(space, address, bytes, REPLACE, protection, &count);
    if (result != 0) return result;
    result = sucrune_space_os_protect(address, bytes, protection);
    if (result == 0) {
        if ((protection & PROT_EXEC) != 0) sucrune_space_os_sync_code(address, bytes);
        commit(space, count);
    }
    return result;
}
int sucrune_space_protect(struct sucrune_guest_space *space, uintptr_t address, size_t length, int protection) {
    size_t bytes, count;
    int result = range(space, address, length, &bytes);
    if (result != 0) return result;
    if (!valid_protection(space, protection)) return -EACCES;
    if (!covered(space, address, bytes, 0)) return -ENOMEM;
    /* Preflight the complete range: an anonymous prefix must not become W+X
     * before a later file-backed VMA rejects the same protection request. */
    if ((protection & (PROT_WRITE | PROT_EXEC)) != 0) {
        uintptr_t end = address + bytes;
        for (size_t i = 0U; i < space->count; i++) {
            const struct sucrune_space_vma *area = &space->areas[i];
            if (area->start < end && area->start + area->length > address &&
                ((area->shared_max_protection && (protection & ~area->shared_max_protection)) ||
                 (area->file_snapshot && writable_executable(protection)))) return -EACCES;
        }
    }
    result = prepare(space, address, bytes, PROTECT, protection, &count);
    if (result != 0) return result;
    result = sucrune_space_os_protect(address, bytes, protection);
    if (result == 0) {
        if ((protection & PROT_EXEC) != 0) sucrune_space_os_sync_code(address, bytes);
        commit(space, count);
    }
    return result;
}
int sucrune_space_mark_file(struct sucrune_guest_space *space, uintptr_t address, size_t length) {
    size_t bytes, count;
    int result = range(space, address, length, &bytes);
    if (result != 0) return result;
    if (!covered(space, address, bytes, 0)) return -ENOMEM;
    uintptr_t end = address + bytes;
    for (size_t i = 0U; i < space->count; i++) {
        const struct sucrune_space_vma *area = &space->areas[i];
        if (area->start < end && area->start + area->length > address && writable_executable(area->protection)) return -EACCES;
    }
    result = prepare(space, address, bytes, MARK_FILE, 0, &count);
    if (result == 0) commit(space, count);
    return result;
}
int sucrune_space_unmap(struct sucrune_guest_space *space, uintptr_t address, size_t length) {
    size_t bytes, count;
    int result = range(space, address, length, &bytes);
    if (result != 0) return result;
    result = prepare(space, address, bytes, REMOVE, 0, &count);
    if (result != 0) return result;
    result = sucrune_space_os_replace(address, bytes, PROT_NONE);
    if (result == 0) commit(space, count);
    return result;
}
int sucrune_space_discard(struct sucrune_guest_space *space, uintptr_t address, size_t length) {
    size_t bytes;
    int result = range(space, address, length, &bytes);
    if (result != 0) return result;
    if (!covered(space, address, bytes, 0)) return -ENOMEM;
    uintptr_t end = address + bytes;
    for (size_t i = 0U; i < space->count; i++) {
        const struct sucrune_space_vma *area = &space->areas[i];
        if (area->start < end && area->start + area->length > address && area->file_snapshot != 0U) return -ENOTSUP;
    }
    for (size_t i = 0U; i < space->count; i++) {
        const struct sucrune_space_vma *area = &space->areas[i];
        uintptr_t begin = area->start > address ? area->start : address;
        uintptr_t stop = area->start + area->length < end ? area->start + area->length : end;
        if (begin < stop) {
            result = sucrune_space_os_discard(begin, stop - begin, area->protection);
            if (result != 0) return result;
        }
    }
    return 0;
}
int sucrune_space_sync(const struct sucrune_guest_space *space, uintptr_t address,
                       size_t length, unsigned int flags) {
    /* Linux ABI values, independent of the host's msync constants. */
    const unsigned int async = 1U, invalidate = 2U, sync = 4U;
    if (space == NULL || space->base == 0U || space->size == 0U ||
        !power_two(space->page_size)) return -EINVAL;
    if ((flags & ~(async | invalidate | sync)) != 0U ||
        address % space->page_size != 0U ||
        (flags & (async | sync)) == (async | sync)) return -EINVAL;
    /* Conservatively reject page-rounding overflow rather than accepting
     * Linux's unsigned-wrap corner where a near-SIZE_MAX length becomes zero. */
    if (length > SIZE_MAX - (space->page_size - 1U)) return -ENOMEM;
    size_t bytes = (length + space->page_size - 1U) & ~(space->page_size - 1U);
    if (bytes > UINTPTR_MAX - address) return -ENOMEM;
    if (bytes == 0U) return 0;
    if (!covered(space, address, bytes, 0)) return -ENOMEM;
    /* Physical reservations cover logical holes, so validate first. */
#if !defined(SUCRUNE_SPACE_TEST_BACKEND)
    for (size_t i = 0; i < space->count; ++i) {
        const struct sucrune_space_vma *area = &space->areas[i];
        if (area->shared_max_protection && area->start < address + bytes && area->start + area->length > address)
            return msync((void *)address, bytes, (int)flags) == 0 ? 0 : -errno;
    }
#endif
    return 0;
}
