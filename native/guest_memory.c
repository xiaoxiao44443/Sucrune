#include "guest_memory.h"
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#define ALLOCATED 8U

int sucrune_memory_init(struct sucrune_guest_memory *m, size_t page) {
    memset(m, 0, sizeof(*m));
    if (page != 4096U && page != 16384U) { errno = EINVAL; return -1; }
    void *arena = mmap(NULL, SUCRUNE_HEAP_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (arena == MAP_FAILED) return -1;
    m->base = (uintptr_t)arena; m->brk = m->base; m->page = page;
    return 0;
}
void sucrune_memory_destroy(struct sucrune_guest_memory *m) {
    if (m->base != 0U) (void)munmap((void *)m->base, SUCRUNE_HEAP_SIZE);
    m->base = 0;
}
static int extent(const struct sucrune_guest_memory *m, uintptr_t address, size_t length) {
    return m->base != 0U && address >= m->base && address - m->base <= SUCRUNE_HEAP_SIZE &&
           length <= SUCRUNE_HEAP_SIZE - (address - m->base);
}
int sucrune_memory_access(const struct sucrune_guest_memory *m, uintptr_t address, size_t length, int write_access) {
    if (!extent(m, address, length)) return 0;
    if (length == 0U) return 1;
    size_t first = (address - m->base) / m->page;
    size_t last = (address - m->base + length - 1U) / m->page;
    unsigned int need = ALLOCATED | (write_access != 0 ? PROT_WRITE : PROT_READ);
    for (size_t i = first; i <= last; i++) if ((m->pages[i] & need) != need) return 0;
    return 1;
}
static void account(struct sucrune_guest_memory *m, size_t first, size_t count, unsigned char value) {
    for (size_t i = first; i < first + count; i++) {
        if ((m->pages[i] & ALLOCATED) != 0U) m->used -= m->page;
        if ((value & ALLOCATED) != 0U) m->used += m->page;
        m->pages[i] = value;
    }
    if (m->used > m->peak) m->peak = m->used;
}
int64_t sucrune_memory_call(struct sucrune_guest_memory *m, int operation, const uint64_t a[6]) {
    if (m->base == 0U) return -ENOMEM;
    if (operation == 214) { /* brk: Linux returns the old break on failure. */
        uintptr_t desired = (uintptr_t)a[0];
        if (desired < m->base || desired - m->base > SUCRUNE_BRK_SIZE) return (int64_t)m->brk;
        size_t before = (m->brk - m->base + m->page - 1U) / m->page;
        size_t after = (desired - m->base + m->page - 1U) / m->page;
        if (after > before) {
            if (syscall(SYS_mprotect, (void *)(m->base + before * m->page), (after - before) * m->page, PROT_READ | PROT_WRITE) != 0) return (int64_t)m->brk;
            account(m, before, after - before, ALLOCATED | PROT_READ | PROT_WRITE);
        } else if (after < before) {
            void *start = (void *)(m->base + after * m->page);
            size_t size = (before - after) * m->page;
            if (syscall(SYS_madvise, start, size, MADV_DONTNEED) != 0 || syscall(SYS_mprotect, start, size, PROT_NONE) != 0) return (int64_t)m->brk;
            account(m, after, before - after, 0);
        }
        m->brk = desired; return (int64_t)desired;
    }
    size_t length = (size_t)a[1];
    if (length == 0U || length > SUCRUNE_HEAP_SIZE) return -EINVAL;
    size_t count = (length + m->page - 1U) / m->page;
    size_t bytes = count * m->page;
    if (operation == 222) { /* mmap: anonymous/private, no executable memory. */
        if ((a[2] & ~(uint64_t)(PROT_READ | PROT_WRITE)) != 0U) return -EACCES;
        if (a[3] != (MAP_PRIVATE | MAP_ANONYMOUS) || (int64_t)a[4] != -1 || a[5] != 0U) return -EINVAL;
        size_t first = SUCRUNE_BRK_SIZE / m->page, limit = SUCRUNE_HEAP_SIZE / m->page, run = 0;
        for (size_t i = first; i < limit; i++) {
            run = m->pages[i] == 0U ? run + 1U : 0U;
            if (run != count) continue;
            first = i + 1U - run;
            uintptr_t address = m->base + first * m->page;
            if (syscall(SYS_mprotect, (void *)address, bytes, (int)a[2]) != 0) return -errno;
            account(m, first, count, (unsigned char)(ALLOCATED | a[2]));
            return (int64_t)address;
        }
        return -ENOMEM;
    }
    uintptr_t address = (uintptr_t)a[0];
    if (address % m->page != 0U || !extent(m, address, bytes) || address - m->base < SUCRUNE_BRK_SIZE) return -EINVAL;
    size_t first = (address - m->base) / m->page;
    if (operation == 215) { /* munmap is logical: retain reservation against host overlap. */
        if (syscall(SYS_madvise, (void *)address, bytes, MADV_DONTNEED) != 0) return -errno;
        if (syscall(SYS_mprotect, (void *)address, bytes, PROT_NONE) != 0) return -errno;
        account(m, first, count, 0); return 0;
    }
    if (operation == 226) {
        if ((a[2] & ~(uint64_t)(PROT_READ | PROT_WRITE)) != 0U) return -EACCES;
        for (size_t i = first; i < first + count; i++) if ((m->pages[i] & ALLOCATED) == 0U) return -ENOMEM;
        if (syscall(SYS_mprotect, (void *)address, bytes, (int)a[2]) != 0) return -errno;
        account(m, first, count, (unsigned char)(ALLOCATED | a[2])); return 0;
    }
    if (operation == 233) {
        if (a[2] != MADV_DONTNEED) return -EINVAL;
        for (size_t i = first; i < first + count; i++) if ((m->pages[i] & ALLOCATED) == 0U) return -ENOMEM;
        return syscall(SYS_madvise, (void *)address, bytes, MADV_DONTNEED) == 0 ? 0 : -errno;
    }
    return -ENOSYS;
}
