#ifndef SUCRUNE_GUEST_MEMORY_H
#define SUCRUNE_GUEST_MEMORY_H
#include <stddef.h>
#include <stdint.h>
#define SUCRUNE_HEAP_SIZE (64U * 1024U * 1024U)
#define SUCRUNE_BRK_SIZE (8U * 1024U * 1024U)
/* Preallocated metadata: signal dispatch never calls malloc or takes a lock.
 * This arena is data-only and cannot overlap the host or guest executable. */
struct sucrune_guest_memory {
    uintptr_t base, brk;
    size_t page, used, peak;
    unsigned char pages[SUCRUNE_HEAP_SIZE / 4096U];
};
int sucrune_memory_init(struct sucrune_guest_memory *memory, size_t page);
void sucrune_memory_destroy(struct sucrune_guest_memory *memory);
int sucrune_memory_access(const struct sucrune_guest_memory *memory,
                          uintptr_t address, size_t length, int write_access);
int64_t sucrune_memory_call(struct sucrune_guest_memory *memory, int operation,
                           const uint64_t arguments[6]);
#endif
