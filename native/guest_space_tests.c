#include "guest_space.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
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
static int fail_replace, fail_protect;
static DWORD windows_protection(int protection) {
    if ((protection & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC)) return PAGE_EXECUTE_READWRITE;
    if ((protection & PROT_EXEC) != 0) return (protection & PROT_READ) != 0 ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
    if ((protection & PROT_WRITE) != 0) return PAGE_READWRITE;
    return (protection & PROT_READ) != 0 ? PAGE_READONLY : PAGE_NOACCESS;
}
size_t sucrune_space_os_page_size(void) { SYSTEM_INFO info; GetSystemInfo(&info); return info.dwPageSize; }
int64_t sucrune_space_os_reserve(uintptr_t address, size_t length) {
    void *memory = VirtualAlloc((void *)address, length, MEM_RESERVE, PAGE_NOACCESS);
    if (memory == NULL && address != 0U) memory = VirtualAlloc(NULL, length, MEM_RESERVE, PAGE_NOACCESS);
    return memory == NULL ? -ENOMEM : (int64_t)(uintptr_t)memory;
}
int sucrune_space_os_replace(uintptr_t address, size_t length, int protection) {
    if (fail_replace != 0) { fail_replace = 0; return -ENOMEM; }
    if (!VirtualFree((void *)address, length, MEM_DECOMMIT)) return -EIO;
    if (protection == PROT_NONE) return 0;
    return VirtualAlloc((void *)address, length, MEM_COMMIT, windows_protection(protection)) == (void *)address ? 0 : -ENOMEM;
}
int sucrune_space_os_protect(uintptr_t address, size_t length, int protection) {
    if (fail_protect != 0) { fail_protect = 0; return -ENOMEM; }
    if (VirtualAlloc((void *)address, length, MEM_COMMIT, windows_protection(protection)) == NULL) return -ENOMEM;
    DWORD previous;
    return VirtualProtect((void *)address, length, windows_protection(protection), &previous) ? 0 : -EACCES;
}
int sucrune_space_os_release(uintptr_t address, size_t length) {
    (void)length;
    return VirtualFree((void *)address, 0U, MEM_RELEASE) ? 0 : -EIO;
}
int sucrune_space_os_discard(uintptr_t address, size_t length, int protection) {
    return sucrune_space_os_replace(address, length, protection);
}
void sucrune_space_os_sync_code(uintptr_t address, size_t length) {
    if (!FlushInstructionCache(GetCurrentProcess(), (void *)address, length)) abort();
}
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000U
#endif
#endif

#define ANON ((unsigned int)(MAP_PRIVATE | MAP_ANONYMOUS))
#define CHECK(expression) do { if (!(expression)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expression); exit(1); } } while (0)
static struct sucrune_guest_space space, other;
static size_t page;
static unsigned int cases;
static void start(size_t pages) { CHECK(sucrune_space_init(&space, pages * page, page) == 0); }
static void finish(void) { CHECK(sucrune_space_destroy(&space) == 0); CHECK(space.base == 0U && space.count == 0U); cases++; }
static uintptr_t map_at(size_t offset, size_t pages, int protection) {
    uintptr_t address = space.base + offset * page;
    CHECK(sucrune_space_map(&space, address, pages * page, 0U, protection, ANON | MAP_FIXED) == (int64_t)address);
    return address;
}
static void validate(void) {
    size_t mapped = 0U, accessible = 0U;
    uintptr_t before = space.base;
    CHECK(space.count <= SUCRUNE_SPACE_MAX_VMAS);
    for (size_t i = 0U; i < space.count; i++) {
        const struct sucrune_space_vma *area = &space.areas[i];
        CHECK(area->start >= before && area->length != 0U);
        CHECK(area->start % page == 0U && area->length % page == 0U);
        CHECK(sucrune_space_contains(&space, area->start, area->length));
        CHECK((area->protection & (PROT_WRITE | PROT_EXEC)) != (PROT_WRITE | PROT_EXEC) ||
              (space.allow_rwx != 0U && area->file_snapshot == 0U));
        if (i != 0U && area->start == before) CHECK(area->protection != space.areas[i - 1U].protection ||
            area->file_snapshot != space.areas[i - 1U].file_snapshot || area->shared_max_protection != space.areas[i - 1U].shared_max_protection);
        before = area->start + area->length;
        mapped += area->length;
        if (area->protection != PROT_NONE) accessible += area->length;
    }
    CHECK(space.mapped_bytes == mapped && space.accessible_bytes == accessible);
    CHECK(space.peak_accessible_bytes >= accessible);
}
static void invalid_arguments(void) {
    CHECK(sucrune_space_init(NULL, page, page) == -EINVAL);
    CHECK(sucrune_space_init(&space, 0U, page) == -EINVAL);
    CHECK(sucrune_space_init(&space, page + 1U, page) == -EINVAL);
    CHECK(sucrune_space_init(&space, page, 8192U) == -EINVAL);
    CHECK(sucrune_space_init_exact(&space, UINTPTR_MAX - page + 1U, page, page) == -EINVAL);
    start(8U);
    uintptr_t base = space.base;
    CHECK(sucrune_space_map(&space, base, 0U, 0U, PROT_READ, ANON) == -EINVAL);
    CHECK(sucrune_space_map(&space, base, SIZE_MAX, 0U, PROT_READ, ANON) == -EINVAL);
    CHECK(sucrune_space_map(&space, base, page, 3U, PROT_READ, ANON) == -EINVAL);
    CHECK(sucrune_space_map(&space, base, page, 0U, PROT_WRITE | PROT_EXEC, ANON) == -EACCES);
    CHECK(sucrune_space_map(&space, base, page, 0U, 8, ANON) == -EACCES);
    CHECK(sucrune_space_map(&space, base, page, 0U, PROT_READ, MAP_PRIVATE) == -EINVAL);
    CHECK(sucrune_space_map(&space, base - page, page, 0U, PROT_READ, ANON | MAP_FIXED) == -EINVAL);
    CHECK(sucrune_space_map(&space, base + 1U, page, 0U, PROT_READ, ANON | MAP_FIXED) == -EINVAL);
    CHECK(space.count == 0U && !sucrune_space_access(&space, base, 1U, 0));
    finish();
}
static void large_sparse_alignment(void) {
    const size_t gib = (size_t)1024U * 1024U * 1024U;
    CHECK(sucrune_space_init(&space, 64U * gib, page) == 0);
    CHECK(space.count == 0U && space.mapped_bytes == 0U && space.accessible_bytes == 0U);
    uintptr_t large;
    CHECK(sucrune_space_find_gap(&space, 0U, page, 4U * gib, &large) == 0);
    CHECK(large % (4U * gib) == 0U && sucrune_space_contains(&space, large, page));
    CHECK(sucrune_space_map(&space, large, page, 4U * gib, PROT_READ | PROT_WRITE, ANON) == (int64_t)large);
    *(volatile uint64_t *)large = UINT64_C(0x123456789abcdef0);
    uintptr_t smaller;
    CHECK(sucrune_space_find_gap(&space, 0U, page, 65536U, &smaller) == 0);
    CHECK(smaller % 65536U == 0U);
    CHECK(space.mapped_bytes == page && space.accessible_bytes == page);
    validate(); finish();
}
static void collision_preserves_host(void) {
    start(32U);
    uintptr_t address = map_at(0U, 1U, PROT_READ | PROT_WRITE);
    *(volatile uint32_t *)address = 0x76abcdefU;
    int result = sucrune_space_init_exact(&other, space.base, space.size, page);
    CHECK(result == -EADDRINUSE || result == -ENOMEM);
    CHECK(*(volatile uint32_t *)address == 0x76abcdefU && other.base == 0U);
    finish();
}
static void protection_across_adjacent(void) {
    start(16U);
    uintptr_t address = map_at(0U, 3U, PROT_READ | PROT_WRITE);
    memset((void *)address, 0x5a, 3U * page);
    CHECK(sucrune_space_protect(&space, address + page, page, PROT_READ) == 0);
    CHECK(space.count == 3U && sucrune_space_access(&space, address, 3U * page, 0));
    CHECK(!sucrune_space_access(&space, address, 3U * page, 1));
    CHECK(sucrune_space_protect(&space, address, 3U * page, PROT_READ) == 0);
    CHECK(space.count == 1U && *(volatile unsigned char *)(address + page) == 0x5aU);
    CHECK(sucrune_space_protect(&space, address, page, PROT_WRITE | PROT_EXEC) == -EACCES);
    validate(); finish();
}
static void fixed_replacement_and_holes(void) {
    start(16U);
    uintptr_t address = map_at(0U, 3U, PROT_READ | PROT_WRITE);
    memset((void *)address, 0x66, 3U * page);
    map_at(1U, 1U, PROT_READ | PROT_WRITE);
    CHECK(*(volatile unsigned char *)address == 0x66U && *(volatile unsigned char *)(address + page) == 0U);
    CHECK(*(volatile unsigned char *)(address + 2U * page) == 0x66U);
    CHECK(space.count == 1U);
    CHECK(sucrune_space_unmap(&space, address + page, page) == 0);
    CHECK(space.count == 2U && !sucrune_space_access(&space, address + page, 1U, 0));
    CHECK(sucrune_space_protect(&space, address, 3U * page, PROT_READ) == -ENOMEM);
    CHECK(sucrune_space_access(&space, address, page, 1));
    CHECK(sucrune_space_unmap(&space, address + page, page) == 0);
    CHECK(sucrune_space_map(&space, address, page, 0U, PROT_READ, ANON | MAP_FIXED_NOREPLACE) == -EEXIST);
    CHECK(*(volatile unsigned char *)address == 0x66U);
    CHECK(sucrune_space_map(&space, address + page, page, 0U, PROT_READ, ANON | MAP_FIXED_NOREPLACE) == (int64_t)(address + page));
    CHECK(*(volatile unsigned char *)(address + page) == 0U);
    validate(); finish();
}
static void hints_none_and_rounding(void) {
    start(32U);
    uintptr_t address = map_at(0U, 2U, PROT_NONE);
    uintptr_t next;
    CHECK(sucrune_space_find_gap(&space, address, page, 0U, &next) == 0 && next == address + 2U * page);
    CHECK(sucrune_space_map(&space, address, page + 1U, 0U, PROT_READ | PROT_WRITE, ANON) == (int64_t)next);
    CHECK(space.mapped_bytes == 4U * page && space.accessible_bytes == 2U * page);
    CHECK(!sucrune_space_access(&space, address, page, 0));
    CHECK(sucrune_space_find_gap(&space, space.base + space.size, page, 0U, &next) == 0);
    CHECK(next == address + 4U * page);
    CHECK(sucrune_space_find_gap(&space, 0U, space.size + 1U, 0U, &next) == -ENOMEM);
    validate(); finish();
}
static void registration_preserves_bytes(void) {
    start(16U);
    uintptr_t address = map_at(0U, 2U, PROT_READ | PROT_WRITE);
    memset((void *)address, 0x35, 2U * page);
    CHECK(sucrune_space_register(&space, address, page, PROT_READ) == 0);
    CHECK(*(volatile unsigned char *)address == 0x35U);
    CHECK(sucrune_space_register(&space, address + 4U * page, page, PROT_READ | PROT_WRITE) == 0);
    CHECK(*(volatile unsigned char *)(address + 4U * page) == 0U);
    CHECK(sucrune_space_register(&space, address + page, 4U * page, PROT_READ) == -ENOMEM);
    CHECK(sucrune_space_access(&space, address + page, page, 1));
    validate(); finish();
}
static void file_snapshot_discard(void) {
    start(16U);
    uintptr_t address = map_at(0U, 3U, PROT_READ | PROT_WRITE);
    memset((void *)address, 0x73, 3U * page);
    CHECK(sucrune_space_mark_file(&space, address + page, page) == 0);
    CHECK(space.count == 3U && space.areas[1].file_snapshot == 1U);
    CHECK(sucrune_space_protect(&space, address, 3U * page, PROT_READ) == 0);
    CHECK(space.count == 3U && space.areas[1].file_snapshot == 1U);
    CHECK(sucrune_space_register(&space, address + page, page, PROT_READ) == 0);
    CHECK(space.areas[1].file_snapshot == 1U);
    CHECK(sucrune_space_discard(&space, address, 3U * page) == -ENOTSUP);
    CHECK(*(volatile unsigned char *)address == 0x73U && *(volatile unsigned char *)(address + page) == 0x73U);
    CHECK(sucrune_space_discard(&space, address, page) == 0);
    CHECK(*(volatile unsigned char *)address == 0U && *(volatile unsigned char *)(address + page) == 0x73U);
    CHECK(sucrune_space_mark_file(&space, address + 4U * page, page) == -ENOMEM);
    validate(); finish();
}
static void anonymous_discard_and_remap(void) {
    start(16U);
    uintptr_t address = map_at(0U, 3U, PROT_READ | PROT_WRITE);
    memset((void *)address, 0x49, 3U * page);
    CHECK(sucrune_space_protect(&space, address + page, page, PROT_READ) == 0);
    CHECK(sucrune_space_discard(&space, address, 3U * page) == 0);
    CHECK(*(volatile unsigned char *)address == 0U && *(volatile unsigned char *)(address + page) == 0U);
    CHECK(!sucrune_space_access(&space, address + page, page, 1));
    CHECK(sucrune_space_unmap(&space, address, 3U * page) == 0 && space.count == 0U);
    map_at(0U, 3U, PROT_READ | PROT_WRITE);
    CHECK(*(volatile unsigned char *)(address + 2U * page) == 0U);
    validate(); finish();
}
static void executable_transition(void) {
    start(16U);
    uintptr_t address = map_at(0U, 1U, PROT_READ | PROT_WRITE);
#if defined(_WIN32) && defined(_M_X64)
    const unsigned char code[] = {0xb8, 42, 0, 0, 0, 0xc3};
#elif defined(__aarch64__)
    const unsigned char code[] = {0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6};
#else
    const unsigned char code[] = {0};
#endif
    memcpy((void *)address, code, sizeof(code));
    CHECK(sucrune_space_protect(&space, address, page, PROT_READ | PROT_EXEC) == 0);
#if defined(_WIN32) && defined(_M_X64)
    int (*entry)(void);
    memcpy(&entry, &address, sizeof(entry));
    CHECK(entry() == 42);
#elif defined(__aarch64__)
    int (*entry)(void);
    memcpy(&entry, &address, sizeof(entry));
    CHECK(entry() == 42);
#endif
    CHECK(!sucrune_space_access(&space, address, page, 1));
    CHECK(sucrune_space_protect(&space, address, page, PROT_READ | PROT_WRITE) == 0);
    CHECK(sucrune_space_access(&space, address, page, 1));
    validate(); finish();
}
static void rwx_policy_defaults_and_lifecycle(void) {
    CHECK(sucrune_space_set_rwx_policy(NULL, 1) == -EINVAL);
    CHECK(sucrune_space_set_rwx_policy(&space, 1) == -EINVAL);
    start(8U);
    CHECK(space.allow_rwx == 0U);
    CHECK(sucrune_space_set_rwx_policy(&space, -1) == -EINVAL);
    CHECK(sucrune_space_set_rwx_policy(&space, 2) == -EINVAL);
    CHECK(sucrune_space_set_rwx_policy(&space, 0) == 0);
    const int rwx = PROT_READ | PROT_WRITE | PROT_EXEC;
    CHECK(sucrune_space_register(&space, space.base, page, rwx) == -EACCES);
    CHECK(sucrune_space_map(&space, space.base, page, 0U, rwx, ANON | MAP_FIXED) == -EACCES);
    uintptr_t address = map_at(0U, 1U, PROT_READ | PROT_WRITE);
    *(volatile unsigned char *)address = 0x64U;
    CHECK(sucrune_space_set_rwx_policy(&space, 1) == -EBUSY);
    CHECK(space.allow_rwx == 0U && *(volatile unsigned char *)address == 0x64U);
    CHECK(sucrune_space_protect(&space, address, page, rwx) == -EACCES);
    validate(); finish();
    CHECK(space.allow_rwx == 0U);
}
static void rwx_anonymous_code_transition(void) {
    start(8U);
    CHECK(sucrune_space_set_rwx_policy(&space, 1) == 0);
    const int rwx = PROT_READ | PROT_WRITE | PROT_EXEC;
    uintptr_t address = map_at(0U, 1U, rwx);
    CHECK(sucrune_space_set_rwx_policy(&space, 0) == -EBUSY && space.allow_rwx == 1U);
#if defined(_M_X64) || defined(__x86_64__)
    const unsigned char code[] = {0xb8, 42, 0, 0, 0, 0xc3};
#elif defined(__aarch64__)
    const unsigned char code[] = {0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6};
#else
    const unsigned char code[] = {0};
#endif
    memcpy((void *)address, code, sizeof(code));
    CHECK(sucrune_space_protect(&space, address, page, PROT_READ | PROT_EXEC) == 0);
    CHECK(!sucrune_space_access(&space, address, page, 1));
#if defined(_M_X64) || defined(__x86_64__) || defined(__aarch64__)
    int (*entry)(void);
    memcpy(&entry, &address, sizeof(entry));
    CHECK(entry() == 42);
#endif
    CHECK(sucrune_space_protect(&space, address, page, rwx) == 0);
    CHECK(sucrune_space_access(&space, address, page, 1));
    CHECK(sucrune_space_register(&space, address + 2U * page, page, rwx) == 0);
    *(volatile unsigned char *)(address + 2U * page) = 0x85U;
    CHECK(sucrune_space_map(&space, address + 4U * page, page, 0U, rwx | 8, ANON | MAP_FIXED) == -EACCES);
    validate(); finish();
}
static void rwx_file_rejection_is_atomic(void) {
    start(8U);
    CHECK(sucrune_space_set_rwx_policy(&space, 1) == 0);
    const int rwx = PROT_READ | PROT_WRITE | PROT_EXEC;
    uintptr_t address = map_at(0U, 3U, PROT_READ | PROT_WRITE);
    memset((void *)address, 0x73, 3U * page);
    CHECK(sucrune_space_mark_file(&space, address + page, page) == 0);
    CHECK(sucrune_space_protect(&space, address, 3U * page, rwx) == -EACCES);
    CHECK(sucrune_space_register(&space, address + page, page, rwx) == -EACCES);
    CHECK(space.count == 3U && space.areas[1].file_snapshot == 1U);
    for (size_t i = 0U; i < 3U; i++) {
        CHECK(space.areas[i].protection == (PROT_READ | PROT_WRITE));
        CHECK(*(volatile unsigned char *)(address + i * page) == 0x73U);
    }
    CHECK(sucrune_space_protect(&space, address + page, page, PROT_READ | PROT_EXEC) == 0);
    CHECK(space.areas[1].file_snapshot == 1U);
    CHECK(sucrune_space_discard(&space, address, 3U * page) == -ENOTSUP);
    CHECK(sucrune_space_protect(&space, address + 2U * page, page, rwx) == 0);
    /* Failed late marking must not mark the anonymous prefix either. */
    CHECK(sucrune_space_mark_file(&space, address, 3U * page) == -EACCES);
    CHECK(space.areas[0].file_snapshot == 0U && space.areas[2].file_snapshot == 0U);
    validate(); finish();
}
static void rwx_fixed_replacement_is_anonymous(void) {
    start(8U);
    CHECK(sucrune_space_set_rwx_policy(&space, 1) == 0);
    const int rwx = PROT_READ | PROT_WRITE | PROT_EXEC;
    uintptr_t address = map_at(0U, 3U, PROT_READ | PROT_WRITE);
    memset((void *)address, 0x51, 3U * page);
    CHECK(sucrune_space_mark_file(&space, address, 3U * page) == 0);
    CHECK(sucrune_space_map(&space, address + page, page, 0U, rwx, ANON | MAP_FIXED_NOREPLACE) == -EEXIST);
    CHECK(*(volatile unsigned char *)(address + page) == 0x51U && space.count == 1U);
    CHECK(sucrune_space_map(&space, address + page, page, 0U, rwx, ANON | MAP_FIXED) == (int64_t)(address + page));
    CHECK(space.count == 3U && space.areas[1].file_snapshot == 0U);
    CHECK(space.areas[0].file_snapshot == 1U && space.areas[2].file_snapshot == 1U);
    CHECK(*(volatile unsigned char *)(address + page) == 0U);
    CHECK(*(volatile unsigned char *)address == 0x51U && *(volatile unsigned char *)(address + 2U * page) == 0x51U);
    CHECK(sucrune_space_discard(&space, address + page, page) == 0);
    CHECK(sucrune_space_protect(&space, address, 3U * page, rwx) == -EACCES);
    validate(); finish();
}
static void rwx_cannot_adopt_host_or_other_space(void) {
    start(8U);
    CHECK(sucrune_space_set_rwx_policy(&space, 1) == 0);
    CHECK(sucrune_space_init(&other, 8U * page, page) == 0);
    CHECK(other.allow_rwx == 0U);
    const int rwx = PROT_READ | PROT_WRITE | PROT_EXEC;
    uintptr_t outside = other.base;
    CHECK(sucrune_space_map(&other, outside, page, 0U, PROT_READ | PROT_WRITE, ANON | MAP_FIXED) == (int64_t)outside);
    *(volatile uint64_t *)outside = UINT64_C(0x9182736455aabbcc);
    CHECK(sucrune_space_map(&space, outside, page, 0U, rwx, ANON | MAP_FIXED) == -EINVAL);
    CHECK(sucrune_space_map(&space, outside, page, 0U, rwx, ANON | MAP_FIXED_NOREPLACE) == -EINVAL);
    CHECK(sucrune_space_protect(&space, outside, page, rwx) == -EINVAL);
    CHECK(sucrune_space_register(&space, outside, page, rwx) == -EINVAL);
    CHECK(sucrune_space_protect(&other, outside, page, rwx) == -EACCES);
    CHECK(*(volatile uint64_t *)outside == UINT64_C(0x9182736455aabbcc));
    int64_t result = sucrune_space_map(&space, outside, page, 0U, rwx, ANON);
    CHECK(result > 0 && sucrune_space_contains(&space, (uintptr_t)result, page));
    CHECK((uintptr_t)result != outside && *(volatile uint64_t *)outside == UINT64_C(0x9182736455aabbcc));
    CHECK(sucrune_space_destroy(&other) == 0);
    validate(); finish();
}
static void vma_capacity_before_mutation(void) {
    start(4096U);
    for (size_t i = 0U; i < SUCRUNE_SPACE_MAX_VMAS - 1U; i++) map_at(i * 2U, 1U, PROT_READ | PROT_WRITE);
    uintptr_t last = map_at((SUCRUNE_SPACE_MAX_VMAS - 1U) * 2U, 3U, PROT_READ | PROT_WRITE);
    *(volatile unsigned char *)(last + page) = 0x68U;
    CHECK(space.count == SUCRUNE_SPACE_MAX_VMAS);
    CHECK(sucrune_space_protect(&space, last + page, page, PROT_READ) == -ENOMEM);
    CHECK(sucrune_space_access(&space, last + page, page, 1) && *(volatile unsigned char *)(last + page) == 0x68U);
    CHECK(sucrune_space_map(&space, space.base + 3000U * page, page, 0U, PROT_READ, ANON | MAP_FIXED) == -ENOMEM);
    CHECK(sucrune_space_unmap(&space, last, 3U * page) == 0);
    map_at(3000U, 1U, PROT_READ);
    CHECK(space.count == SUCRUNE_SPACE_MAX_VMAS);
    validate(); finish();
}
#if defined(_WIN32)
static void backend_failure_transaction(void) {
    start(16U);
    uintptr_t address = map_at(0U, 1U, PROT_READ | PROT_WRITE);
    *(volatile unsigned char *)address = 0x51U;
    fail_replace = 1;
    CHECK(sucrune_space_map(&space, address, page, 0U, PROT_READ, ANON | MAP_FIXED) == -ENOMEM);
    CHECK(space.count == 1U && *(volatile unsigned char *)address == 0x51U);
    fail_protect = 1;
    CHECK(sucrune_space_protect(&space, address, page, PROT_READ) == -ENOMEM);
    CHECK(sucrune_space_access(&space, address, page, 1));
    fail_replace = 1;
    CHECK(sucrune_space_unmap(&space, address, page) == -ENOMEM);
    CHECK(sucrune_space_access(&space, address, page, 1));
    validate(); finish();
}
#endif
static void randomized_reference_model(void) {
    start(64U);
    int protection[64] = {0};
    unsigned char occupied[64] = {0}, snapshot[64] = {0};
    uint32_t random = 0x72656c66U;
    for (unsigned int iteration = 0U; iteration < 1024U; iteration++) {
        random = random * 1664525U + 1013904223U;
        size_t first = (random >> 8U) % 64U;
        size_t count = 1U + ((random >> 16U) % (64U - first));
        int operation = (int)(random % 4U);
        int prot = (random & 0x80U) != 0U ? PROT_READ : PROT_READ | PROT_WRITE;
        uintptr_t address = space.base + first * page;
        int all = 1;
        for (size_t i = first; i < first + count; i++) if (occupied[i] == 0U) all = 0;
        if (operation == 0) {
            CHECK(sucrune_space_map(&space, address, count * page, 0U, prot, ANON | MAP_FIXED) == (int64_t)address);
            for (size_t i = first; i < first + count; i++) { occupied[i] = 1U; protection[i] = prot; snapshot[i] = 0U; }
        } else if (operation == 1) {
            CHECK(sucrune_space_protect(&space, address, count * page, prot) == (all != 0 ? 0 : -ENOMEM));
            if (all != 0) for (size_t i = first; i < first + count; i++) protection[i] = prot;
        } else if (operation == 2) {
            CHECK(sucrune_space_unmap(&space, address, count * page) == 0);
            for (size_t i = first; i < first + count; i++) { occupied[i] = 0U; snapshot[i] = 0U; }
        } else {
            CHECK(sucrune_space_mark_file(&space, address, count * page) == (all != 0 ? 0 : -ENOMEM));
            if (all != 0) for (size_t i = first; i < first + count; i++) snapshot[i] = 1U;
        }
        validate();
        for (size_t i = 0U; i < 64U; i++) {
            uintptr_t current = space.base + i * page;
            CHECK(sucrune_space_access(&space, current, page, 0) == (occupied[i] != 0U));
            CHECK(sucrune_space_access(&space, current, page, 1) == (occupied[i] != 0U && (protection[i] & PROT_WRITE) != 0));
            for (size_t j = 0U; j < space.count; j++) if (current >= space.areas[j].start && current - space.areas[j].start < space.areas[j].length) CHECK(space.areas[j].file_snapshot == snapshot[i]);
        }
    }
    finish();
}
static void sync_arguments_and_empty_ranges(void) {
    start(8U);
    uintptr_t address = map_at(0U, 1U, PROT_READ | PROT_WRITE);
    CHECK(sucrune_space_sync(NULL, 0U, 0U, 0U) == -EINVAL);
    CHECK(sucrune_space_sync(&space, address, page, 8U) == -EINVAL);
    CHECK(sucrune_space_sync(&space, address, page, UINT32_MAX) == -EINVAL);
    CHECK(sucrune_space_sync(&space, address, page, 5U) == -EINVAL);
    CHECK(sucrune_space_sync(&space, address, page, 7U) == -EINVAL);
    CHECK(sucrune_space_sync(&space, address + 1U, page, 1U) == -EINVAL);
    CHECK(sucrune_space_sync(&space, address + 1U, 0U, 0U) == -EINVAL);
    CHECK(sucrune_space_sync(&space, 0U, 0U, 8U) == -EINVAL);
    CHECK(sucrune_space_sync(&space, 0U, 0U, 5U) == -EINVAL);
    const unsigned int valid_flags[] = {0U, 1U, 2U, 3U, 4U, 6U};
    for (size_t i = 0U; i < sizeof(valid_flags) / sizeof(valid_flags[0]); i++) {
        CHECK(sucrune_space_sync(&space, address, 0U, valid_flags[i]) == 0);
        CHECK(sucrune_space_sync(&space, 0U, 0U, valid_flags[i]) == 0);
        CHECK(sucrune_space_sync(&space, space.base + space.size, 0U, valid_flags[i]) == 0);
        CHECK(sucrune_space_sync(&space, address + 2U * page, 0U, valid_flags[i]) == 0);
        CHECK(sucrune_space_sync(&space, address, 1U, valid_flags[i]) == 0);
    }
    uintptr_t highest_page = UINTPTR_MAX & ~(uintptr_t)(page - 1U);
    CHECK(sucrune_space_sync(&space, highest_page, 0U, 1U) == 0);
    CHECK(sucrune_space_sync(&space, highest_page, 1U, 1U) == -ENOMEM);
    CHECK(sucrune_space_sync(&space, address, SIZE_MAX - page, 1U) == -ENOMEM);
    CHECK(sucrune_space_sync(&space, address, SIZE_MAX, 1U) == -ENOMEM);
    CHECK(sucrune_space_sync(&space, 0U, SIZE_MAX, 4U) == -ENOMEM);
    validate(); finish();
}
static void sync_adjacent_private_and_none(void) {
    static struct sucrune_guest_space before;
    start(8U);
    uintptr_t address = map_at(0U, 4U, PROT_READ | PROT_WRITE);
    memset((void *)address, 0x63, 4U * page);
    CHECK(sucrune_space_mark_file(&space, address + page, page) == 0);
    CHECK(sucrune_space_protect(&space, address + 2U * page, page, PROT_READ) == 0);
    CHECK(sucrune_space_protect(&space, address + 3U * page, page, PROT_NONE) == 0);
    CHECK(space.count == 4U);
    memcpy(&before, &space, sizeof(space));
    const unsigned int valid_flags[] = {0U, 1U, 2U, 3U, 4U, 6U};
    for (size_t i = 0U; i < sizeof(valid_flags) / sizeof(valid_flags[0]); i++) {
        CHECK(sucrune_space_sync(&space, address, 3U * page + 1U, valid_flags[i]) == 0);
        CHECK(sucrune_space_sync(&space, address + page, page, valid_flags[i]) == 0);
        CHECK(sucrune_space_sync(&space, address + 3U * page, page, valid_flags[i]) == 0);
        CHECK(memcmp(&before, &space, sizeof(space)) == 0);
    }
    CHECK(sucrune_space_protect(&space, address + 3U * page, page, PROT_READ) == 0);
    for (size_t i = 0U; i < 4U * page; i++) CHECK(*(volatile unsigned char *)(address + i) == 0x63U);
    validate(); finish();
}
static void sync_holes_and_foreign_addresses(void) {
    static struct sucrune_guest_space before;
    start(8U);
    uintptr_t address = map_at(0U, 3U, PROT_READ | PROT_WRITE);
    memset((void *)address, 0x38, 3U * page);
    CHECK(sucrune_space_unmap(&space, address + page, page) == 0);
    CHECK(sucrune_space_init(&other, 8U * page, page) == 0);
    CHECK(sucrune_space_map(&other, other.base, page, 0U, PROT_READ | PROT_WRITE,
                            ANON | MAP_FIXED) == (int64_t)other.base);
    *(volatile uint64_t *)other.base = UINT64_C(0x4567abcdef123890);
    memcpy(&before, &space, sizeof(space));
    CHECK(sucrune_space_sync(&space, address, page, 1U) == 0);
    CHECK(sucrune_space_sync(&space, address, page + 1U, 1U) == -ENOMEM);
    CHECK(sucrune_space_sync(&space, address, 3U * page, 4U) == -ENOMEM);
    CHECK(sucrune_space_sync(&space, address + page, 1U, 1U) == -ENOMEM);
    CHECK(sucrune_space_sync(&space, address + 7U * page, page, 1U) == -ENOMEM);
    CHECK(sucrune_space_sync(&space, 0U, page, 1U) == -ENOMEM);
    CHECK(sucrune_space_sync(&space, space.base - page, page, 1U) == -ENOMEM);
    CHECK(sucrune_space_sync(&space, space.base + space.size, page, 1U) == -ENOMEM);
    CHECK(sucrune_space_sync(&space, address, space.size + page, 1U) == -ENOMEM);
    CHECK(sucrune_space_sync(&space, other.base, page, 1U) == -ENOMEM);
    CHECK(sucrune_space_sync(&other, other.base, page, 1U) == 0);
    CHECK(memcmp(&before, &space, sizeof(space)) == 0);
    CHECK(*(volatile unsigned char *)address == 0x38U);
    CHECK(*(volatile unsigned char *)(address + 2U * page) == 0x38U);
    CHECK(*(volatile uint64_t *)other.base == UINT64_C(0x4567abcdef123890));
    CHECK(sucrune_space_destroy(&other) == 0);
    validate(); finish();
}
#if !defined(_WIN32)
static void shared_file_visibility(void) {
    const char *temporary_directory = getenv("TMPDIR");
    if (temporary_directory == NULL || !*temporary_directory) temporary_directory = "/tmp";
    char path[2048];
    int length = snprintf(path, sizeof(path), "%s/sucrune-shared-XXXXXX", temporary_directory);
    CHECK(length > 0 && (size_t)length < sizeof(path));
    int writer = mkstemp(path);
    CHECK(writer >= 0 && ftruncate(writer, (off_t)(2U * page)) == 0);
    int reader = open(path, O_RDONLY | O_CLOEXEC);
    CHECK(reader >= 0 && unlink(path) == 0);
    start(4U);
    uintptr_t prefix = map_at(0, 1, PROT_READ);
    int64_t result = sucrune_space_map_shared_file(&space, 0, page, PROT_READ, reader, page);
    CHECK(result == (int64_t)(prefix + page));
    CHECK(close(reader) == 0 && pwrite(writer, "S", 1, (off_t)page) == 1);
    CHECK(*(volatile unsigned char *)(uintptr_t)result == 'S');
    CHECK(sucrune_space_protect(&space, prefix, page * 2, PROT_WRITE) == -EACCES);
    CHECK(!sucrune_space_access(&space, prefix, 1, 1));
    CHECK(sucrune_space_protect(&space, (uintptr_t)result, page, PROT_EXEC) == -EACCES);
    CHECK(sucrune_space_discard(&space, (uintptr_t)result, page) == 0);
    CHECK(sucrune_space_sync(&space, (uintptr_t)result, page, MS_SYNC) == 0);
    CHECK(*(volatile unsigned char *)(uintptr_t)result == 'S');
    CHECK(sucrune_space_unmap(&space, (uintptr_t)result, page) == 0);
    CHECK(map_at(1, 1, PROT_READ | PROT_WRITE) == (uintptr_t)result);
    CHECK(*(volatile unsigned char *)(uintptr_t)result == 0);
    CHECK(sucrune_space_map_shared_file(&space, 0, page, PROT_EXEC, writer, 0) == -EACCES);
    int64_t writable = sucrune_space_map_shared_file(&space, 0, page, PROT_READ, writer, 0);
    CHECK(writable == (int64_t)(prefix + 2U * page));
    int verifier = dup(writer);
    CHECK(verifier >= 0 && close(writer) == 0);
    CHECK(sucrune_space_protect(&space, (uintptr_t)writable, page, PROT_READ | PROT_WRITE) == 0);
    CHECK(sucrune_space_protect(&space, (uintptr_t)writable, page, PROT_READ | PROT_EXEC) == -EACCES);
    *(volatile unsigned char *)(uintptr_t)writable = 'W';
    CHECK(sucrune_space_sync(&space, (uintptr_t)writable, page, MS_SYNC) == 0);
    unsigned char value = 0;
    CHECK(pread(verifier, &value, 1, 0) == 1 && value == 'W');
    CHECK(sucrune_space_unmap(&space, (uintptr_t)writable, page) == 0);
    CHECK(pread(verifier, &value, 1, 0) == 1 && value == 'W' && close(verifier) == 0);
    validate(); finish();
}
#endif
#if !defined(_WIN32)
static void extend_exact_around_live_image(void) {
    const size_t bytes = 7U * page;
    unsigned char *block = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(block != MAP_FAILED);
    block[5U * page] = 107;
    CHECK(munmap(block + page, 4U * page) == 0);
    uintptr_t start = (uintptr_t)(block + page);
    uintptr_t middle = (uintptr_t)(block + 3U * page);
    CHECK(sucrune_space_init_exact(&space, middle, page, page) == 0);
    CHECK(map_at(0, 1, PROT_READ | PROT_WRITE) == middle);
    block[3U * page] = 42;
    CHECK(sucrune_space_extend_exact(&space, start, 5U * page, 4U * page) == -ENOMEM);
    CHECK(sucrune_space_extend_exact(&space, start, 5U * page, bytes) == -EADDRINUSE);
    CHECK(space.base == middle && space.size == page && space.count == 1U);
    CHECK(block[5U * page] == 107 && block[3U * page] == 42);
    /* A refused suffix must release the temporary prefix. */
    CHECK(sucrune_space_init_exact(&other, start, 2U * page, page) == 0);
    CHECK(sucrune_space_destroy(&other) == 0);
    CHECK(munmap(block + 5U * page, page) == 0);
    CHECK(sucrune_space_extend_exact(&space, start, 5U * page, bytes) == 0);
    CHECK(space.base == start && space.size == 5U * page && block[3U * page] == 42);
    CHECK(map_at(0, 1, PROT_READ | PROT_WRITE) == start);
    CHECK(map_at(4, 1, PROT_READ | PROT_WRITE) == (uintptr_t)(block + 5U * page));
    finish();
    CHECK(munmap(block, page) == 0);
    CHECK(munmap(block + 6U * page, page) == 0);
}
#endif

int main(void) {
#if defined(_WIN32)
    page = sucrune_space_os_page_size();
#else
    page = (size_t)sysconf(_SC_PAGESIZE);
    shared_file_visibility();
    extend_exact_around_live_image();
#endif
    invalid_arguments(); large_sparse_alignment(); collision_preserves_host();
    protection_across_adjacent(); fixed_replacement_and_holes(); hints_none_and_rounding();
    registration_preserves_bytes(); file_snapshot_discard(); anonymous_discard_and_remap();
    executable_transition(); vma_capacity_before_mutation();
    rwx_policy_defaults_and_lifecycle(); rwx_anonymous_code_transition(); rwx_file_rejection_is_atomic();
    rwx_fixed_replacement_is_anonymous(); rwx_cannot_adopt_host_or_other_space();
#if defined(_WIN32)
    backend_failure_transaction();
#endif
    randomized_reference_model();
    sync_arguments_and_empty_ranges(); sync_adjacent_private_and_none(); sync_holes_and_foreign_addresses();
    printf("Guest space checks: %u/%u passed; sparse 64 GiB, aligned gaps, VMA transitions, snapshot preservation, explicit anonymous JIT policy and private msync.\n", cases, cases);
    return 0;
}
