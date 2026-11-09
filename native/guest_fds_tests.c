/* Pure ownership/alias tests. No host files, Linux ELF or syscall trap executes. */
#include "guest_fds.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(value) do { if (!(value)) { \
    (void)fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #value); exit(1); \
} } while (0)
struct released { unsigned int count; enum sucrune_fd_kind kind[128]; int handles[128], fail_handle; };
static int release(void *context, enum sucrune_fd_kind kind, int handle) {
    struct released *events = context;
    CHECK(events->count < 128U);
    events->kind[events->count] = kind;
    events->handles[events->count++] = handle;
    return handle == events->fail_handle ? -EIO : 0;
}
static void initialize(struct sucrune_fd_table *table, struct released *events) {
    memset(events, 0, sizeof(*events)); events->fail_handle = -999;
    sucrune_fds_init(table, 100, 101, 102, 0, 1, release, events);
}
static void empty_stdin_is_open(void) {
    struct sucrune_fd_table table;
    sucrune_fds_init(&table, -1, 101, 102, 0, 1, NULL, NULL);
    CHECK(table.count == 3U && table.resource_count == 3U && table.peak == 3U);
    CHECK(sucrune_fds_get(&table, 0U)->kind == SUCRUNE_FD_INPUT);
    CHECK(sucrune_fds_get(&table, 0U)->handle == -1);
    CHECK(sucrune_fds_get(&table, UINT64_MAX) == NULL);
    CHECK(sucrune_fds_destroy(&table) == 0 && table.count == 0U && table.resource_count == 0U);
}
static void last_input_reference(void) {
    struct sucrune_fd_table table; struct released events;
    initialize(&table, &events);
    CHECK(sucrune_fds_duplicate(&table, 0U, 3U, 0U) == 3);
    CHECK(sucrune_fds_get(&table, 0U) == sucrune_fds_get(&table, 3U));
    CHECK(sucrune_fds_close(&table, 0U) == 0 && events.count == 0U);
    CHECK(sucrune_fds_replace(&table, 3U, 0U, 0U) == 0);
    CHECK(sucrune_fds_close(&table, 3U) == 0 && events.count == 0U);
    CHECK(sucrune_fds_close(&table, 0U) == 0 && events.count == 1U);
    CHECK(events.kind[0] == SUCRUNE_FD_INPUT && events.handles[0] == 100);
    CHECK(sucrune_fds_close(&table, 0U) == -EBADF && events.count == 1U);
    CHECK(sucrune_fds_destroy(&table) == 0 && events.count == 3U);
}
static void lowest_reuse_and_identity(void) {
    struct sucrune_fd_table table; struct released events;
    initialize(&table, &events);
    CHECK(sucrune_fds_close(&table, 0U) == 0);
    CHECK(sucrune_fds_available(&table) == 0);
    CHECK(sucrune_fds_add(&table, SUCRUNE_FD_BROKER, 3, 2, SUCRUNE_FD_CLOEXEC) == 0);
    CHECK(sucrune_fds_duplicate(&table, 0U, 0U, 0U) == 3);
    CHECK(sucrune_fds_get(&table, 0U) == sucrune_fds_get(&table, 3U));
    CHECK(sucrune_fds_get(&table, 0U)->handle == 3);
    CHECK(sucrune_fds_get_flags(&table, 0U) == 1 && sucrune_fds_get_flags(&table, 3U) == 0);
    sucrune_fds_get(&table, 0U)->status_flags |= 1024;
    CHECK(sucrune_fds_get(&table, 3U)->status_flags == 1026);
    CHECK(sucrune_fds_destroy(&table) == 0 && events.count == 4U);
}
static void invalid_replace_has_no_effect(void) {
    struct sucrune_fd_table table; struct released events;
    initialize(&table, &events);
    CHECK(sucrune_fds_set_flags(&table, 1U, SUCRUNE_FD_CLOEXEC) == 0);
    struct sucrune_fd_table before = table;
    CHECK(sucrune_fds_replace(&table, 1U, 1U, 0U) == -EINVAL);
    CHECK(sucrune_fds_replace(&table, 63U, 1U, 0U) == -EBADF);
    CHECK(sucrune_fds_replace(&table, 1U, 64U, 0U) == -EBADF);
    CHECK(sucrune_fds_replace(&table, 1U, 2U, 2U) == -EINVAL);
    CHECK(memcmp(&before, &table, sizeof(table)) == 0 && events.count == 0U);
    CHECK(sucrune_fds_destroy(&table) == 0);
}
static void replacing_shared_description(void) {
    struct sucrune_fd_table table; struct released events;
    initialize(&table, &events);
    CHECK(sucrune_fds_duplicate(&table, 1U, 3U, 1U) == 3);
    CHECK(sucrune_fds_replace(&table, 1U, 3U, 0U) == 3);
    CHECK(sucrune_fds_get_flags(&table, 3U) == 0 && events.count == 0U);
    CHECK(sucrune_fds_replace(&table, 2U, 1U, 1U) == 1);
    CHECK(sucrune_fds_get(&table, 1U) == sucrune_fds_get(&table, 2U));
    CHECK(sucrune_fds_get(&table, 3U)->kind == SUCRUNE_FD_OUTPUT);
    CHECK(sucrune_fds_close(&table, 3U) == 0 && events.count == 1U);
    CHECK(events.handles[0] == 101);
    CHECK(sucrune_fds_exec(&table) == 0 && events.count == 1U);
    CHECK(sucrune_fds_get(&table, 1U) == NULL && sucrune_fds_get(&table, 2U) != NULL);
    CHECK(sucrune_fds_destroy(&table) == 0 && events.count == 3U);
}
static void cloexec_is_per_descriptor(void) {
    struct sucrune_fd_table table; struct released events;
    initialize(&table, &events);
    CHECK(sucrune_fds_duplicate(&table, 0U, 3U, 1U) == 3);
    CHECK(sucrune_fds_set_flags(&table, 0U, 1U) == 0);
    CHECK(sucrune_fds_duplicate(&table, 0U, 3U, 0U) == 4);
    CHECK(sucrune_fds_set_flags(&table, 4U, 2U) == -EINVAL);
    CHECK(sucrune_fds_exec(&table) == 0 && events.count == 0U);
    CHECK(sucrune_fds_get(&table, 0U) == NULL && sucrune_fds_get(&table, 3U) == NULL);
    CHECK(sucrune_fds_get(&table, 4U)->references == 1U);
    CHECK(sucrune_fds_close(&table, 4U) == 0 && events.count == 1U);
    CHECK(sucrune_fds_destroy(&table) == 0 && events.count == 3U);
}
static void capacity_and_minimum(void) {
    struct sucrune_fd_table table; struct released events;
    initialize(&table, &events);
    for (unsigned int i = 3; i < SUCRUNE_FD_LIMIT; i++) CHECK(sucrune_fds_duplicate(&table, 1U, 0U, 0U) == (int)i);
    CHECK(table.count == 64U && table.resource_count == 3U && table.peak == 64U);
    CHECK(sucrune_fds_duplicate(&table, 1U, 0U, 0U) == -EMFILE);
    CHECK(sucrune_fds_available(&table) == -EMFILE);
    CHECK(sucrune_fds_duplicate(&table, 1U, 64U, 0U) == -EINVAL);
    CHECK(sucrune_fds_duplicate(&table, 1U, UINT64_MAX, 0U) == -EINVAL);
    CHECK(sucrune_fds_close(&table, 17U) == 0 && events.count == 0U);
    CHECK(sucrune_fds_duplicate(&table, 1U, 18U, 0U) == -EMFILE);
    CHECK(sucrune_fds_duplicate(&table, 1U, 17U, 0U) == 17);
    CHECK(sucrune_fds_destroy(&table) == 0 && events.count == 3U);
}
static void sixty_four_resources(void) {
    struct sucrune_fd_table table; struct released events;
    initialize(&table, &events);
    CHECK(sucrune_fds_destroy(&table) == 0 && events.count == 3U);
    for (unsigned int i = 0; i < SUCRUNE_FD_LIMIT; i++)
        CHECK(sucrune_fds_add(&table, SUCRUNE_FD_BROKER, (int)i + 3, 2, 0U) == (int)i);
    CHECK(table.resource_count == 64U && table.count == 64U);
    CHECK(sucrune_fds_add(&table, SUCRUNE_FD_BROKER, 67, 2, 0U) == -EMFILE);
    CHECK(sucrune_fds_destroy(&table) == 0 && events.count == 67U);
    CHECK(table.count == 0U && table.resource_count == 0U && table.peak == 64U);
}
static void close_error_consumes_number(void) {
    struct sucrune_fd_table table; struct released events;
    initialize(&table, &events); events.fail_handle = 101;
    CHECK(sucrune_fds_close(&table, 1U) == -EIO && events.count == 1U);
    CHECK(sucrune_fds_get(&table, 1U) == NULL);
    CHECK(sucrune_fds_close(&table, 1U) == -EBADF && events.count == 1U);
    CHECK(sucrune_fds_duplicate(&table, 2U, 0U, 0U) == 1);
    CHECK(sucrune_fds_destroy(&table) == 0 && events.count == 3U);
}
static void replacement_ignores_target_close_error(void) {
    struct sucrune_fd_table table; struct released events;
    initialize(&table, &events); events.fail_handle = 101;
    CHECK(sucrune_fds_replace(&table, 2U, 1U, 0U) == 1);
    CHECK(events.count == 1U && table.resource_count == 2U);
    CHECK(sucrune_fds_get(&table, 1U) == sucrune_fds_get(&table, 2U));
    events.fail_handle = 102;
    CHECK(sucrune_fds_set_flags(&table, 1U, 1U) == 0 && sucrune_fds_set_flags(&table, 2U, 1U) == 0);
    CHECK(sucrune_fds_exec(&table) == -EIO && events.count == 2U);
    CHECK(sucrune_fds_get(&table, 1U) == NULL && sucrune_fds_get(&table, 2U) == NULL);
    CHECK(sucrune_fds_destroy(&table) == 0 && events.count == 3U);
}
struct aliases { int live[256], canonical[256]; unsigned int calls, made, closed, fail_call; int fail_close; };
static int alias_create(void *context, enum sucrune_fd_kind kind, int canonical, int *alias) {
    struct aliases *state = context;
    state->calls++;
    if (state->calls == state->fail_call) return -EMFILE;
    if (kind == SUCRUNE_FD_BROKER || canonical < 0) { *alias = -1; return 0; }
    CHECK(state->made < 256U);
    unsigned int index = state->made++;
    state->live[index] = 1; state->canonical[index] = canonical;
    *alias = 1000 + (int)index;
    return 0;
}
static int alias_close(void *context, enum sucrune_fd_kind kind, int alias) {
    struct aliases *state = context;
    (void)kind;
    CHECK(alias >= 1000 && alias < 1256 && state->live[alias - 1000] == 1);
    state->live[alias - 1000] = 0; state->closed++;
    return alias == state->fail_close ? -EIO : 0;
}
static void alias_enable_rollback(void) {
    struct sucrune_fd_table table; struct released events; struct aliases aliases = {0};
    initialize(&table, &events); struct sucrune_fd_table before = table;
    aliases.fail_call = 2U;
    CHECK(sucrune_fds_enable_aliases(&table, alias_create, alias_close, &aliases) == -EMFILE);
    CHECK(memcmp(&before, &table, sizeof(table)) == 0 && events.count == 0U);
    CHECK(aliases.made == 1U && aliases.closed == 1U);
    aliases.fail_call = 0U;
    CHECK(sucrune_fds_enable_aliases(&table, alias_create, alias_close, &aliases) == 0);
    CHECK(sucrune_fds_enable_aliases(&table, alias_create, alias_close, &aliases) == -EINVAL);
    CHECK(sucrune_fds_alias(&table, 0U) >= 1000 && sucrune_fds_alias(&table, 99U) == -EBADF);
    CHECK(sucrune_fds_destroy(&table) == 0 && aliases.closed == aliases.made);
}
static void broker_read_fd_last_drop(void) {
    struct sucrune_fd_table table; struct released events; struct aliases aliases = {0};
    initialize(&table, &events);
    CHECK(sucrune_fds_enable_aliases(&table,alias_create,alias_close,&aliases)==0);
    int fd=sucrune_fds_add(&table,SUCRUNE_FD_BROKER,45,0,SUCRUNE_FD_CLOEXEC);
    CHECK(fd==3);
    struct sucrune_fd_resource *r=sucrune_fds_get(&table,3U);
    CHECK(r->read_fd==-1);
    int local;
    CHECK(alias_create(&aliases,SUCRUNE_FD_LOCAL,45,&local)==0);
    r->read_fd=local;
    CHECK(sucrune_fds_duplicate(&table,3U,4U,0U)==4);
    int held=sucrune_fds_hold(&table,4U);
    CHECK(held>=0 && sucrune_fds_exec(&table)==0);
    CHECK(sucrune_fds_get(&table,4U)->read_fd==local && sucrune_fds_close(&table,4U)==0);
    CHECK(aliases.live[local-1000] && events.count==0U);
    CHECK(sucrune_fds_drop(&table,(unsigned)held)==0);
    CHECK(!aliases.live[local-1000] && events.count==1U && events.handles[0]==45);
    CHECK(sucrune_fds_add(&table,SUCRUNE_FD_BROKER,46,0,0)==3 && sucrune_fds_get(&table,3U)->read_fd==-1);
    CHECK(sucrune_fds_destroy(&table)==0 && aliases.closed==aliases.made);
}
static void alias_identity_and_last_close(void) {
    struct sucrune_fd_table table; struct released events; struct aliases aliases = {0};
    initialize(&table, &events);
    CHECK(sucrune_fds_enable_aliases(&table, alias_create, alias_close, &aliases) == 0);
    int first = sucrune_fds_alias(&table, 0U);
    CHECK(sucrune_fds_duplicate(&table, 0U, 3U, 1U) == 3);
    int second = sucrune_fds_alias(&table, 3U);
    CHECK(first != second && aliases.canonical[first - 1000] == aliases.canonical[second - 1000]);
    CHECK(sucrune_fds_get(&table, 0U) == sucrune_fds_get(&table, 3U));
    CHECK(sucrune_fds_close(&table, 0U) == 0 && aliases.live[first - 1000] == 0 && events.count == 0U);
    CHECK(sucrune_fds_exec(&table) == 0 && aliases.live[second - 1000] == 0 && events.count == 1U);
    CHECK(events.handles[0] == 100);
    CHECK(sucrune_fds_destroy(&table) == 0 && aliases.closed == aliases.made);
}
static void alias_dup_failure_preserves_target(void) {
    struct sucrune_fd_table table; struct released events; struct aliases aliases = {0};
    initialize(&table, &events);
    CHECK(sucrune_fds_enable_aliases(&table, alias_create, alias_close, &aliases) == 0);
    struct sucrune_fd_table before = table;
    aliases.fail_call = aliases.calls + 1U;
    CHECK(sucrune_fds_replace(&table, 0U, 1U, 1U) == -EMFILE);
    CHECK(memcmp(&before, &table, sizeof(table)) == 0 && events.count == 0U);
    aliases.fail_call = aliases.calls + 1U;
    CHECK(sucrune_fds_duplicate(&table, 0U, 3U, 0U) == -EMFILE);
    CHECK(memcmp(&before, &table, sizeof(table)) == 0 && events.count == 0U);
    CHECK(sucrune_fds_destroy(&table) == 0 && aliases.closed == aliases.made);
}
static void alias_batch_failure_is_atomic(void) {
    struct sucrune_fd_table table; struct released events; struct aliases aliases = {0};
    initialize(&table, &events);
    CHECK(sucrune_fds_enable_aliases(&table, alias_create, alias_close, &aliases) == 0);
    const int handles[2] = {500,501}, status[2] = {0,1}; const unsigned int flags[2] = {1U,0U};
    int32_t result[2] = {-71,-72};
    struct sucrune_fd_table before = table;
    aliases.fail_call = aliases.calls + 2U;
    CHECK(sucrune_fds_add_batch(&table, SUCRUNE_FD_LOCAL, handles, status, flags, 2U, result) == -EMFILE);
    CHECK(memcmp(&before, &table, sizeof(table)) == 0 && events.count == 0U);
    CHECK(result[0] == -71 && result[1] == -72 && aliases.closed == 1U);
    aliases.fail_call = 0U;
    CHECK(sucrune_fds_add_batch(&table, SUCRUNE_FD_LOCAL, handles, status, flags, 2U, result) == 0);
    CHECK(result[0] == 3 && result[1] == 4 && table.count == 5U && table.resource_count == 5U);
    CHECK(sucrune_fds_get(&table, 3U)->kind == SUCRUNE_FD_LOCAL);
    CHECK(sucrune_fds_destroy(&table) == 0 && aliases.closed == aliases.made && events.count == 5U);
}
static void alias_close_error_still_releases_canonical(void) {
    struct sucrune_fd_table table; struct released events; struct aliases aliases = {0};
    initialize(&table, &events);
    CHECK(sucrune_fds_enable_aliases(&table, alias_create, alias_close, &aliases) == 0);
    aliases.fail_close = sucrune_fds_alias(&table, 1U);
    CHECK(sucrune_fds_close(&table, 1U) == -EIO && events.count == 1U);
    CHECK(sucrune_fds_alias(&table, 1U) == -EBADF);
    aliases.fail_close = sucrune_fds_alias(&table, 0U);
    CHECK(sucrune_fds_replace(&table, 2U, 0U, 0U) == 0 && events.count == 2U);
    CHECK(sucrune_fds_destroy(&table) == 0 && aliases.closed == aliases.made && events.count == 3U);
}
static void batch_capacity_preflight(void) {
    struct sucrune_fd_table table; struct released events; struct aliases aliases = {0};
    initialize(&table, &events);
    CHECK(sucrune_fds_enable_aliases(&table, alias_create, alias_close, &aliases) == 0);
    for (unsigned int i = 3U; i < 63U; i++) CHECK(sucrune_fds_duplicate(&table, 1U, 0U, 0U) == (int)i);
    unsigned int calls = aliases.calls;
    const int handles[2] = {500,501}, status[2] = {0,1}; const unsigned int flags[2] = {0U,0U};
    int32_t result[2] = {-71,-72};
    CHECK(sucrune_fds_add_batch(&table, SUCRUNE_FD_LOCAL, handles, status, flags, 2U, result) == -EMFILE);
    CHECK(aliases.calls == calls && result[0] == -71 && result[1] == -72 && table.count == 63U);
    CHECK(sucrune_fds_destroy(&table) == 0 && aliases.closed == aliases.made);
}
static void linux_high_descriptors(void) {
    struct sucrune_fd_table table;
    sucrune_fds_init_empty(&table, NULL, NULL);
    CHECK(table.limit == SUCRUNE_FD_LIMIT);
    sucrune_fds_enable_linux(&table);
    CHECK(table.limit == SUCRUNE_LINUX_FD_LIMIT);
    for (unsigned int i = 0; i < table.limit - 2U; i++)
        CHECK(sucrune_fds_add(&table, SUCRUNE_FD_BROKER, (int)i + 3, 0, 0U) == (int)i);
    CHECK(sucrune_fds_duplicate(&table, 300, 1022, 0U) == 1022);
    CHECK(sucrune_fds_duplicate(&table, 300, 1023, SUCRUNE_FD_CLOEXEC) == 1023);
    CHECK(sucrune_fds_available(&table) == -EMFILE && table.peak == SUCRUNE_LINUX_FD_LIMIT);
    CHECK(sucrune_fds_get(&table, 1022) == sucrune_fds_get(&table, 300));
    CHECK(sucrune_fds_exec(&table) == 0 && sucrune_fds_get(&table, 1023) == NULL);
    CHECK(sucrune_fds_get(&table, 1022)->handle == 303);
    CHECK(sucrune_fds_add(&table, SUCRUNE_FD_LOCAL, 900, 0, 0U) == 1023);
    CHECK(sucrune_fds_replace(&table, 1023, 1024, 0) == -EBADF);
    CHECK(sucrune_fds_destroy(&table) == 0 && table.count == 0 && table.resource_count == 0);
}
int main(void) {
    linux_high_descriptors();
    empty_stdin_is_open(); last_input_reference(); lowest_reuse_and_identity();
    invalid_replace_has_no_effect(); replacing_shared_description(); cloexec_is_per_descriptor();
    capacity_and_minimum(); sixty_four_resources(); close_error_consumes_number();
    replacement_ignores_target_close_error();
    alias_enable_rollback(); alias_identity_and_last_close(); alias_dup_failure_preserves_target();
    alias_batch_failure_is_atomic(); alias_close_error_still_releases_canonical(); batch_capacity_preflight();
    broker_read_fd_last_drop();
    (void)puts("Guest FD ownership invariants: 18/18 passed (pure table tests; no Linux guest execution).");
    return 0;
}
