#include "guest_fds.h"
#include <errno.h>
#include <stddef.h>
#include <string.h>

static int live(const struct sucrune_fd_table *table, uint64_t descriptor) {
    return descriptor < table->limit && table->entries[descriptor].resource >= 0;
}
static int free_descriptor(const struct sucrune_fd_table *table, unsigned int minimum) {
    for (unsigned int descriptor = minimum; descriptor < table->limit; descriptor++)
        if (table->entries[descriptor].resource < 0) return (int)descriptor;
    return -EMFILE;
}
static void attach(struct sucrune_fd_table *table, unsigned int descriptor,
                   int resource, unsigned int flags, int alias) {
    table->entries[descriptor].resource = resource;
    table->entries[descriptor].flags = flags;
    table->entries[descriptor].host_alias = alias;
    table->resources[resource].references++;
    table->count++;
    if (table->count > table->peak) table->peak = table->count;
}
void sucrune_fds_init_empty(struct sucrune_fd_table *table,sucrune_fd_release release,void *context) {
    memset(table, 0, sizeof(*table));
    table->limit = SUCRUNE_FD_LIMIT;
    table->release = release;
    table->context = context;
    for (unsigned int i = 0; i < table->limit; i++) {
        table->entries[i].resource = -1; table->entries[i].host_alias = -1;
        table->resources[i].read_fd = -1;
    }
}
void sucrune_fds_enable_linux(struct sucrune_fd_table *table) {
    for (unsigned int i = table->limit; i < SUCRUNE_LINUX_FD_LIMIT; i++) {
        table->entries[i].resource = -1;
        table->entries[i].host_alias = -1;
        table->resources[i].read_fd = -1;
    }
    table->limit = SUCRUNE_LINUX_FD_LIMIT;
}
void sucrune_fds_init(struct sucrune_fd_table *table, int input, int output, int error_output,
                     int read_flags, int write_flags, sucrune_fd_release release, void *context) {
    sucrune_fds_init_empty(table,release,context);
    (void)sucrune_fds_add(table, SUCRUNE_FD_INPUT, input, read_flags, 0U);
    (void)sucrune_fds_add(table, SUCRUNE_FD_OUTPUT, output, write_flags, 0U);
    (void)sucrune_fds_add(table, SUCRUNE_FD_ERROR, error_output, write_flags, 0U);
}
int sucrune_fds_enable_aliases(struct sucrune_fd_table *table, sucrune_fd_alias_create create,
                              sucrune_fd_alias_close close, void *context) {
    if (table == NULL || create == NULL || close == NULL || table->alias_create != NULL) return -EINVAL;
    int aliases[SUCRUNE_LINUX_FD_LIMIT];
    for (unsigned int i = 0U; i < table->limit; i++) aliases[i] = -1;
    int error = 0;
    for (unsigned int i = 0U; i < table->limit; i++) {
        if (!live(table, i)) continue;
        const struct sucrune_fd_resource *resource = &table->resources[table->entries[i].resource];
        error = create(context, resource->kind, resource->handle, &aliases[i]);
        if (error != 0) { aliases[i] = -1; break; }
        if (aliases[i] < -1) { error = -EIO; break; }
    }
    if (error != 0) {
        for (unsigned int i = 0U; i < table->limit; i++) if (aliases[i] >= 0)
            (void)close(context, table->resources[table->entries[i].resource].kind, aliases[i]);
        return error < 0 ? error : -EIO;
    }
    table->alias_create = create; table->alias_close = close; table->alias_context = context;
    for (unsigned int i = 0U; i < table->limit; i++) table->entries[i].host_alias = aliases[i];
    return 0;
}
int sucrune_fds_alias(const struct sucrune_fd_table *table, uint64_t descriptor) {
    if (!live(table, descriptor)) return -EBADF;
    int alias = table->entries[descriptor].host_alias;
    return alias >= 0 ? alias : -ENOTSUP;
}
static int prepare_alias(struct sucrune_fd_table *table, enum sucrune_fd_kind kind, int handle, int *alias) {
    *alias = -1;
    if (table->alias_create == NULL) return 0;
    int error = table->alias_create(table->alias_context, kind, handle, alias);
    if (error != 0) return error < 0 ? error : -EIO;
    return *alias >= -1 ? 0 : -EIO;
}
struct sucrune_fd_resource *sucrune_fds_get(struct sucrune_fd_table *table, uint64_t descriptor) {
    if (!live(table, descriptor)) return NULL;
    return &table->resources[table->entries[descriptor].resource];
}
int sucrune_fds_available(const struct sucrune_fd_table *table) {
    return table->resource_count < table->limit ? free_descriptor(table, 0U) : -EMFILE;
}
int sucrune_fds_add(struct sucrune_fd_table *table, enum sucrune_fd_kind kind,
                   int handle, int status_flags, unsigned int flags) {
    int32_t descriptor;
    int error = sucrune_fds_add_batch(table, kind, &handle, &status_flags, &flags, 1U, &descriptor);
    return error == 0 ? descriptor : error;
}
int sucrune_fds_add_batch(struct sucrune_fd_table *table, enum sucrune_fd_kind kind,
    const int *handles, const int *status_flags, const unsigned int *flags,
    size_t count, int32_t *descriptors) {
    if (table == NULL || kind <= SUCRUNE_FD_UNUSED || kind > SUCRUNE_FD_LOCAL ||
        count == 0U || count > table->limit || handles == NULL || status_flags == NULL || flags == NULL || descriptors == NULL) return -EINVAL;
    for (size_t i = 0U; i < count; i++) if ((flags[i] & ~SUCRUNE_FD_CLOEXEC) != 0U) return -EINVAL;
    if (count > table->limit - table->count || count > table->limit - table->resource_count) return -EMFILE;
    int slots[SUCRUNE_LINUX_FD_LIMIT], resources[SUCRUNE_LINUX_FD_LIMIT], aliases[SUCRUNE_LINUX_FD_LIMIT];
    unsigned int next_slot = 0U, next_resource = 0U;
    for (size_t i = 0U; i < count; i++) {
        int slot = free_descriptor(table, next_slot);
        if (slot < 0) return slot;
        while (next_resource < table->limit && table->resources[next_resource].references != 0U)
            next_resource++;
        if (next_resource == table->limit) return -EMFILE;
        slots[i] = slot;
        resources[i] = (int)next_resource;
        next_slot = (unsigned int)slot + 1U;
        next_resource++;
    }
    for (size_t i = 0U; i < count; i++) {
        int error = prepare_alias(table, kind, handles[i], &aliases[i]);
        if (error != 0) {
            for (size_t j = 0U; j < i; j++) if (aliases[j] >= 0)
                (void)table->alias_close(table->alias_context, kind, aliases[j]);
            return error;
        }
    }
    for (size_t i = 0U; i < count; i++) {
        struct sucrune_fd_resource *resource = &table->resources[resources[i]];
        resource->kind = kind; resource->handle = handles[i]; resource->status_flags = status_flags[i];
        table->resource_count++;
        attach(table, (unsigned int)slots[i], resources[i], flags[i], aliases[i]);
        descriptors[i] = slots[i];
    }
    return 0;
}
int sucrune_fds_hold(struct sucrune_fd_table *table,uint64_t fd) {
    if (!live(table,fd)) return -EBADF;
    int id=table->entries[fd].resource;
    if (table->resources[id].references==UINT32_MAX) return -EOVERFLOW;
    table->resources[id].references++;
    return id;
}
int sucrune_fds_drop(struct sucrune_fd_table *table,unsigned int id) {
    if (id>=table->limit || table->resources[id].references==0U) return -EBADF;
    struct sucrune_fd_resource *r=&table->resources[id];
    if (--r->references!=0U) return 0;
    enum sucrune_fd_kind kind=r->kind; int handle=r->handle;
    if (r->read_fd >= 0) (void)table->alias_close(table->alias_context, kind, r->read_fd);
    memset(r,0,sizeof(*r)); table->resource_count--;
    r->read_fd = -1;
    return table->release==NULL ? 0 : table->release(table->context,kind,handle);
}
int sucrune_fds_close(struct sucrune_fd_table *table, uint64_t descriptor) {
    if (!live(table, descriptor)) return -EBADF;
    unsigned int id=(unsigned int)table->entries[descriptor].resource;
    struct sucrune_fd_resource *resource = &table->resources[id];
    int alias = table->entries[descriptor].host_alias;
    enum sucrune_fd_kind kind = resource->kind;
    int notified = table->descriptor_closed ? table->descriptor_closed(table->context,kind,resource->handle) : 0;
    table->entries[descriptor].resource = -1;
    table->entries[descriptor].flags = 0U;
    table->entries[descriptor].host_alias = -1;
    table->count--;
    int alias_error = alias < 0 ? 0 : table->alias_close(table->alias_context, kind, alias);
    /* Descriptor removal is final even if the backend reports a close error. */
    int release_error = sucrune_fds_drop(table,id);
    if (notified<0) return notified;
    return alias_error != 0 ? alias_error : release_error;
}
int sucrune_fds_get_flags(const struct sucrune_fd_table *table, uint64_t descriptor) {
    return live(table, descriptor) ? (int)table->entries[descriptor].flags : -EBADF;
}
int sucrune_fds_set_flags(struct sucrune_fd_table *table, uint64_t descriptor, uint64_t flags) {
    if (!live(table, descriptor)) return -EBADF;
    if ((flags & ~(uint64_t)SUCRUNE_FD_CLOEXEC) != 0U) return -EINVAL;
    table->entries[descriptor].flags = (unsigned int)flags;
    return 0;
}
int sucrune_fds_duplicate(struct sucrune_fd_table *table, uint64_t source,
                         uint64_t minimum, unsigned int cloexec) {
    if (!live(table, source)) return -EBADF;
    if (minimum >= table->limit || cloexec > 1U) return -EINVAL;
    int destination = free_descriptor(table, (unsigned int)minimum);
    if (destination < 0) return destination;
    int resource = table->entries[source].resource, alias;
    int error = prepare_alias(table, table->resources[resource].kind, table->resources[resource].handle, &alias);
    if (error != 0) return error;
    attach(table, (unsigned int)destination, resource, cloexec, alias);
    return destination;
}
int sucrune_fds_replace(struct sucrune_fd_table *table, uint64_t source,
                       uint64_t destination, unsigned int cloexec) {
    if (source == destination || cloexec > 1U) return -EINVAL;
    if (!live(table, source) || destination >= table->limit) return -EBADF;
    int resource = table->entries[source].resource;
    int alias;
    int error = prepare_alias(table, table->resources[resource].kind, table->resources[resource].handle, &alias);
    if (error != 0) return error;
    /* Hold a reference before closing the target, including when both numbers
     * already refer to the same open description. No allocation can now fail. */
    table->resources[resource].references++;
    if (live(table, destination)) (void)sucrune_fds_close(table, destination);
    attach(table, (unsigned int)destination, resource, cloexec, alias);
    table->resources[resource].references--;
    return (int)destination;
}
int sucrune_fds_exec(struct sucrune_fd_table *table) {
    int failure = 0;
    for (unsigned int i = 0; i < table->limit; i++) {
        if (!live(table, i) || (table->entries[i].flags & SUCRUNE_FD_CLOEXEC) == 0U) continue;
        int result = sucrune_fds_close(table, i);
        if (result < 0 && failure == 0) failure = result;
    }
    return failure;
}
int sucrune_fds_destroy(struct sucrune_fd_table *table) {
    int failure = 0;
    for (unsigned int i = 0; i < table->limit; i++) {
        if (!live(table, i)) continue;
        int result = sucrune_fds_close(table, i);
        if (result < 0 && failure == 0) failure = result;
    }
    return failure;
}
