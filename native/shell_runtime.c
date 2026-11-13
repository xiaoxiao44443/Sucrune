#include "shell_runtime.h"
#include "guest_shebang.h"
#include "elf_loader.h"
#include "workspace_broker.h"
#include "workspace_locks.h"
#include "guest_memory.h"
#include "guest_fds.h"
#include "guest_abi.h"
#include "program_catalog.h"
#include "linux_elf.h"
#include "linux_runner.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__aarch64__)
#include <elf.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/futex.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <linux/if_arp.h>
#include <sys/syscall.h>
#include <sys/auxv.h>
#include <time.h>
#include <ucontext.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/times.h>
#include <sys/time.h>
#include <sys/file.h>
#include <asm/hwcap.h>
#include "guest_context.h"
#include "guest_fault.h"
#include "guest_signals.h"
#include "guest_threads.h"
#include "guest_local_io.h"
#include "guest_devices.h"
#include "guest_landlock_decode.h"
#include "guest_sockets.h"
#include "guest_network.h"
#include "broker_transport.h"
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <sys/vfs.h>
#include <sched.h>
#include "guest_gates.h"
#include "guest_processes.h"
#include "guest_proc.h"
#include "guest_exec.h"
#include "pty_runtime.h"
#include "pty_broker.h"
#include "pty_session.h"
#include <poll.h>
#include "guest_exec_receive.h"
#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif
#define SHELL_TAG 0x5352U
#define STACK_SIZE (1024U * 1024U)
#define ALT_SIZE (128U * 1024U)
#define SCRIPT_LIMIT (64U * 1024U)
#define EXEC_LIMIT 32U
#define BUNDLED_EXEC_ARGS 65U
#define EXEC_STRING_LIMIT (64U * 1024U)
_Static_assert(FD_CLOEXEC == SUCRUNE_FD_CLOEXEC, "Linux guest FD flag ABI");
struct pending_exec {
    const struct sucrune_program *program;
    void *images[2];
    size_t image_sizes[2];
    char linux_path[SUCRUNE_PATH_LIMIT];
    char execfn[SUCRUNE_PATH_LIMIT];
    struct sucrune_script_chain scripts;
    size_t argc, envc, used;
    const char *argv[SUCRUNE_GUEST_EXEC_ARGS], *envp[SUCRUNE_GUEST_EXEC_ENV];
    char strings[EXEC_STRING_LIMIT];
};
struct shell_state {
    struct sucrune_elf_image image;
    struct sucrune_elf_image interpreter;
    struct sucrune_guest_space space, fixed_space;
    uintptr_t linux_entry, linux_brk_base, linux_brk;
    bool linux_mode, build_profile, linux_allow_rwx, trace_syscalls, trace_faults;
    _Alignas(16) struct sucrune_host_context host;
    struct sucrune_signal_gate gate;
    struct sucrune_guest_memory memory;
    struct sucrune_fd_table descriptors;
    struct sucrune_guest_network network;
    struct sucrune_pty_table ptys;
    const struct sucrune_guest_exec *inherited;
    unsigned char datagram_buffer[65536U]; /* state_lock owns private receive staging */
    pthread_mutex_t state_lock;
    bool may_have_record_locks;
    struct sucrune_thread_group *threads;
    struct sucrune_thread_stats thread_stats;
    struct sucrune_process_group *processes;
    struct sucrune_proc_table proc;
    struct sucrune_process_stats process_stats;
    uintptr_t main_clear_tid;
    int broker, output, error_output, input;
    struct sucrune_project_owner owner;
    gid_t *supplementary_groups;
    uint64_t input_read;
    uint64_t direct_read_calls, direct_read_bytes, guest_direct_read_bytes;
    long page;
    void *stack, *alternate;
    size_t stack_size, alternate_size;
    uintptr_t stack_low, stack_high, stack_pointer, alt_low, alt_high;
    const char *stage, *message;
    int error;
    uint64_t syscalls, unsupported; /* Translated calls are serialized by state_lock in the Linux runner. */
    volatile sig_atomic_t exited, exit_code, alt_seen, tls_seen, last_unsupported;
    bool joined, restored, returned, tls_restored, program, collision_rejected;
    uint64_t guest_signal_mask;
    struct sucrune_signal_process signal_process;
    struct sucrune_signal_thread signal_thread;
    uintptr_t signal_restorer;
    unsigned int signal_deliveries, signal_returns;
    int termination_signal;
    int parser_checks;
    const struct sucrune_program *current_program;
    struct sucrune_program replaced_program;
    char replaced_path[SUCRUNE_PATH_LIMIT];
    struct pending_exec pending;
    volatile sig_atomic_t exec_pending, exec_count, exec_failed_before_commit;
    size_t heap_peak;
    unsigned int host_context_restores;
};
static _Atomic(struct shell_state *) active_shell;
static pthread_mutex_t shell_lock = PTHREAD_MUTEX_INITIALIZER;
_Static_assert(ATOMIC_POINTER_LOCK_FREE == 2, "signal pointer must be lock free");

static int in_range(uintptr_t begin, size_t length, uintptr_t address, size_t count) {
    return address >= begin && address - begin <= length && count <= length - (address - begin);
}
static int guest_memory(struct shell_state *s, uintptr_t address, size_t count, bool write_access) {
    if (s->linux_mode) return sucrune_space_access(&s->space, address, count, write_access ? 1 : 0) ||
        sucrune_space_access(&s->fixed_space, address, count, write_access ? 1 : 0);
    if (sucrune_memory_access(&s->memory, address, count, write_access ? 1 : 0)) return 1;
    if (in_range(s->stack_low, s->stack_high - s->stack_low, address, count)) return 1;
    for (size_t i = 0; i < s->image.segment_count; i++) {
        const struct sucrune_elf_range *r = &s->image.segments[i];
        if ((r->flags & (write_access ? PF_W : PF_R)) != 0U && in_range(r->start, r->length, address, count)) return 1;
    }
    return 0;
}
static int signal_access(void *opaque, uintptr_t address, size_t count, int write_access) {
    return guest_memory(opaque, address, count, write_access != 0);
}
static int signal_executable(void *opaque, uintptr_t address) {
    struct shell_state *s = opaque;
    struct sucrune_guest_space *spaces[] = {&s->space, &s->fixed_space};
    for (size_t i = 0; i < 2U; i++) for (size_t j = 0; j < spaces[i]->count; j++) {
        const struct sucrune_space_vma *area = &spaces[i]->areas[j];
        if ((area->protection & PROT_EXEC) != 0 && in_range(area->start, area->length, address, 4U)) return 1;
    }
    return 0;
}
static struct sucrune_signal_memory signal_memory(struct shell_state *s) {
    return (struct sucrune_signal_memory){.opaque = s, .access = signal_access,
        .executable = signal_executable, .restorer = s->signal_restorer};
}
static struct sucrune_signal_thread *current_signals(struct shell_state *s) {
    struct sucrune_guest_thread *thread = sucrune_thread_current();
    return thread == NULL ? &s->signal_thread : sucrune_thread_signals(thread);
}
static int can_receive_child(struct shell_state *s) {
    return s->signal_process.actions[SIGCHLD].handler>1U &&
        (current_signals(s)->mask&(UINT64_C(1)<<(SIGCHLD-1)))==0U;
}
static void collect_child_signal(struct shell_state *s) {
    struct sucrune_signal_thread *thread=current_signals(s);
    if(s->inherited && s->inherited->scope.lease>=0) {
        unsigned int signals=sucrune_scope_pending();
        while(signals) {
            unsigned int sig=(unsigned int)__builtin_ctz(signals)+1U;
            signals&=signals-1U;
            (void)sucrune_signals_self(&s->signal_process,thread,129,thread->pid,(int64_t)sig,0);
        }
    }
    uint64_t bit=UINT64_C(1)<<(SIGCHLD-1);
    if(s->signal_process.actions[SIGCHLD].handler>1U && ((thread->mask|thread->pending)&bit)!=0U) return;
    struct sucrune_signal_info info;
    if(sucrune_processes_take_child_signal(s->processes,&info) && s->signal_process.actions[SIGCHLD].handler>1U) {
        thread->pending_info[SIGCHLD]=info;thread->pending|=bit;
    }
}
static void copy_bytes(unsigned char *to, const unsigned char *from, size_t size) {
    volatile unsigned char *destination = to;
    const volatile unsigned char *source = from;
    for (size_t i = 0; i < size; i++) destination[i] = source[i];
}
static int path_arg(struct shell_state *s, struct sucrune_request *r, uintptr_t address) {
    size_t start = r->size;
    if (start > SUCRUNE_IO_LIMIT - SUCRUNE_PATH_LIMIT) return ENAMETOOLONG;
    size_t checked = 0;
    for (size_t i = 0; i < SUCRUNE_PATH_LIMIT; i++) {
        if (i == checked) {
            if (address > UINTPTR_MAX - i) return EFAULT;
            uintptr_t current = address + i;
            size_t count = 1U;
            if (s->linux_mode) {
                /* Linux VMAs are page-aligned and stable under state_lock.
                 * Validate this page once; read only through the first NUL. */
                size_t page = s->space.page_size;
                count = page - (current & (page - 1U));
                if (count > SUCRUNE_PATH_LIMIT - i) count = SUCRUNE_PATH_LIMIT - i;
            }
            if (!guest_memory(s, current, count, false)) return EFAULT;
            checked = i + count;
        }
        unsigned char c = *(const volatile unsigned char *)(address + i);
        r->data[start + i] = c;
        if (c == 0U) { r->size = (uint32_t)(start + i + 1U); return 0; }
    }
    return ENAMETOOLONG;
}

static int directory_handle(struct shell_state *s, uint64_t fd, const unsigned char *path,
                            int64_t *handle) {
    if (path[0] == '/' || (int32_t)fd == AT_FDCWD) {
        *handle = AT_FDCWD;
        return 0;
    }
    struct sucrune_fd_resource *base = sucrune_fds_get(&s->descriptors, fd);
    if (base == NULL) return EBADF;
    if (base->kind != SUCRUNE_FD_BROKER) return ENOTDIR;
    *handle = base->handle;
    return 0;
}

/* Snapshot exec arguments while the old address space is still live. Every
 * dereference is checked against guest mappings; this signal path never calls
 * strlen on a guest pointer, allocates, or changes mappings/descriptors. */
static int exec_vector(struct shell_state *s, uintptr_t address, const char **values,
        size_t limit, size_t *count) {
    *count = 0;
    if (address == 0U) return 0;
    for (size_t index = 0; index <= limit; index++) {
        size_t offset = index * sizeof(uint64_t);
        if (address > UINTPTR_MAX - offset ||
            !guest_memory(s, address + offset, sizeof(uint64_t), false)) return EFAULT;
        uint64_t pointer;
        copy_bytes((unsigned char *)&pointer, (const void *)(address + offset), sizeof(pointer));
        if (pointer == 0U) return 0;
        if (index == limit) return E2BIG;
        values[index] = s->pending.strings + s->pending.used;
        for (size_t byte = 0; ; byte++) {
            if (s->pending.used == EXEC_STRING_LIMIT) return E2BIG;
            if (pointer > UINTPTR_MAX - byte || !guest_memory(s, (uintptr_t)pointer + byte, 1U, false)) return EFAULT;
            unsigned char value = *(const volatile unsigned char *)((uintptr_t)pointer + byte);
            s->pending.strings[s->pending.used++] = (char)value;
            if (value == 0U) break;
        }
        (*count)++;
    }
    return E2BIG;
}
static int stage_linux_exec(struct shell_state *s, const char *path);
static int64_t prepare_exec(struct shell_state *s, const uint64_t args[6]) {
    if ((unsigned int)s->exec_count >= EXEC_LIMIT) return -ELOOP;
    char path[SUCRUNE_PATH_LIMIT];
    size_t length = 0;
    for (; length < sizeof(path); length++) {
        uintptr_t address = (uintptr_t)args[0];
        if (address > UINTPTR_MAX - length || !guest_memory(s, address + length, 1U, false)) return -EFAULT;
        path[length] = *(const volatile char *)(address + length);
        if (path[length] == '\0') break;
    }
    if (length == sizeof(path)) return -ENAMETOOLONG;
    const struct sucrune_program *program = s->linux_mode ? NULL : sucrune_program_find_path(path);
    if (!s->linux_mode && program == NULL) return -ENOENT;
    if (s->linux_mode) {
        struct sucrune_thread_stats stats = {0};
        sucrune_threads_stats(s->threads, &stats);
        if (sucrune_thread_current() != NULL || stats.created != stats.joined) return -EOPNOTSUPP;
    }
    s->pending.used = 0;
    size_t arg_limit = s->linux_mode ? SUCRUNE_GUEST_EXEC_ARGS : BUNDLED_EXEC_ARGS;
    int error = exec_vector(s, (uintptr_t)args[1], s->pending.argv, arg_limit, &s->pending.argc);
    if (error == 0) error = exec_vector(s, (uintptr_t)args[2], s->pending.envp, SUCRUNE_GUEST_EXEC_ENV, &s->pending.envc);
    if (error != 0) return -error;
    /* Linux accepts an empty argv; give the entry stack a valid empty argv[0]. */
    if (s->pending.argc == 0U) {
        if (s->pending.used == EXEC_STRING_LIMIT) return -E2BIG;
        s->pending.argv[0] = s->pending.strings + s->pending.used;
        s->pending.strings[s->pending.used++] = '\0'; s->pending.argc = 1U;
    }
    if (s->linux_mode) {
        error = stage_linux_exec(s, path);
        if (error != 0) return -error;
    }
    s->pending.program = program;
    s->exec_pending = 1;
    return 0;
}

/* Ordinary transactions carry no descriptors. */
static int64_t exchange(int broker, const struct sucrune_request *r, struct sucrune_response *out) {
    int error = sucrune_broker_exchange(broker, r, out, NULL, 5000);
    return error != 0 ? error : out->result;
}

/* The broker always owns the guest handle. A read-only regular file may also
 * return a capability for the same open description in the open reply. */
static int64_t open_project_file(struct shell_state *s, struct sucrune_request *r,
                                 struct sucrune_response *out, int *read_fd) {
    *read_fd = -1;
    int64_t opened;
    if (s->linux_mode && r->operation != SUCRUNE_BROKER_PROC_NET_OPEN &&
        !(r->args[1] & (O_ACCMODE | O_PATH | O_DIRECTORY))) {
        const bool exec = r->operation == SUCRUNE_BROKER_OPEN_EXEC;
        if (exec) r->args[3] = 1; /* permit a direct snapshot of the authorized executable */
        else r->operation = SUCRUNE_BROKER_OPEN_READ;
        int error = sucrune_broker_exchange(s->broker, r, out, read_fd, 5000);
        if (error != 0) return error;
        opened = out->result;
        if (!exec && opened == -ENOSYS) {
            r->operation = 56U;
            opened = exchange(s->broker, r, out);
        }
    } else opened = exchange(s->broker, r, out);
    if (opened < 0) return opened;
    if (out->size != 0U || opened < SUCRUNE_BROKER_HANDLE_BASE ||
        opened >= SUCRUNE_BROKER_HANDLE_BASE + SUCRUNE_FILE_RESOURCES) {
        if (*read_fd >= 0) (void)close(*read_fd);
        *read_fd = -1;
        return -EPROTO;
    }
    return opened;
}

/* A policy may allow transfer but deny use in the isolated domain. Retry
 * only a denied, zero-progress read through the manager's original OFD. */
static int64_t read_direct(struct shell_state *s, int *fd, void *bytes, size_t count,
                           bool positioned, uint64_t offset) {
    ssize_t got = positioned ? pread(*fd, bytes, count, (off_t)offset) : read(*fd, bytes, count);
    if (got >= 0) {
        s->direct_read_calls++;
        s->direct_read_bytes += (uint64_t)got;
        return got;
    }
    int error = errno;
    if (error == EACCES || error == EPERM || error == EOPNOTSUPP || error == ENOSYS) {
        (void)close(*fd);
        *fd = -1;
    }
    return -error;
}

static int64_t guest_direct_read(struct shell_state *s, int *fd, const uint64_t args[6], bool positioned) {
    size_t count = args[2] > SUCRUNE_BULK_READ_LIMIT ? SUCRUNE_BULK_READ_LIMIT : (size_t)args[2];
    uint64_t offset = positioned ? args[3] : 0;
    /* Match the error order in the small and bulk broker paths. */
    if (count > SUCRUNE_IO_LIMIT && offset > INT64_MAX) return -EINVAL;
    if (count && !guest_memory(s, (uintptr_t)args[1], count, true)) return -EFAULT;
    if (offset > INT64_MAX) return -EINVAL;
    if (offset > (uint64_t)INT64_MAX - count) return -EOVERFLOW;
    /* Zero bytes require no guest pointer, even outside the host user range. */
    char empty;
    void *bytes = count ? (void *)(uintptr_t)args[1] : &empty;
    int64_t got = read_direct(s, fd, bytes, count, positioned, offset);
    if (got > 0) s->guest_direct_read_bytes += (uint64_t)got;
    return got;
}

/* The manager makes one real read on the open description. Packet boundaries
 * are private: Node's readFile treats short regular-file reads as EOF. Keep
 * the guest state lock across the transfer, including the final copy-out. */
static int64_t bulk_file_read(struct shell_state *s, int handle, uint64_t address, uint64_t wanted,
                              bool positioned, uint64_t offset,
                              struct sucrune_request *r, struct sucrune_response *reply) {
    const size_t limit = wanted > SUCRUNE_BULK_READ_LIMIT ? SUCRUNE_BULK_READ_LIMIT : (size_t)wanted;
    if (offset > INT64_MAX) return -EINVAL;
    if (!guest_memory(s, (uintptr_t)address, limit, true)) return -EFAULT;
    r->operation = SUCRUNE_BROKER_BULK_READ;
    r->args[0] = handle; r->args[1] = (int64_t)limit;
    r->args[2] = positioned ? 1 : 0; r->args[3] = (int64_t)offset;
    int64_t total = exchange(s->broker, r, reply);
    if (total < 0) return total;
    int64_t error = -EPROTO;
    if ((uint64_t)total > limit) goto abandon;
    size_t copied = 0, remaining = (size_t)total;
    *r = (struct sucrune_request){.magic=SUCRUNE_BROKER_MAGIC,.operation=SUCRUNE_BROKER_BULK_NEXT};
    for (;;) {
        size_t part = remaining < SUCRUNE_IO_LIMIT ? remaining : SUCRUNE_IO_LIMIT;
        if (reply->size != part) goto abandon;
        copy_bytes((unsigned char *)(uintptr_t)address + copied, reply->data, part);
        copied += part; remaining -= part;
        if (remaining == 0U) return total;
        int64_t n = exchange(s->broker, r, reply);
        if (n < 0) {error=n; goto abandon;}
        if ((uint64_t)n != reply->size) goto abandon;
    }
abandon:
    *r = (struct sucrune_request){.magic=SUCRUNE_BROKER_MAGIC,.operation=SUCRUNE_BROKER_BULK_ABORT};
    (void)exchange(s->broker, r, reply);
    return error;
}

/* Keep the guest state lock across all packets. No regular-file bytes or OFD
 * position are modified until COMMIT, which performs a single kernel write. */
static int64_t bulk_file_write(struct shell_state *s,int handle,uint64_t address,uint64_t wanted,
                               bool positioned,uint64_t offset,
                               struct sucrune_request *r,struct sucrune_response *reply) {
    size_t limit=s->build_profile ? SUCRUNE_BUILD_BULK_WRITE_LIMIT : SUCRUNE_BULK_WRITE_LIMIT;
    size_t total=wanted>limit ? limit : (size_t)wanted;
    if(offset>INT64_MAX) return -EINVAL;
    if(!guest_memory(s,(uintptr_t)address,total,false)) return -EFAULT;
    *r=(struct sucrune_request){.magic=SUCRUNE_BROKER_MAGIC,.operation=SUCRUNE_BROKER_BULK_WRITE,
        .args={handle,(int64_t)total,positioned ? 1 : 0,(int64_t)offset}};
    int64_t result=exchange(s->broker,r,reply);
    if(result<0) return result;
    if(result!=0 || reply->size) goto malformed;
    *r=(struct sucrune_request){.magic=SUCRUNE_BROKER_MAGIC,.operation=SUCRUNE_BROKER_BULK_PUSH};
    for(size_t at=0;at<total;) {
        size_t n=total-at;
        if(n>SUCRUNE_IO_LIMIT) n=SUCRUNE_IO_LIMIT;
        r->args[0]=(int64_t)at;r->size=(uint32_t)n;
        copy_bytes(r->data,(const void *)(uintptr_t)(address+at),n);
        result=exchange(s->broker,r,reply);
        if(result<0) goto abandon;
        if(result!=0 || reply->size) goto malformed;
        at+=n;
    }
    *r=(struct sucrune_request){.magic=SUCRUNE_BROKER_MAGIC,.operation=SUCRUNE_BROKER_BULK_COMMIT};
    result=exchange(s->broker,r,reply);
    if(result>=0 && ((uint64_t)result>total || reply->size)) return -EPROTO;
    return result;
malformed:
    result=-EPROTO;
abandon:
    *r=(struct sucrune_request){.magic=SUCRUNE_BROKER_MAGIC,.operation=SUCRUNE_BROKER_BULK_DROP};
    (void)exchange(s->broker,r,reply);
    return result;
}

/* Fill the loader's private snapshot before publishing executable mappings. */
static int64_t snapshot_read(struct shell_state *s, int handle, int *read_fd, void *bytes, size_t count, uint64_t offset) {
    struct sucrune_request r = { .magic = SUCRUNE_BROKER_MAGIC, .operation = 67U };
    struct sucrune_response response;
    if (offset > INT64_MAX) return -EINVAL;
    if (*read_fd >= 0) {
        if (count > SUCRUNE_BULK_READ_LIMIT) count = SUCRUNE_BULK_READ_LIMIT;
        int64_t result = read_direct(s, read_fd, bytes, count, true, offset);
        if (*read_fd >= 0) return result;
    }
    if (count > SUCRUNE_IO_LIMIT) count = SUCRUNE_IO_LIMIT;
    r.args[0] = handle; r.args[1] = (int64_t)count; r.args[2] = (int64_t)offset;
    int64_t result = exchange(s->broker, &r, &response);
    if (result >= 0) {
        if ((uint64_t)result != response.size || response.size > count) return -EIO;
        copy_bytes(bytes, response.data, response.size);
    }
    return result;
}
static int snapshot_file(struct shell_state *s, const char *path, void **bytes, size_t *size,
                         struct sucrune_script_line *script) {
    *bytes = NULL; *size = 0;
    size_t length = strlen(path);
    if (length == 0U) return ENOENT;
    if (length >= SUCRUNE_PATH_LIMIT) return ENAMETOOLONG;
    struct sucrune_request r = { .magic = SUCRUNE_BROKER_MAGIC, .operation = SUCRUNE_BROKER_OPEN_EXEC };
    struct sucrune_response response;
    r.args[0] = AT_FDCWD; r.args[1] = O_RDONLY; r.size = (uint32_t)(length + 1U);
    memcpy(r.data, path, length + 1U);
    int read_fd;
    int64_t opened = open_project_file(s, &r, &response, &read_fd);
    if (opened < 0) return (int)-opened;
    int error = 0;
    r.operation = 80U; r.size = 0; r.args[0] = opened; r.args[3] = 0;
    int64_t stat_result = exchange(s->broker, &r, &response);
    struct sucrune_arm64_stat st = {0};
    if (stat_result < 0) error = (int)-stat_result;
    else if (stat_result != 0 || response.size != sizeof(st)) error = EIO;
    else {
        memcpy(&st, response.data, sizeof(st));
        if (!sucrune_project_executable(&st, &s->owner)) error = EACCES;
        else if (st.size <= 0) error = ENOEXEC;
    }
    unsigned char header[SUCRUNE_SHEBANG_HEADER];
    size_t done = 0;
    int format = 0;
    if (error == 0 && script != NULL) {
        size_t header_size = (uint64_t)st.size < sizeof(header) ? (size_t)st.size : sizeof(header);
        while (done < header_size) {
            int64_t got = snapshot_read(s, (int)opened, &read_fd, header + done, header_size - done, done);
            if (got <= 0) { error = got < 0 ? (int)-got : ENOEXEC; break; }
            done += (size_t)got;
        }
        if (error == 0) {
            format = sucrune_script_parse(header, done, script);
            if (format < 0) error = -format;
        }
    }
    if (error == 0 && format == 0) {
        if (st.size < (int64_t)sizeof(Elf64_Ehdr) || st.size > SUCRUNE_LINUX_MAX_FILE) error = ENOEXEC;
        else if ((*bytes = malloc((size_t)st.size)) == NULL) error = ENOMEM;
        else if (done != 0) memcpy(*bytes, header, done);
    }
    while (error == 0 && format == 0 && done < (size_t)st.size) {
        size_t count = (size_t)st.size - done;
        int64_t got = snapshot_read(s, (int)opened, &read_fd, (unsigned char *)*bytes + done, count, done);
        if (got <= 0) error = got < 0 ? (int)-got : EIO;
        else done += (size_t)got;
    }
    if (read_fd >= 0) (void)close(read_fd);
    r.operation = SUCRUNE_BROKER_PRIVATE_CLOSE; r.size = 0; r.args[0] = opened;
    int64_t closed = exchange(s->broker, &r, &response);
    if (error == 0 && closed != 0) error = closed < 0 ? (int)-closed : EIO;
    if (error != 0) { free(*bytes); *bytes = NULL; }
    else *size = done;
    return error;
}

static int snapshot_program(struct shell_state *s, const char *path, void **bytes, size_t *size) {
    struct sucrune_script_chain *chain = &s->pending.scripts;
    chain->count = 0;
    for (;;) {
        struct sucrune_script_line line = {0};
        int error = snapshot_file(s, path, bytes, size, &line);
        if (error != 0 || *bytes != NULL) return error;
        if (chain->count == SUCRUNE_SHEBANG_DEPTH) return ELOOP;
        chain->lines[chain->count] = line;
        path = chain->lines[chain->count++].text;
    }
}
static int script_arguments(struct shell_state *s, const char *filename,
        size_t *argc, const char **argv, size_t envc, const char *const *envp) {
    if (s->pending.scripts.count == 0U) return 0;
    const char *prefix[2U * SUCRUNE_SHEBANG_DEPTH + 1U];
    size_t count = sucrune_script_prefix(&s->pending.scripts, filename, prefix);
    if (count > SUCRUNE_GUEST_EXEC_ARGS - (*argc - 1U)) return E2BIG;
    size_t bytes = 0;
    for (size_t i = 0; i < count; i++) bytes += strlen(prefix[i]) + 1U;
    for (size_t i = 1; i < *argc; i++) bytes += strlen(argv[i]) + 1U;
    for (size_t i = 0; i < envc; i++) bytes += strlen(envp[i]) + 1U;
    if (bytes > EXEC_STRING_LIMIT) return E2BIG;
    memmove(argv + count, argv + 1U, (*argc - 1U) * sizeof(*argv));
    memcpy(argv, prefix, count * sizeof(*argv));
    *argc += count - 1U;
    return 0;
}
static int executable_abspath(struct shell_state *s, const char *path, char output[SUCRUNE_PATH_LIMIT]) {
    if (path[0] == '/') { memcpy(output, path, strlen(path) + 1U); return 0; }
    struct sucrune_request request = {.magic=SUCRUNE_BROKER_MAGIC, .operation=17};
    struct sucrune_response response;
    request.args[0] = SUCRUNE_PATH_LIMIT;
    int64_t count = exchange(s->broker, &request, &response);
    if (count <= 0 || count != response.size || response.data[count-1] != 0) return count < 0 ? (int)-count : EIO;
    return snprintf(output, SUCRUNE_PATH_LIMIT, "%s%s%s", (const char *)response.data,
                    count == 2 ? "" : "/", path) >= (int)SUCRUNE_PATH_LIMIT ? ENAMETOOLONG : 0;
}
/* Preflight both immutable images before giving up the old guest PC/stack.
 * The broker resolves relative paths against this execution's own cwd. */
static int stage_linux_exec(struct shell_state *s, const char *path) {
    struct pending_exec *p = &s->pending;
    struct sucrune_linux_plan elf, interp;
    memcpy(p->execfn, path, strlen(path) + 1U);
    int error = snapshot_program(s, path, &p->images[0], &p->image_sizes[0]);
    if (error == 0 && sucrune_linux_validate(p->images[0], p->image_sizes[0], (size_t)s->page, &elf) != SUCRUNE_ELF_OK)
        error = ENOEXEC;
    if (error == 0 && elf.interpreter[0] != '\0') {
        error = snapshot_file(s, elf.interpreter, &p->images[1], &p->image_sizes[1], NULL);
        if (error == 0 && (sucrune_linux_validate(p->images[1], p->image_sizes[1], (size_t)s->page, &interp) != SUCRUNE_ELF_OK ||
            interp.load.fixed_address || interp.interpreter[0] != '\0')) error = ELIBBAD;
    }
    if (error == 0) error = script_arguments(s, p->execfn, &p->argc, p->argv, p->envc, p->envp);
    if (error == 0) error = executable_abspath(s, p->scripts.count ? p->argv[0] : path, p->linux_path);
    if (error == 0 && elf.load.fixed_address) {
        if (s->fixed_space.base == 0U)
            error = -sucrune_space_init_exact(&s->fixed_space, elf.load.virtual_base, elf.load.image_size, (size_t)s->page);
        else error = -sucrune_space_extend_exact(&s->fixed_space, elf.load.virtual_base,
                elf.load.image_size, SUCRUNE_LINUX_MAX_IMAGE);
    }
    if (error != 0) for (size_t i = 0; i < 2; i++) { free(p->images[i]); p->images[i] = NULL; }
    return error;
}

static struct sucrune_guest_space *linux_space(struct shell_state *s, uintptr_t address, size_t length) {
    if (sucrune_space_contains(&s->space, address, length)) return &s->space;
    if (sucrune_space_contains(&s->fixed_space, address, length)) return &s->fixed_space;
    return NULL;
}
static int linux_executable_resume(struct shell_state *s, uintptr_t pc) {
    if (pc < 4U || pc % 4U != 0U) return 0;
    uintptr_t call = pc - 4U;
    const struct sucrune_guest_space *space = linux_space(s, call, 4U);
    if (space == NULL) return 0;
    for (size_t i = 0; i < space->count; i++) {
        const struct sucrune_space_vma *area = &space->areas[i];
        if ((area->protection & PROT_EXEC) && in_range(area->start, area->length, call, 4U)) return 1;
    }
    return 0;
}
static int64_t linux_memory_call(struct shell_state *s, int operation, const uint64_t a[6]) {
    if (operation == 227) {
        if ((a[2] & ~UINT64_C(7)) != 0U) return -EINVAL;
        struct sucrune_guest_space *space = linux_space(s, (uintptr_t)a[0], (size_t)a[1]);
        // The space helper validates flags/alignment even for an empty range,
        // and rejects unmapped addresses by logical VMA coverage, not reservation.
        if (space == NULL) space = &s->space;
        return sucrune_space_sync(space, (uintptr_t)a[0], (size_t)a[1], (unsigned int)a[2]);
    }
    if (operation == 214) {
        uintptr_t desired = (uintptr_t)a[0];
        if (desired < s->linux_brk_base || desired - s->linux_brk_base > 64U * 1024U * 1024U) return (int64_t)s->linux_brk;
        size_t page = (size_t)s->page;
        size_t before = (s->linux_brk - s->linux_brk_base + page - 1U) & ~(page - 1U);
        size_t after = (desired - s->linux_brk_base + page - 1U) & ~(page - 1U);
        int error = 0;
        if (after > before) error = sucrune_space_protect(&s->space, s->linux_brk_base + before, after - before, PROT_READ | PROT_WRITE);
        else if (before > after) {
            error = sucrune_space_discard(&s->space, s->linux_brk_base + after, before - after);
            if (error == 0) error = sucrune_space_protect(&s->space, s->linux_brk_base + after, before - after, PROT_NONE);
        }
        if (error == 0) s->linux_brk = desired;
        return (int64_t)s->linux_brk;
    }
    if (a[1] == 0U || a[1] > s->space.size) return -EINVAL;
    size_t length = (size_t)a[1], page = (size_t)s->page;
    if (length > SIZE_MAX - page + 1U) return -EINVAL;
    size_t rounded = (length + page - 1U) & ~(page - 1U);
    if (operation == 222) {
        unsigned int flags = (unsigned int)a[3];
        if ((flags & MAP_TYPE) == MAP_SHARED) {
            if (a[3] != MAP_SHARED) return -ENOTSUP;
            if ((a[2] & ~(uint64_t)(PROT_READ | PROT_WRITE)) != 0) return -EACCES;
            if (rounded > SUCRUNE_LINUX_MAX_FILE) return -ENOMEM;
            struct sucrune_fd_resource *file = sucrune_fds_get(&s->descriptors, a[4]);
            if (file == NULL) return -EBADF;
            if (file->kind != SUCRUNE_FD_BROKER) return -ENODEV;
            struct sucrune_request request = {.magic = SUCRUNE_BROKER_MAGIC,
                .operation = SUCRUNE_BROKER_MAP_FILE, .args = {file->handle, (a[2] & PROT_WRITE) != 0}};
            struct sucrune_response response;
            int fd = -1;
            int error = sucrune_broker_exchange(s->broker, &request, &response, &fd, 5000);
            if (error != 0) return error;
            if (response.result < 0) return response.result;
            int64_t mapped = sucrune_space_map_shared_file(&s->space, (uintptr_t)a[0],
                length, (int)a[2], fd, a[5]);
            (void)close(fd);
            return mapped;
        }
        const uint64_t supported = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_FIXED_NOREPLACE | MAP_NORESERVE | MAP_STACK | MAP_DENYWRITE;
        if ((a[3] & ~supported) != 0U || !(flags & MAP_PRIVATE) || (a[2] & ~(uint64_t)(PROT_READ | PROT_WRITE | PROT_EXEC))) return -EINVAL;
        if ((a[2] & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC) &&
            (!s->linux_allow_rwx || !(flags & MAP_ANONYMOUS))) return -EACCES;
        flags &= ~(unsigned int)MAP_DENYWRITE;
        struct sucrune_guest_space *space = &s->space;
        if (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) {
            space = linux_space(s, (uintptr_t)a[0], rounded);
            if (space == NULL) return -EINVAL;
        }
        if (flags & MAP_ANONYMOUS) return sucrune_space_map(space, (uintptr_t)a[0], length, page, (int)a[2], flags);
        struct sucrune_fd_resource *resource = sucrune_fds_get(&s->descriptors, a[4]);
        if (resource == NULL) return -EBADF;
        if (resource->kind != SUCRUNE_FD_BROKER) return -ENODEV;
        if (a[5] % page != 0U || a[5] > INT64_MAX - rounded) return -EINVAL;
        if (rounded > SUCRUNE_LINUX_MAX_FILE) return -ENOMEM;
        struct sucrune_request request = { .magic = SUCRUNE_BROKER_MAGIC, .operation = 25U };
        struct sucrune_response response;
        request.args[0] = resource->handle; request.args[1] = F_GETFL;
        int64_t access = exchange(s->broker, &request, &response);
        if (access < 0) return access;
        if (response.size != 0U) return -EIO;
        if ((access & O_ACCMODE) == O_WRONLY) return -EACCES;
        request.operation = 80U;
        int64_t metadata = exchange(s->broker, &request, &response);
        if (metadata < 0) return metadata;
        struct sucrune_arm64_stat st;
        if (metadata != 0 || response.size != sizeof(st)) return -EIO;
        memcpy(&st, response.data, sizeof(st));
        if ((st.mode & 0170000U) != 0100000U) return -ENODEV;
        /* Validate and read before MAP_FIXED can discard a prior guest VMA.
         * This is a private snapshot, not shared/writeback or SIGBUS-on-EOF
         * semantics. The transient host buffer is never guest executable. */
        void *snapshot = mmap(NULL, rounded, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (snapshot == MAP_FAILED) return -errno;
        size_t done = 0;
        int error = 0;
        while (done < rounded) {
            int64_t got = snapshot_read(s, resource->handle, &resource->read_fd,
                                        (unsigned char *)snapshot + done, rounded - done, a[5] + done);
            if (got < 0) { error = (int)got; break; }
            if (got == 0) break;
            done += (size_t)got;
        }
        if (error != 0) { (void)munmap(snapshot, rounded); return error; }
        int64_t mapped = sucrune_space_map(space, (uintptr_t)a[0], length, page, PROT_READ | PROT_WRITE, flags | MAP_ANONYMOUS);
        if (mapped < 0) { (void)munmap(snapshot, rounded); return mapped; }
        memcpy((void *)(uintptr_t)mapped, snapshot, rounded);
        if (munmap(snapshot, rounded) != 0) error = -errno;
        if (error == 0) error = sucrune_space_protect(space, (uintptr_t)mapped, rounded, (int)a[2]);
        if (error == 0) error = sucrune_space_mark_file(space, (uintptr_t)mapped, rounded);
        if (error != 0) { (void)sucrune_space_unmap(space, (uintptr_t)mapped, rounded); return error; }
        return mapped;
    }
    struct sucrune_guest_space *space = linux_space(s, (uintptr_t)a[0], rounded);
    if (space == NULL) return -EINVAL;
    if (operation == 215) return sucrune_space_unmap(space, (uintptr_t)a[0], length);
    if (operation == 226) return sucrune_space_protect(space, (uintptr_t)a[0], length, (int)a[2]);
    if (operation == 233) {
        if (a[2] == MADV_DONTNEED) return sucrune_space_discard(space, (uintptr_t)a[0], length);
        /* Advice does not change data or grant access. Unsupported advice is explicit. */
        if (a[2] == MADV_NORMAL || a[2] == MADV_RANDOM || a[2] == MADV_SEQUENTIAL || a[2] == MADV_WILLNEED)
            return sucrune_space_contains(space, (uintptr_t)a[0], rounded) ? 0 : -ENOMEM;
    }
    return -EINVAL;
}

/* The FD table owns one reference per open description, not per alias. Broker
 * handles never expose host files. Only the original stdin is an owned local
 * descriptor; output PFDs remain borrowed until the worker's Kotlin cleanup. */
static int release_descriptor(void *context, enum sucrune_fd_kind kind, int handle) {
    struct shell_state *s = context;
    if (kind == SUCRUNE_FD_INPUT) {
        s->input = -1;
        if (handle >= 0 && close(handle) != 0) return -errno;
    } else if (kind == SUCRUNE_FD_LOCAL) {
        if (sucrune_proc_has(&s->proc,handle)) {sucrune_proc_close(&s->proc,handle);return 0;}
        enum sucrune_pty_kind terminal=sucrune_pty_kind(&s->ptys,handle);
        if (terminal!=SUCRUNE_PTY_NONE) {
            int64_t dropped=0;
            if (terminal==SUCRUNE_PTY_MASTER) {
                struct sucrune_request drop={.magic=SUCRUNE_BROKER_MAGIC,.operation=SUCRUNE_PTY_MASTER_DROP};
                struct sucrune_response response; drop.args[0]=sucrune_pty_number(&s->ptys,handle);
                dropped=exchange(s->broker,&drop,&response);
            }
            int closed=sucrune_pty_release(&s->ptys,handle);
            return dropped<0 ? (int)dropped : closed;
        }
        if (sucrune_guest_network_contains(&s->network, handle))
            return sucrune_guest_network_release(&s->network, handle);
        if (close(handle) != 0) return -errno;
    } else if (kind == SUCRUNE_FD_BROKER) {
        struct sucrune_request request = { .magic = SUCRUNE_BROKER_MAGIC,
            .operation = sucrune_pty_slave_handle(handle) ? 57U : SUCRUNE_BROKER_PRIVATE_CLOSE };
        struct sucrune_response response;
        request.args[0] = handle;
        int64_t result = exchange(s->broker, &request, &response);
        if (result != 0) return result < 0 ? (int)result : -EIO;
        if (response.size != 0U) return -EIO;
    }
    return 0;
}
static int create_local_alias(void *context, enum sucrune_fd_kind kind, int handle, int *alias) {
    (void)context; *alias = -1;
    if (kind == SUCRUNE_FD_BROKER || handle < 0) return 0;
    int copy = fcntl(handle, F_DUPFD_CLOEXEC, 16);
    if (copy < 0) return -errno;
    *alias = copy; return 0;
}
static int close_local_alias(void *context, enum sucrune_fd_kind kind, int alias) {
    (void)context; (void)kind; return close(alias) == 0 ? 0 : -errno;
}
struct local_call_context { struct shell_state *state; uintptr_t pipe_output; };
static int local_reserve(void *context, size_t count, uintptr_t *reservation) {
    struct shell_state *s = ((struct local_call_context *)context)->state;
    int error = pthread_mutex_lock(&s->state_lock);
    if (error != 0) return -error;
    if (count > s->descriptors.limit - s->descriptors.count || count > s->descriptors.limit - s->descriptors.resource_count) {
        (void)pthread_mutex_unlock(&s->state_lock); return -EMFILE;
    }
    *reservation = count; return 0; /* Retain this short reservation lock. */
}
static int local_commit(void *context, uintptr_t reservation, size_t count,
        const struct sucrune_local_new_fd *descriptors, int32_t *guest_fds) {
    struct local_call_context *call = context;
    struct shell_state *s = call->state;
    if (count != reservation || count == 0U || count > 2U) return -EINVAL;
    if (call->pipe_output != 0U && !guest_memory(s, call->pipe_output, 8U, true)) return -EFAULT;
    int handles[2], status[2]; unsigned int flags[2];
    for (size_t i = 0; i < count; i++) {
        handles[i] = descriptors[i].host_fd; status[i] = descriptors[i].status_flags; flags[i] = descriptors[i].descriptor_flags;
    }
    int result = sucrune_fds_add_batch(&s->descriptors, SUCRUNE_FD_LOCAL, handles, status, flags, count, guest_fds);
    if (result == 0) {
        if (call->pipe_output != 0U) copy_bytes((void *)call->pipe_output, (unsigned char *)guest_fds, 8U);
        (void)pthread_mutex_unlock(&s->state_lock);
    }
    return result;
}
static void local_cancel(void *context, uintptr_t reservation) {
    (void)reservation; struct shell_state *s = ((struct local_call_context *)context)->state; (void)pthread_mutex_unlock(&s->state_lock);
}
static int local_acquire(void *context, const int32_t *descriptors, size_t count,
        enum sucrune_local_pin_mode mode, struct sucrune_local_pin *pins) {
    struct shell_state *s = ((struct local_call_context *)context)->state;
    int error = pthread_mutex_lock(&s->state_lock);
    if (error != 0) return -error;
    for (size_t i = 0; i < count; i++) {
        int alias = sucrune_fds_alias(&s->descriptors, (uint64_t)(int64_t)descriptors[i]);
        if (alias==-ENOTSUP) {
            struct sucrune_fd_resource *r=sucrune_fds_get(&s->descriptors,(uint64_t)(int64_t)descriptors[i]);
            if (r != NULL && r->kind == SUCRUNE_FD_BROKER) {
                if (sucrune_pty_slave_handle(r->handle))
                    alias = sucrune_pty_session_poll_fd(s->broker, r->handle);
                else if (r->handle >= (int)SUCRUNE_BROKER_HANDLE_BASE &&
                         r->handle < (int)(SUCRUNE_BROKER_HANDLE_BASE + SUCRUNE_FILE_RESOURCES))
                    alias = sucrune_local_file_poll_fd(r->status_flags);
                /* Stable readiness alias only. Data and metadata stay in the broker. */
                if (alias >= 0) s->descriptors.entries[descriptors[i]].host_alias = alias;
            }
        }
        pins[i] = (struct sucrune_local_pin){.host_fd = alias, .error = alias < 0 ? alias : 0};
        if (alias >= 0 && mode == SUCRUNE_LOCAL_RETAINED_WAIT) {
            pins[i].host_fd = fcntl(alias, F_DUPFD_CLOEXEC, 16);
            if (pins[i].host_fd < 0) pins[i].error = -errno;
        }
    }
    if (mode == SUCRUNE_LOCAL_RETAINED_WAIT) (void)pthread_mutex_unlock(&s->state_lock);
    return 0;
}
static void local_release(void *context, enum sucrune_local_pin_mode mode, struct sucrune_local_pin *pins, size_t count) {
    struct shell_state *s = ((struct local_call_context *)context)->state;
    if (mode == SUCRUNE_LOCAL_STABLE_CTL) (void)pthread_mutex_unlock(&s->state_lock);
    else for (size_t i = 0; i < count; i++) if (pins[i].host_fd >= 0) (void)close(pins[i].host_fd);
}
static struct sucrune_local_io local_io(struct local_call_context *context) {
    return (struct sucrune_local_io){.context = context, .ops = {
        .reserve = local_reserve, .commit = local_commit, .cancel = local_cancel,
        .acquire_many = local_acquire, .release_many = local_release}};
}

static int publish_terminal(struct shell_state *s, int fd, uint64_t flags) {
    if (fd < 0) return fd;
    int descriptor=sucrune_fds_add(&s->descriptors,SUCRUNE_FD_LOCAL,fd,
        (int)(flags & (O_ACCMODE|O_NONBLOCK)),(flags & O_CLOEXEC)!=0U ? SUCRUNE_FD_CLOEXEC : 0U);
    if (descriptor<0) (void)release_descriptor(s,SUCRUNE_FD_LOCAL,fd);
    return descriptor;
}
static int broker_terminal_open(struct shell_state *s,int number,uint64_t flags,bool master) {
    struct sucrune_request request={.magic=SUCRUNE_BROKER_MAGIC,.operation=master?SUCRUNE_PTY_MASTER_OPEN:SUCRUNE_PTY_SLAVE_OPEN};
    struct sucrune_response response;
    request.args[0]=master?(int64_t)flags:number; request.args[1]=master?0:(int64_t)flags;
    int fd=-1;
    int err=sucrune_broker_exchange(s->broker,&request,&response,master?&fd:NULL,5000);
    if (err!=0) return err;
    if (response.result<0) return (int)response.result;
    if (master) {
        if (fd<0 || response.result>INT_MAX) {if(fd>=0)(void)close(fd);return -EPROTO;}
        err=sucrune_pty_adopt(&s->ptys,fd,SUCRUNE_PTY_MASTER,(int)response.result);
        if (err!=0) {
            (void)close(fd);request=(struct sucrune_request){.magic=SUCRUNE_BROKER_MAGIC,.operation=SUCRUNE_PTY_MASTER_DROP,.args={response.result}};
            (void)exchange(s->broker,&request,&response);return err;
        }
        return publish_terminal(s,fd,flags);
    }
    if (!sucrune_pty_slave_handle(response.result)) return -EPROTO;
    fd=(int)response.result;
    int descriptor=sucrune_fds_add(&s->descriptors,SUCRUNE_FD_BROKER,fd,(int)(flags & (O_ACCMODE|O_NONBLOCK)),
        (flags & O_CLOEXEC)!=0U ? SUCRUNE_FD_CLOEXEC : 0U);
    if (descriptor<0) (void)release_descriptor(s,SUCRUNE_FD_BROKER,fd);
    return descriptor;
}
static int broker_slave_ioctl(struct shell_state *s,int handle,uint64_t cmd,uint64_t arg) {
    struct sucrune_pty_request plan;
    int err=sucrune_pty_plan(SUCRUNE_PTY_SLAVE,cmd,&plan);
    if (err!=0) return err;
    struct sucrune_request r={.magic=SUCRUNE_BROKER_MAGIC,.operation=SUCRUNE_PTY_IOCTL,.args={handle,(int64_t)cmd}};
    struct sucrune_response reply;
    if (plan.size>SUCRUNE_PTY_BUFFER) return -EIO;
    bool get=plan.argument==SUCRUNE_PTY_GET;
    if (plan.size!=0U && !guest_memory(s,(uintptr_t)arg,plan.size,get)) return -EFAULT;
    if (cmd==TIOCSCTTY || cmd==TIOCGSID || cmd==TIOCGPGRP || cmd==TIOCSPGRP) {
        int value=0;
        if (cmd==TIOCSPGRP) {
            copy_bytes((unsigned char *)&value,(void *)(uintptr_t)arg,sizeof(value));
        }
        err=sucrune_pty_session_control(s->broker,handle,cmd,cmd==TIOCSCTTY ? arg : 0U,&value,s->processes);
        if (err==0 && get) copy_bytes((void *)(uintptr_t)arg,(unsigned char *)&value,sizeof(value));
        return err;
    }
    if (!get && plan.size!=0U) {copy_bytes(r.data,(void *)(uintptr_t)arg,plan.size);r.size=(uint32_t)plan.size;}
    if (plan.argument==SUCRUNE_PTY_SCALAR) r.args[2]=(int64_t)arg;
    int64_t result=exchange(s->broker,&r,&reply);
    if (result<0) return (int)result;
    if (reply.size!=(get ? plan.size : 0U)) return -EPROTO;
    if (get) copy_bytes((void *)(uintptr_t)arg,reply.data,plan.size);
    return 0;
}
/* Keep the original slave's OFD for every read/write and its real EOF. A
 * verified alias of this controlling terminal is only a kernel wakeup source.
 * A closed/reused guest descriptor or a replaced VMA cannot redirect copyout. */
static int64_t broker_slave_io(struct shell_state *s,uint64_t fd,bool writing,uintptr_t address,size_t count) {
    int id=sucrune_fds_hold(&s->descriptors,fd);
    if (id<0) return id;
    int handle=s->descriptors.resources[id].handle,ready=-1;
    struct sucrune_request op={.magic=SUCRUNE_BROKER_MAGIC,.operation=writing ? 64U : 63U,.args={handle,(int64_t)count}};
    struct sucrune_response reply;
    if (writing) {op.size=(uint32_t)count;copy_bytes(op.data,(const void *)address,count);}
    int64_t result;
    for (;;) {
        result=exchange(s->broker,&op,&reply);
        if (result!=-EAGAIN) break;
        struct sucrune_request fl={.magic=SUCRUNE_BROKER_MAGIC,.operation=25U,.args={handle,F_GETFL}};
        int64_t status=exchange(s->broker,&fl,&reply);
        if (status<0) {result=status;break;}
        if ((status&O_NONBLOCK)!=0) break;
        if (ready<0) ready=sucrune_pty_session_poll_fd(s->broker,handle);
        if (ready<0) {result=ready==-ENXIO || ready==-ENOTTY ? -EOPNOTSUPP : ready;break;}
        struct pollfd wait={.fd=ready,.events=writing ? POLLOUT : POLLIN};
        (void)pthread_mutex_unlock(&s->state_lock);
        int n=poll(&wait,1,-1);int saved=errno;
        (void)pthread_mutex_lock(&s->state_lock);
        if (n<0) {result=-saved;break;}
        if (!writing && count != 0U && !guest_memory(s,address,count,true)) {result=-EFAULT;break;}
    }
    if (result>=0) {
        if ((uint64_t)result>count || reply.size!=(writing ? 0U : (uint32_t)result)) result=-EPROTO;
        else if (!writing && result>0) copy_bytes((void *)address,reply.data,(size_t)result);
    }
    if (ready>=0) (void)close(ready);
    int dropped=sucrune_fds_drop(&s->descriptors,(unsigned int)id);
    return dropped<0 && result==0 ? dropped : result;
}
/* The project network exposes a loopback interface. Never return the phone's
 * interface list, addresses, hardware identifiers or a host pointer. */
static int network_interface_query(struct shell_state *s, unsigned long cmd, uintptr_t argument) {
    struct ifreq interface = {0};
    struct sockaddr_in address = {.sin_family=AF_INET, .sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    if (cmd == SIOCGIFCONF) {
        struct ifconf config;
        if (!guest_memory(s, argument, sizeof(config), false) || !guest_memory(s, argument, sizeof(config), true))
            return -EFAULT;
        memcpy(&config, (const void *)argument, sizeof(config));
        /* A null pointer is a size query. OpenJDK leaves ifc_len uninitialized
         * in this call, as the kernel ignores its incoming value. */
        if (config.ifc_buf == NULL) config.ifc_len=(int)sizeof(interface);
        else if (config.ifc_len < 0) return -EINVAL;
        else if ((size_t)config.ifc_len < sizeof(interface)) config.ifc_len=0;
        else {
            if (!guest_memory(s,(uintptr_t)config.ifc_buf,sizeof(interface),true)) return -EFAULT;
            memcpy(interface.ifr_name,"lo",3);
            memcpy(&interface.ifr_addr,&address,sizeof(address));
            memcpy(config.ifc_buf,&interface,sizeof(interface));
            config.ifc_len=(int)sizeof(interface);
        }
        memcpy((void *)argument,&config,sizeof(config));
        return 0;
    }
    switch (cmd) {
        case SIOCGIFNAME: case SIOCGIFINDEX: case SIOCGIFFLAGS: case SIOCGIFADDR:
        case SIOCGIFNETMASK: case SIOCGIFMTU: case SIOCGIFHWADDR: break;
        default: return -ENOTTY;
    }
    if (!guest_memory(s,argument,sizeof(interface),false) || !guest_memory(s,argument,sizeof(interface),true))
        return -EFAULT;
    memcpy(&interface,(const void *)argument,sizeof(interface));
    if (cmd == SIOCGIFNAME) {
        if (interface.ifr_ifindex != 1) return -ENODEV;
        memset(interface.ifr_name,0,IFNAMSIZ);
        memcpy(interface.ifr_name,"lo",3);
    } else {
        if (strncmp(interface.ifr_name,"lo",IFNAMSIZ) != 0) return -ENODEV;
        switch (cmd) {
            case SIOCGIFINDEX: interface.ifr_ifindex=1; break;
            case SIOCGIFFLAGS: interface.ifr_flags=IFF_UP|IFF_RUNNING|IFF_LOOPBACK; break;
            case SIOCGIFMTU: interface.ifr_mtu=65536; break;
            case SIOCGIFHWADDR:
                memset(&interface.ifr_hwaddr,0,sizeof(interface.ifr_hwaddr));
                interface.ifr_hwaddr.sa_family=ARPHRD_LOOPBACK;
                break;
            case SIOCGIFNETMASK: address.sin_addr.s_addr=htonl(0xff000000U); /* fall through */
            case SIOCGIFADDR: memcpy(&interface.ifr_addr,&address,sizeof(address)); break;
        }
    }
    memcpy((void *)argument,&interface,sizeof(interface));
    return 0;
}

static int terminal_ioctl(struct shell_state *s, int fd, enum sucrune_pty_kind kind, uint64_t cmd, uint64_t arg) {
    struct sucrune_pty_request plan;
    int error=sucrune_pty_plan(kind,cmd,&plan);
    if (error!=0) return error;
    if (plan.argument==SUCRUNE_PTY_OPEN_PEER) {
        int available=sucrune_fds_available(&s->descriptors);
        return available<0 ? available : broker_terminal_open(s,sucrune_pty_number(&s->ptys,fd),arg,false);
    }
    union { int32_t pid; unsigned char bytes[SUCRUNE_PTY_BUFFER]; } data={0};
    if (plan.size>sizeof(data.bytes)) return -EIO;
    bool get=plan.argument==SUCRUNE_PTY_GET;
    if (plan.size!=0U && !guest_memory(s,(uintptr_t)arg,plan.size,get)) return -EFAULT;
    if (!get && plan.size!=0U) copy_bytes(data.bytes,(const void *)(uintptr_t)arg,plan.size);
    if (plan.argument==SUCRUNE_PTY_SET_GROUP)
        return sucrune_processes_set_foreground(s->processes,fd,data.pid);
    if (plan.may_wait) {
        int pin=fcntl(fd,F_DUPFD_CLOEXEC,16);
        if (pin<0) return -errno;
        (void)pthread_mutex_unlock(&s->state_lock);
        error=sucrune_pty_apply(kind,pin,cmd,arg,data.bytes,plan.size,0);
        (void)close(pin);
        (void)pthread_mutex_lock(&s->state_lock);
    } else error=sucrune_pty_apply(kind,fd,cmd,arg,data.bytes,plan.size,0);
    if (error==0 && get) {
        if (!guest_memory(s,(uintptr_t)arg,plan.size,true)) return -EFAULT;
        copy_bytes((void *)(uintptr_t)arg,data.bytes,plan.size);
    }
    return error;
}
static int publish_network_descriptor(struct shell_state *s, int handle, int flags) {
    if (handle < 0) return handle;
    int descriptor = sucrune_fds_add(&s->descriptors, SUCRUNE_FD_LOCAL, handle,
        O_RDWR | ((flags & SOCK_NONBLOCK) != 0 ? O_NONBLOCK : 0),
        (flags & SOCK_CLOEXEC) != 0 ? SUCRUNE_FD_CLOEXEC : 0U);
    if (descriptor < 0) (void)sucrune_guest_network_release(&s->network, handle);
    return descriptor;
}

static int record_descriptor_closed(void *context,enum sucrune_fd_kind kind,int handle) {
    struct shell_state *s=context;
    if (!s->may_have_record_locks || kind!=SUCRUNE_FD_BROKER || sucrune_pty_slave_handle(handle)) return 0;
    struct sucrune_request request={.magic=SUCRUNE_BROKER_MAGIC,.operation=SUCRUNE_BROKER_RECORD_CLOSE,.args={handle}};
    struct sucrune_response response;
    int64_t result=exchange(s->broker,&request,&response);
    return result<0 ? (int)result : (result==0 && !response.size ? 0 : -EPROTO);
}
static int64_t guest_record_lock(struct shell_state *s,const uint64_t args[6],struct sucrune_fd_resource *resource) {
    if (resource->kind!=SUCRUNE_FD_BROKER || sucrune_pty_slave_handle(resource->handle)) return -EOPNOTSUPP;
    uintptr_t address=(uintptr_t)args[2];
    bool query=args[1]==F_GETLK;
    if (!guest_memory(s,address,sizeof(struct sucrune_record_lock),false) ||
        (query && !guest_memory(s,address,sizeof(struct sucrune_record_lock),true))) return -EFAULT;
    struct sucrune_request request={.magic=SUCRUNE_BROKER_MAGIC,.operation=SUCRUNE_BROKER_RECORD_LOCK,
        .args={resource->handle,query ? F_GETLK : F_SETLK,getpid()},.size=sizeof(struct sucrune_record_lock)};
    struct sucrune_response response;
    copy_bytes(request.data,(const void *)address,request.size);
    int held=sucrune_fds_hold(&s->descriptors,args[0]);
    if (held<0) return held;
    const struct timespec delay={.tv_nsec=10000000};
    int64_t result;
    for (;;) {
        result=exchange(s->broker,&request,&response);
        if (args[1]!=F_SETLKW || result!=-EAGAIN) break;
        if (response.size!=request.size) {result=-EPROTO;break;}
        copy_bytes(request.data,response.data,request.size);
        (void)pthread_mutex_unlock(&s->state_lock);
        (void)nanosleep(&delay,NULL);
        (void)pthread_mutex_lock(&s->state_lock);
        collect_child_signal(s);
        struct sucrune_signal_thread *signals=current_signals(s);
        if (signals->pending & ~signals->mask) {result=-EINTR;break;}
        if (sucrune_fds_get(&s->descriptors,args[0])!=resource) {result=-EBADF;break;}
    }
    if (result==0) {
        if (response.size!=(query ? sizeof(struct sucrune_record_lock) : 0U)) result=-EPROTO;
        else if (query) copy_bytes((void *)address,response.data,response.size);
        else s->may_have_record_locks=true;
    }
    int dropped=sucrune_fds_drop(&s->descriptors,(unsigned int)held);
    return result==0 && dropped<0 ? dropped : result;
}
static int64_t descriptor_fcntl(struct shell_state *s, const uint64_t args[6]) {
    struct sucrune_fd_resource *resource = sucrune_fds_get(&s->descriptors, args[0]);
    if (resource == NULL) return -EBADF;
    if (s->linux_mode && (args[1]==F_GETLK || args[1]==F_SETLK || args[1]==F_SETLKW))
        return guest_record_lock(s,args,resource);
    if (args[1] == F_GETFD) return sucrune_fds_get_flags(&s->descriptors, args[0]);
    if (args[1] == F_SETFD) return sucrune_fds_set_flags(&s->descriptors, args[0], args[2]);
    if (args[1] == F_DUPFD || args[1] == F_DUPFD_CLOEXEC)
        return sucrune_fds_duplicate(&s->descriptors, args[0], args[2], args[1] == F_DUPFD_CLOEXEC ? 1U : 0U);
    if (args[1] != F_GETFL && args[1] != F_SETFL) return -EINVAL;
    if (s->linux_mode && resource->kind != SUCRUNE_FD_BROKER && resource->handle >= 0) {
        if (args[1] == F_SETFL && (args[2] & ~(uint64_t)(O_ACCMODE | O_APPEND | O_NONBLOCK | O_LARGEFILE | O_CLOEXEC)) != 0U) return -EINVAL;
        int network_type = sucrune_guest_network_type(&s->network, resource->handle);
        if (network_type == SOCK_DGRAM || network_type == SOCK_STREAM) {
            int physical = fcntl(resource->handle, F_GETFL);
            if (physical < 0) return -errno;
            if (args[1] == F_GETFL) return (physical & ~O_NONBLOCK) | (resource->status_flags & O_NONBLOCK);
            if (fcntl(resource->handle, F_SETFL, (int)args[2] | O_NONBLOCK) != 0) return -errno;
            resource->status_flags = (resource->status_flags & ~(O_NONBLOCK | O_APPEND)) | (int)(args[2] & (O_NONBLOCK | O_APPEND));
            return 0;
        }
        int result = fcntl(resource->handle, (int)args[1], (int)args[2]);
        return result < 0 ? -errno : result;
    }
    if (resource->kind == SUCRUNE_FD_BROKER) {
        struct sucrune_request request = { .magic = SUCRUNE_BROKER_MAGIC, .operation = 25U };
        struct sucrune_response response;
        request.args[0] = resource->handle;
        request.args[1] = (int64_t)args[1]; request.args[2] = (int64_t)args[2];
        int64_t result = exchange(s->broker, &request, &response);
        return result >= 0 && response.size != 0U ? -EIO : result;
    }
    if (args[1] == F_GETFL) return resource->status_flags;
    /* Only O_APPEND is mutable in this bounded backend. Access/open-time bits
     * are ignored as on Linux; guest nonblocking/asynchronous modes are absent. */
    const uint64_t allowed = O_ACCMODE | O_APPEND | O_LARGEFILE | O_CREAT | O_EXCL |
        O_TRUNC | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW | O_DIRECTORY;
    if ((args[2] & ~allowed) != 0U) return -EINVAL;
    resource->status_flags = (resource->status_flags & ~O_APPEND) | (int)(args[2] & O_APPEND);
    return 0;
}

/* The broker owns a nonblocking socket. A guest blocking call sleeps on
 * the same open description without stopping the other guest threads. */
static int wait_stream_ready(struct shell_state *s, uint64_t fd, struct sucrune_fd_resource *resource, short events) {
    int held = sucrune_fds_hold(&s->descriptors, fd);
    if (held < 0) return held;
    struct pollfd item = {.fd = resource->handle, .events = events};
    int result = 0;
    for (;;) {
        collect_child_signal(s);
        struct sucrune_signal_thread *signals = current_signals(s);
        if (signals->pending & ~signals->mask) { result = -EINTR; break; }
        (void)pthread_mutex_unlock(&s->state_lock);
        int ready = poll(&item, 1, 100);
        int saved = errno;
        (void)pthread_mutex_lock(&s->state_lock);
        if (sucrune_fds_get(&s->descriptors, fd) != resource) { result = -EBADF; break; }
        if (ready < 0) { result = -saved; break; }
        if (ready > 0) {
            if (item.revents & POLLNVAL) result = -EBADF;
            break;
        }
    }
    int dropped = sucrune_fds_drop(&s->descriptors, (unsigned int)held);
    return result < 0 ? result : dropped;
}

struct sucrune_arm64_msghdr {
    uint64_t name;
    uint32_t name_length, padding;
    uint64_t vectors, vector_count, control, control_length;
    uint32_t flags, tail_padding;
};
_Static_assert(sizeof(struct sucrune_arm64_msghdr) == 56U, "ARM64 msghdr ABI");

static int guest_message_vectors(struct shell_state *s, const struct sucrune_arm64_msghdr *wire,
        bool receiving, struct iovec *vectors, uint64_t *total_bytes) {
    struct {uint64_t pointer, length;} item;
    if (wire->vector_count > 1024U) return -EMSGSIZE;
    size_t count = (size_t)wire->vector_count;
    if (count != 0U && !guest_memory(s, (uintptr_t)wire->vectors, count * sizeof(item), false)) return -EFAULT;
    uint64_t total = 0U;
    for (size_t index = 0; index < count; index++) {
        copy_bytes((unsigned char *)&item, (const void *)(uintptr_t)(wire->vectors + index * sizeof(item)), sizeof(item));
        if (item.length > INT64_MAX - total) return -EMSGSIZE;
        if (item.length != 0U && !guest_memory(s, (uintptr_t)item.pointer, (size_t)item.length, receiving)) return -EFAULT;
        vectors[index] = (struct iovec){.iov_base = (void *)(uintptr_t)item.pointer, .iov_len = (size_t)item.length};
        total += item.length;
    }
    *total_bytes = total;
    return 0;
}

/* Only connected payload I/O is admitted. Never pass a guest sockaddr,
 * ancillary data, or unvalidated guest iovec to the host socket. */
static int64_t guest_stream_message(struct shell_state *s, int operation, uint64_t *args,
        const struct sucrune_arm64_msghdr *vector_request) {
    bool receiving = operation == 212;
    int allowed = MSG_DONTWAIT | (receiving ? MSG_PEEK : MSG_NOSIGNAL | MSG_MORE);
    if ((args[2] & ~(uint64_t)allowed) != 0U) return -EOPNOTSUPP;
    for (;;) {
        struct sucrune_fd_resource *resource = sucrune_fds_get(&s->descriptors, args[0]);
        if (resource == NULL) return -EBADF;
        if (resource->kind != SUCRUNE_FD_LOCAL ||
            sucrune_guest_network_type(&s->network, resource->handle) != SOCK_STREAM) return -ENOTSOCK;
        struct sucrune_arm64_msghdr wire;
        if (vector_request != NULL) wire = *vector_request;
        else {
            if (!guest_memory(s, (uintptr_t)args[1], sizeof(wire), false) ||
                (receiving && !guest_memory(s, (uintptr_t)args[1], sizeof(wire), true))) return -EFAULT;
            copy_bytes((unsigned char *)&wire, (const void *)(uintptr_t)args[1], sizeof(wire));
        }
        if (wire.name || wire.name_length || wire.control || wire.control_length) return -EOPNOTSUPP;
        struct iovec vectors[1024];
        uint64_t total;
        int checked = guest_message_vectors(s, &wire, receiving, vectors, &total);
        if (checked < 0) return checked;
        struct msghdr message = {.msg_iov = vectors, .msg_iovlen = (size_t)wire.vector_count};
        int flags = (int)args[2] | MSG_DONTWAIT;
        ssize_t result = receiving ? recvmsg(resource->handle, &message, flags) :
            sendmsg(resource->handle, &message, flags | MSG_NOSIGNAL);
        if (result >= 0) {
            if (receiving && vector_request == NULL) {
                uint32_t flags_out = (uint32_t)message.msg_flags;
                copy_bytes((unsigned char *)(uintptr_t)args[1] + offsetof(struct sucrune_arm64_msghdr, flags),
                    (const unsigned char *)&flags_out, sizeof(flags_out));
            }
            return result;
        }
        int error = errno;
        if (error != EAGAIN || (args[2] & MSG_DONTWAIT) || (resource->status_flags & O_NONBLOCK)) return -error;
        /* wait_stream_ready pins the description and releases state_lock.
         * Re-read and validate all guest pointers before another attempt. */
        int ready = wait_stream_ready(s, args[0], resource, receiving ? POLLIN : POLLOUT);
        if (ready < 0) return ready;
    }
}

/* All admitted IP sockets are nonblocking. Keep the state lock across these
 * short calls so the canonical token cannot disappear/reuse between routing,
 * packet I/O and source normalization. Never copy a private DNS address out. */
static int64_t guest_datagram(struct shell_state *s, int operation, uint64_t *args,
        const struct sucrune_arm64_msghdr *vector_request) {
retry:
    ;
    struct sucrune_fd_resource *resource = sucrune_fds_get(&s->descriptors, args[0]);
    if (resource == NULL) return -EBADF;
    if (resource->kind != SUCRUNE_FD_LOCAL || sucrune_guest_network_type(&s->network, resource->handle) != SOCK_DGRAM)
        return -EOPNOTSUPP;
    if (operation == 269) { /* sendmmsg: preserve Linux partial-success semantics. */
        if (args[2] > 1024U) return -EINVAL;
        for (uint64_t index = 0; index < args[2]; index++) {
            uintptr_t item = (uintptr_t)args[1] + (uintptr_t)index * 64U;
            int64_t result;
            if (item < args[1] || !guest_memory(s, item, 60U, true)) result = -EFAULT;
            else {
                uint64_t call[6] = {args[0], item, args[3], 0U, 0U, 0U};
                result = guest_datagram(s, 211, call, NULL);
                if (result >= 0) {
                    if (!guest_memory(s, item + 56U, sizeof(uint32_t), true)) return index ? (int64_t)index : -EFAULT;
                    uint32_t written = (uint32_t)result;
                    copy_bytes((void *)(item + 56U), (const unsigned char *)&written, sizeof(written));
                }
            }
            if (result < 0) return index != 0U ? (int64_t)index : result;
        }
        return (int64_t)args[2];
    }
    bool receiving = operation == 207 || operation == 212;
    bool message_call = operation == 211 || operation == 212;
    uint64_t flags = args[message_call ? 2 : 3];
    int allowed = receiving ? MSG_DONTWAIT | MSG_PEEK | MSG_TRUNC : MSG_DONTWAIT | MSG_NOSIGNAL;
    if ((flags & ~(uint64_t)allowed) != 0U) return -EOPNOTSUPP;
    bool blocking = (resource->status_flags & O_NONBLOCK) == 0 && (flags & MSG_DONTWAIT) == 0U;
    int echo_domain = sucrune_guest_network_echo_domain(&s->network, resource->handle);
    if (blocking && !s->build_profile && !echo_domain) return -EOPNOTSUPP;
    struct iovec vectors[1024];
    struct sucrune_arm64_msghdr wire = {0};
    uint64_t address_pointer = args[4];
    uint32_t address_capacity = 0;
    size_t vector_count = 1U;
    uint64_t total_bytes = 0U;
    if (message_call) {
        if (vector_request != NULL) wire = *vector_request;
        else {
            if (!guest_memory(s, (uintptr_t)args[1], sizeof(wire), false) ||
                (receiving && !guest_memory(s, (uintptr_t)args[1], sizeof(wire), true))) return -EFAULT;
            copy_bytes((unsigned char *)&wire, (const void *)(uintptr_t)args[1], sizeof(wire));
        }
        if (wire.control_length != 0U) return -EOPNOTSUPP;
        int checked = guest_message_vectors(s, &wire, receiving, vectors, &total_bytes);
        if (checked < 0) return checked;
        vector_count = (size_t)wire.vector_count;
        address_pointer = wire.name;
        address_capacity = wire.name_length;
    } else {
        if (args[2] > INT64_MAX) return -EMSGSIZE;
        if (args[2] != 0U && !guest_memory(s, (uintptr_t)args[1], (size_t)args[2], receiving)) return -EFAULT;
        vectors[0] = (struct iovec){.iov_base = (void *)(uintptr_t)args[1], .iov_len = (size_t)args[2]};
        total_bytes = args[2];
        if (address_pointer != 0U) {
            if (receiving) {
                if (!guest_memory(s, (uintptr_t)args[5], sizeof(uint32_t), false) ||
                    !guest_memory(s, (uintptr_t)args[5], sizeof(uint32_t), true)) return -EFAULT;
                copy_bytes((unsigned char *)&address_capacity, (const void *)(uintptr_t)args[5], sizeof(address_capacity));
            } else {
                if (args[5] > SUCRUNE_SOCKET_ADDRESS_LIMIT) return -EINVAL;
                address_capacity = (uint32_t)args[5];
            }
        }
    }
    if (address_capacity > INT32_MAX) return -EINVAL;
    int udp_state = sucrune_guest_network_udp_state(&s->network, resource->handle);
    if (udp_state < 0) return udp_state;
    if (receiving && (udp_state & SUCRUNE_UDP_BOUND) == 0) return -EAGAIN;
    if (!receiving && address_pointer == 0U && (udp_state & SUCRUNE_UDP_CONNECTED) == 0) return -EDESTADDRREQ;
    struct sockaddr_storage address;
    size_t routed_length = sizeof(address);
    if (!receiving && address_pointer != 0U) {
        if (address_capacity > sizeof(address)) return -EINVAL;
        if (address_capacity != 0U && !guest_memory(s, (uintptr_t)address_pointer, address_capacity, false)) return -EFAULT;
        if (echo_domain) {
            copy_bytes((unsigned char *)&address, (const void *)(uintptr_t)address_pointer, address_capacity);
            routed_length = address_capacity;
        } else {
            unsigned char guest_address[SUCRUNE_SOCKET_ADDRESS_LIMIT];
            if (address_capacity > sizeof(guest_address)) return -EINVAL;
            copy_bytes(guest_address, (const void *)(uintptr_t)address_pointer, address_capacity);
            int routed = sucrune_guest_network_route(&s->network, resource->handle, 0,
                guest_address, address_capacity, &address, sizeof(address), &routed_length);
            if (routed != 0) return routed;
            if (routed_length > sizeof(address)) return -EIO;
        }
    }
    struct msghdr message = {
        .msg_name = receiving || address_pointer != 0U ? &address : NULL,
        .msg_namelen = receiving ? sizeof(address) : address_pointer != 0U ? (socklen_t)routed_length : 0U,
        .msg_iov = vectors, .msg_iovlen = vector_count,
    };
    struct iovec staged = {.iov_base = s->datagram_buffer,
        .iov_len = total_bytes < sizeof(s->datagram_buffer) ? (size_t)total_bytes : sizeof(s->datagram_buffer)};
    if (receiving) {message.msg_iov = &staged; message.msg_iovlen = 1U;}
    ssize_t result;
    if (echo_domain) {
        result = sucrune_guest_network_echo_message(&s->network, resource->handle, receiving, &message, (int)flags);
    } else {
        result = receiving ? recvmsg(resource->handle, &message, (int)flags | MSG_DONTWAIT) :
            sendmsg(resource->handle, &message, (int)flags | MSG_DONTWAIT | MSG_NOSIGNAL);
        if (result < 0) result = -errno;
    }
    if (result == -EAGAIN && blocking) {
        /* Pin the open description, not its guest fd number. Never wait
         * under the process state lock or retain guest pointers across it. */
        int held = sucrune_fds_hold(&s->descriptors, args[0]);
        if (held < 0) return held;
        struct pollfd wait = {.fd=resource->handle, .events=receiving ? POLLIN : POLLOUT};
        (void)pthread_mutex_unlock(&s->state_lock);
        /* Another JVM thread may close or replace this number to wake a
         * DatagramSocket receiver. Our retained OFD itself cannot signal
         * that close, so recheck the guest descriptor periodically. */
        int ready = poll(&wait, 1, 100);
        int saved = errno;
        (void)pthread_mutex_lock(&s->state_lock);
        bool same = sucrune_fds_get(&s->descriptors, args[0]) == resource;
        int dropped = sucrune_fds_drop(&s->descriptors, (unsigned int)held);
        if (ready < 0) return -saved;
        if (!same) return -EBADF;
        if (dropped < 0) return dropped;
        goto retry;
    }
    if (result < 0) return result;
    if (receiving) {
        unsigned char guest_address[SUCRUNE_SOCKET_ADDRESS_LIMIT];
        size_t guest_length = message.msg_namelen;
        if (guest_length > sizeof(address)) return -EIO;
        if (echo_domain) {
            if (guest_length > sizeof(guest_address)) return -EIO;
            memcpy(guest_address, &address, guest_length);
        } else {
            int routed = sucrune_guest_network_route(&s->network, resource->handle, 1,
                &address, message.msg_namelen, guest_address, sizeof(guest_address), &guest_length);
            if (routed != 0) return routed;
            if (guest_length > sizeof(guest_address)) return -EIO;
        }
        if (address_pointer != 0U) {
            size_t copied = address_capacity < guest_length ? address_capacity : guest_length;
            if (copied != 0U && !guest_memory(s, (uintptr_t)address_pointer, copied, true)) return -EFAULT;
            if (copied != 0U) copy_bytes((void *)(uintptr_t)address_pointer, guest_address, copied);
        }
        size_t copied_data = (uint64_t)result < staged.iov_len ? (size_t)result : staged.iov_len;
        size_t offset = 0U;
        for (size_t index = 0U; index < vector_count && offset < copied_data; index++) {
            size_t count = vectors[index].iov_len < copied_data - offset ? vectors[index].iov_len : copied_data - offset;
            copy_bytes(vectors[index].iov_base, s->datagram_buffer + offset, count);
            offset += count;
        }
        if (message_call && vector_request == NULL) {
            wire.name_length = address_pointer == 0U ? 0U : (uint32_t)guest_length;
            wire.control_length = 0U;
            wire.flags = (uint32_t)message.msg_flags;
            copy_bytes((void *)(uintptr_t)args[1], (const unsigned char *)&wire, sizeof(wire));
        } else if (address_pointer != 0U) {
            uint32_t length = (uint32_t)guest_length;
            copy_bytes((void *)(uintptr_t)args[5], (const unsigned char *)&length, sizeof(length));
        }
    }
    return result;
}

/* Raw ARM64 pselect6. Keep the transient mask in the guest signal state.
 * On an interrupted sleep, handle_shell delivers against this mask and
 * puts the caller's original mask in the guest rt_sigreturn frame. */
static int guest_pselect(struct shell_state *s,const uint64_t args[6]) {
    int nfds=(int32_t)args[0];
    if(nfds<0 || nfds>1024) return -EINVAL;
    size_t words=((size_t)nfds+63U)/64U;
    struct sucrune_local_fdset input[3]={0},output[3]={0};
    for(size_t set=0;set<3;set++) {
        uintptr_t addr=(uintptr_t)args[1U+set];
        if(!addr || !words) continue;
        if(!guest_memory(s,addr,words*8U,false) || !guest_memory(s,addr,words*8U,true)) return -EFAULT;
        copy_bytes((unsigned char *)input[set].words,(const void *)addr,words*8U);
        if(nfds%64) input[set].words[words-1U]&=(UINT64_C(1)<<(unsigned int)(nfds%64))-1U;
    }
    struct sucrune_local_timespec timeout={0,0},left={0,0},zero={0,0};
    if(args[4]) {
        if(!guest_memory(s,(uintptr_t)args[4],sizeof(timeout),false) ||
           !guest_memory(s,(uintptr_t)args[4],sizeof(timeout),true)) return -EFAULT;
        copy_bytes((unsigned char *)&timeout,(const void *)(uintptr_t)args[4],sizeof(timeout));
        if(timeout.seconds<0 || timeout.nanoseconds<0 || timeout.nanoseconds>=1000000000) return -EINVAL;
    }
    struct sucrune_signal_thread *thread=current_signals(s);
    uint64_t original=thread->mask,mask=original;
    if(args[5]) {
        uint64_t pair[2];
        if(!guest_memory(s,(uintptr_t)args[5],sizeof(pair),false)) return -EFAULT;
        copy_bytes((unsigned char *)pair,(const void *)(uintptr_t)args[5],sizeof(pair));
        if(pair[0]) {
            if(pair[1]!=8U) return -EINVAL;
            if(!guest_memory(s,(uintptr_t)pair[0],sizeof(mask),false)) return -EFAULT;
            copy_bytes((unsigned char *)&mask,(const void *)(uintptr_t)pair[0],sizeof(mask));
            mask&=~((UINT64_C(1)<<(SIGKILL-1))|(UINT64_C(1)<<(SIGSTOP-1)));
        }
    }
    thread->mask=mask;collect_child_signal(s);
    bool pending=(thread->pending&~mask)!=0U;
    int wake=can_receive_child(s) ? sucrune_processes_wake_fd(s->processes) : -1;
    struct local_call_context call={.state=s};
    struct sucrune_local_io io=local_io(&call);
    io.descriptor_limit=s->descriptors.limit;
    (void)pthread_mutex_unlock(&s->state_lock);
    int result=sucrune_local_pselect(&io,input,output,pending ? &zero : args[4] ? &timeout : NULL,&left,wake);
    (void)pthread_mutex_lock(&s->state_lock);
    if(pending) {left=timeout;if(result==0) result=-EINTR;}
    if(result!=-EINTR) thread->mask=original;
    if(args[4] && (result>=0 || result==-EINTR)) {
        if(!guest_memory(s,(uintptr_t)args[4],sizeof(left),true)) {thread->mask=original;return -EFAULT;}
        copy_bytes((void *)(uintptr_t)args[4],(const unsigned char *)&left,sizeof(left));
    }
    if(result>=0 && words) {
        for(size_t set=0;set<3;set++) if(args[1U+set] &&
            !guest_memory(s,(uintptr_t)args[1U+set],words*8U,true)) return -EFAULT;
        for(size_t set=0;set<3;set++) if(args[1U+set])
            copy_bytes((void *)(uintptr_t)args[1U+set],(const unsigned char *)output[set].words,words*8U);
    }
    return result;
}
static int proc_descriptor(struct shell_state *s,uint64_t fd) {
    struct sucrune_fd_resource *r=sucrune_fds_get(&s->descriptors,fd);
    return r!=NULL && r->kind==SUCRUNE_FD_LOCAL && sucrune_proc_has(&s->proc,r->handle)?r->handle:0;
}
static int proc_at_path_arg(struct shell_state *s,struct sucrune_request *r,uint64_t fd,uintptr_t address) {
    int error=path_arg(s,r,address);
    if (error || !s->linux_mode || !r->data[0] || r->data[0]=='/') return error;
    if (sucrune_proc_net_dir_fd(&s->proc,proc_descriptor(s,fd))) {
        int size=sucrune_proc_net_at((char *)r->data,r->size,SUCRUNE_PATH_LIMIT);
        if (size<0) return -size;
        r->size=(uint32_t)size;
    }
    return 0;
}
static int proc_path_stat(struct shell_state *s,const char *path,struct sucrune_arm64_stat *out) {
    return sucrune_proc_path_stat(s->processes,path,out);
}

static int open_guest_device(struct shell_state *s, const char *device, uint64_t flags) {
    int native_flags = sucrune_device_open_flags(device, flags);
    if (native_flags < 0) return native_flags;
    int fd = open(device, native_flags);
    if (fd < 0) return -errno;
    int descriptor = sucrune_fds_add(&s->descriptors, SUCRUNE_FD_LOCAL, fd,
        (int)flags & (O_ACCMODE | O_APPEND | O_NONBLOCK | O_PATH),
        (flags & O_CLOEXEC) != 0U ? SUCRUNE_FD_CLOEXEC : 0U);
    if (descriptor < 0) (void)close(fd);
    return descriptor;
}

static struct sucrune_arm64_stat guest_stat(const struct stat *st) {
    return (struct sucrune_arm64_stat) {
        .device = st->st_dev, .inode = st->st_ino, .mode = st->st_mode, .nlink = (uint32_t)st->st_nlink,
        .uid = st->st_uid, .gid = st->st_gid, .rdevice = st->st_rdev, .size = st->st_size,
        .block_size = (int32_t)st->st_blksize, .blocks = st->st_blocks,
        .atime_sec = st->st_atim.tv_sec, .atime_nsec = (uint64_t)st->st_atim.tv_nsec,
        .mtime_sec = st->st_mtim.tv_sec, .mtime_nsec = (uint64_t)st->st_mtim.tv_nsec,
        .ctime_sec = st->st_ctim.tv_sec, .ctime_nsec = (uint64_t)st->st_ctim.tv_nsec
    };
}
static int ll_read(void *context, uintptr_t address, void *out, size_t size) {
    if (!guest_memory(context, address, size, false)) return -EFAULT;
    copy_bytes(out, (const void *)address, size);
    return 0;
}
static int ll_handle(void *context, int32_t fd, int64_t *handle) {
    struct shell_state *s = context;
    struct sucrune_fd_resource *res = sucrune_fds_get(&s->descriptors, (uint32_t)fd);
    if (!res) return -EBADF;
    if (res->kind == SUCRUNE_FD_BROKER) {
        *handle = res->handle;
        return 0;
    }
    struct stat st;
    int alias = sucrune_fds_alias(&s->descriptors, (uint32_t)fd);
    if (alias >= 0 && fstat(alias, &st) == 0 && sucrune_ll_is_null(&st)) {
        *handle = SUCRUNE_LL_NULL;
        return 0;
    }
    return -EBADFD;
}
static int64_t ll_call(struct shell_state *s, struct sucrune_request *r, const uint64_t *args) {
    if (!s->linux_mode) return -ENOSYS;
    int error = sucrune_ll_request(r, args, s, ll_read, ll_handle);
    if (error) return error;
    bool allocate = r->operation == SUCRUNE_LL_CREATE && r->args[2] == 0;
    if (allocate && (error = sucrune_fds_available(&s->descriptors)) < 0) return error;
    if (r->operation == SUCRUNE_LL_RESTRICT ||
        (r->operation == SUCRUNE_LL_PRCTL && r->args[0] == PR_SET_NO_NEW_PRIVS)) {
        /* This broker session is shared by the thread group. A restriction
         * by one of several live threads needs an independent thread domain. */
        struct sucrune_thread_stats stats = {0};
        sucrune_threads_stats(s->threads, &stats);
        if (sucrune_thread_current() || stats.live) return -EOPNOTSUPP;
    }
    struct sucrune_response out;
    int64_t result = exchange(s->broker, r, &out);
    if (result < 0 || !allocate) return result;
    if (out.size || result < SUCRUNE_BROKER_HANDLE_BASE ||
        result >= SUCRUNE_BROKER_HANDLE_BASE + SUCRUNE_FILE_RESOURCES) return -EPROTO;
    int fd = sucrune_fds_add(&s->descriptors, SUCRUNE_FD_BROKER, (int)result, O_RDWR, SUCRUNE_FD_CLOEXEC);
    if (fd < 0) (void)release_descriptor(s, SUCRUNE_FD_BROKER, (int)result);
    return fd;
}
static int ll_special_open(struct shell_state *s, int id, uint64_t flags, int directory) {
    uint64_t access = sucrune_ll_special_access(flags, directory);
    if (!access) return 0;
    struct sucrune_request req = { .magic=SUCRUNE_BROKER_MAGIC, .operation=SUCRUNE_BROKER_LL_SPECIAL,
        .args={id, (int64_t)access, 0, 0} };
    struct sucrune_response out;
    return (int)exchange(s->broker, &req, &out);
}

static int64_t guest_call(struct shell_state *s, int operation, uint64_t *args) {
    struct sucrune_request request = { .magic = SUCRUNE_BROKER_MAGIC, .operation = (uint32_t)operation };
    struct sucrune_response response;
    uintptr_t output = 0;
    size_t output_size = 0;
    int error = 0;
    switch (operation) {
        case SUCRUNE_LL_PRCTL: case SUCRUNE_LL_CREATE: case SUCRUNE_LL_ADD: case SUCRUNE_LL_RESTRICT:
            return ll_call(s, &request, args);
        case 260: { /* wait4: copy status only after actual kernel reaping. */
            if (!s->linux_mode || s->processes == NULL) return -ENOSYS;
            struct rusage usage = {0};
            uintptr_t usage_pointer = (uintptr_t)args[3];
            if (usage_pointer != 0U && !guest_memory(s, usage_pointer, sizeof(usage), true)) return -EFAULT;
            uintptr_t pointer = (uintptr_t)args[1];
            if (pointer != 0U && !guest_memory(s, pointer, sizeof(int32_t), true)) return -EFAULT;
            int status = 0;
            (void)pthread_mutex_unlock(&s->state_lock);
            int64_t result = sucrune_processes_wait(s->processes, (int32_t)args[0], (unsigned int)args[2], &status,
                usage_pointer ? &usage : NULL);
            (void)pthread_mutex_lock(&s->state_lock);
            if (result > 0 && usage_pointer != 0U && !guest_memory(s, usage_pointer, sizeof(usage), true)) return -EFAULT;
            if (result > 0 && pointer != 0U) {
                if (!guest_memory(s, pointer, sizeof(int32_t), true)) return -EFAULT;
                int32_t value = (int32_t)status;
                memcpy((void *)pointer, &value, sizeof(value));
            }
            if (result > 0 && usage_pointer != 0U) memcpy((void *)usage_pointer, &usage, sizeof(usage));
            return result;
        }
        case 198: {
            if (!s->linux_mode) return -ENOSYS;
            int available = sucrune_fds_available(&s->descriptors);
            if (available < 0) return available;
            int flags = (int)args[1];
            if ((flags & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)) == SOCK_STREAM) flags |= SOCK_NONBLOCK;
            int handle = sucrune_guest_network_socket(&s->network, (int)args[0], flags, (int)args[2]);
            return publish_network_descriptor(s, handle, (int)args[1]);
        }
        case 199: {
            if (!s->linux_mode) return -ENOSYS;
            if (!guest_memory(s, (uintptr_t)args[3], 8U, true)) return -EFAULT;
            struct local_call_context call = {.state = s, .pipe_output = (uintptr_t)args[3]};
            struct sucrune_local_io io = local_io(&call);
            int32_t pair[2];
            (void)pthread_mutex_unlock(&s->state_lock);
            int result = sucrune_socket_pair(&io, (int)args[0], (int)args[1], (int)args[2], pair);
            (void)pthread_mutex_lock(&s->state_lock);
            return result;
        }
        case 200: case 203: case 201: case 208: case 210: {
            if (!s->linux_mode) return -ENOSYS;
            struct sucrune_fd_resource *resource = sucrune_fds_get(&s->descriptors, args[0]);
            if (resource == NULL) return -EBADF;
            if (!sucrune_guest_network_contains(&s->network, resource->handle) || resource->kind != SUCRUNE_FD_LOCAL)
                return -ENOTSOCK;
            size_t unused = 0;
            if (operation == 200 || operation == 203) {
                if (args[2] > SUCRUNE_SOCKET_ADDRESS_LIMIT) return -EINVAL;
                if (!guest_memory(s, (uintptr_t)args[1], (size_t)args[2], false)) return -EFAULT;
                unsigned char address[SUCRUNE_SOCKET_ADDRESS_LIMIT];
                copy_bytes(address, (const void *)(uintptr_t)args[1], (size_t)args[2]);
                int result = sucrune_guest_network_address(&s->network, resource->handle, operation == 203,
                    address, (size_t)args[2]);
                if (operation != 203 || result != -EINPROGRESS || (resource->status_flags & O_NONBLOCK) ||
                    sucrune_guest_network_type(&s->network, resource->handle) != SOCK_STREAM) return result;
                result = wait_stream_ready(s, args[0], resource, POLLOUT);
                if (result < 0) return result;
                int socket_error = 0;
                size_t length = 0;
                result = sucrune_guest_network_control(&s->network, resource->handle, SUCRUNE_NET_GETOPT,
                    SOL_SOCKET, SO_ERROR, NULL, 0, &socket_error, sizeof(socket_error), &length);
                if (result < 0) return result;
                return length == sizeof(socket_error) ? -socket_error : -EPROTO;
            }
            if (operation == 208) {
                if (args[4] < sizeof(uint32_t)) return -EINVAL;
                if (!guest_memory(s, (uintptr_t)args[3], sizeof(uint32_t), false)) return -EFAULT;
                unsigned char value[4]; copy_bytes(value, (const void *)(uintptr_t)args[3], sizeof(value));
                return sucrune_guest_network_control(&s->network, resource->handle, SUCRUNE_NET_SETOPT,
                    (int)args[1], (int)args[2], value, sizeof(value), NULL, 0, &unused);
            }
            int value = (int)args[1];
            if (operation == 201 && (value < 0 || value > 128)) value = 128;
            return sucrune_guest_network_control(&s->network, resource->handle,
                operation == 201 ? SUCRUNE_NET_LISTEN : SUCRUNE_NET_SHUTDOWN, value, 0, NULL, 0, NULL, 0, &unused);
        }
        case 206: case 207: { /* Connected send/recv, including idle TCP MSG_PEEK. */
            if (!s->linux_mode) return -ENOSYS;
            struct sucrune_fd_resource *resource = sucrune_fds_get(&s->descriptors, args[0]);
            if (resource == NULL) return -EBADF;
            if (resource->kind != SUCRUNE_FD_LOCAL || resource->handle < 0) return -ENOTSOCK;
            int network_type = sucrune_guest_network_type(&s->network, resource->handle);
            if (network_type == SOCK_DGRAM)
                return guest_datagram(s, operation, args, NULL);
            if (args[2] > INT64_MAX) return -EINVAL;
            int allowed = operation == 206 ? MSG_DONTWAIT | MSG_NOSIGNAL | MSG_MORE :
                MSG_DONTWAIT | MSG_PEEK | MSG_WAITALL;
            if ((args[3] & ~(uint64_t)allowed) != 0U) return -EOPNOTSUPP;
            /* Addressed datagrams require the manager's destination policy.
             * Do not let an explicit sendto destination bypass connect. */
            if (operation == 206 && args[4] != 0U) return -EOPNOTSUPP;
retry_stream_data:
            if (args[2] != 0U && !guest_memory(s, (uintptr_t)args[1], (size_t)args[2], operation == 207)) return -EFAULT;
            uint32_t capacity = 0;
            if (operation == 207 && args[4] != 0U) {
                if (!guest_memory(s, (uintptr_t)args[5], sizeof(capacity), false) ||
                    !guest_memory(s, (uintptr_t)args[5], sizeof(capacity), true)) return -EFAULT;
                copy_bytes((unsigned char *)&capacity, (const void *)(uintptr_t)args[5], sizeof(capacity));
                if (capacity > INT32_MAX) return -EINVAL;
                size_t checked = capacity < sizeof(struct sockaddr_storage) ? capacity : sizeof(struct sockaddr_storage);
                if (checked != 0U && !guest_memory(s, (uintptr_t)args[4], checked, true)) return -EFAULT;
            }
            bool tcp = network_type == SOCK_STREAM;
            int retained = resource->handle;
            if (!tcp) {
                retained = fcntl(resource->handle, F_DUPFD_CLOEXEC, 16);
                if (retained < 0) return -errno;
                (void)pthread_mutex_unlock(&s->state_lock);
            }
            struct sockaddr_storage address;
            socklen_t length = sizeof(address);
            int io_flags = (int)args[3] | (tcp ? MSG_DONTWAIT : 0);
            ssize_t result;
            do {
                if (operation == 206) result = sendto(retained, (const void *)(uintptr_t)args[1], (size_t)args[2],
                    io_flags | MSG_NOSIGNAL, NULL, 0);
                else result = recvfrom(retained, (void *)(uintptr_t)args[1], (size_t)args[2], io_flags,
                    args[4] == 0U ? NULL : (struct sockaddr *)&address, args[4] == 0U ? NULL : &length);
            } while (result < 0 && errno == EINTR);
            int saved = errno;
            if (!tcp) {
                (void)close(retained);
                (void)pthread_mutex_lock(&s->state_lock);
            } else if (result < 0 && saved == EAGAIN && !(resource->status_flags & O_NONBLOCK) &&
                !(args[3] & MSG_DONTWAIT)) {
                int ready = wait_stream_ready(s, args[0], resource, operation == 206 ? POLLOUT : POLLIN);
                if (ready < 0) return ready;
                goto retry_stream_data;
            }
            if (result < 0) return -saved;
            if (operation == 207 && args[4] != 0U) {
                size_t copied = capacity < length ? capacity : length;
                if (copied > sizeof(address)) return -EIO;
                if (!guest_memory(s, (uintptr_t)args[5], sizeof(uint32_t), true) ||
                    (copied != 0U && !guest_memory(s, (uintptr_t)args[4], copied, true))) return -EFAULT;
                if (copied != 0U) copy_bytes((void *)(uintptr_t)args[4], (const unsigned char *)&address, copied);
                uint32_t reported = length;
                copy_bytes((void *)(uintptr_t)args[5], (const unsigned char *)&reported, sizeof(reported));
            }
            return result;
        }
        case 211: case 212: case 269: {
            if (!s->linux_mode) return -ENOSYS;
            struct sucrune_fd_resource *resource = sucrune_fds_get(&s->descriptors, args[0]);
            if (resource == NULL) return -EBADF;
            if (operation != 269 && resource->kind == SUCRUNE_FD_LOCAL &&
                sucrune_guest_network_type(&s->network, resource->handle) == SOCK_STREAM)
                return guest_stream_message(s, operation, args, NULL);
            return guest_datagram(s, operation, args, NULL);
        }
        case 202: case 242: {
            if (!s->linux_mode) return -ENOSYS;
            struct sucrune_fd_resource *resource = sucrune_fds_get(&s->descriptors, args[0]);
            if (resource == NULL) return -EBADF;
            if (resource->kind != SUCRUNE_FD_LOCAL || !sucrune_guest_network_contains(&s->network, resource->handle)) return -ENOTSOCK;
            int available = sucrune_fds_available(&s->descriptors);
            if (available < 0) return available;
            uint32_t requested = 0;
            uintptr_t output_address = (uintptr_t)args[1], size_address = (uintptr_t)args[2];
            if (output_address != 0U) {
                if (!guest_memory(s, size_address, sizeof(uint32_t), false) ||
                    !guest_memory(s, size_address, sizeof(uint32_t), true)) return -EFAULT;
                copy_bytes((unsigned char *)&requested, (const void *)size_address, sizeof(requested));
                if (requested > INT32_MAX) return -EINVAL;
            }
            unsigned char address[SUCRUNE_SOCKET_ADDRESS_LIMIT]; size_t length = 0;
            size_t capacity = requested < sizeof(address) ? requested : sizeof(address);
            int flags = operation == 242 ? (int)args[3] : 0;
            if (flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK)) return -EINVAL;
            int handle;
            for (;;) {
                handle = sucrune_guest_network_accept(&s->network, resource->handle,
                    flags | SOCK_NONBLOCK, address, capacity, &length);
                if (handle != -EAGAIN || (resource->status_flags & O_NONBLOCK)) break;
                int ready = wait_stream_ready(s, args[0], resource, POLLIN);
                if (ready < 0) return ready;
            }
            if (handle < 0) return handle;
            size_t copied = capacity < length ? capacity : length;
            if ((copied != 0U && !guest_memory(s, output_address, copied, true)) ||
                (output_address != 0U && !guest_memory(s, size_address, sizeof(uint32_t), true))) {
                (void)sucrune_guest_network_release(&s->network, handle); return -EFAULT;
            }
            int descriptor = publish_network_descriptor(s, handle, flags);
            if (descriptor < 0) return descriptor;
            if (output_address != 0U) {
                if (copied != 0U) copy_bytes((void *)output_address, address, copied);
                uint32_t reported = (uint32_t)length;
                copy_bytes((void *)size_address, (const unsigned char *)&reported, sizeof(reported));
            }
            return descriptor;
        }
        case 204: case 205: case 209: {
            if (!s->linux_mode) return -ENOSYS;
            struct sucrune_fd_resource *resource = sucrune_fds_get(&s->descriptors, args[0]);
            if (resource == NULL) return -EBADF;
            if (resource->kind == SUCRUNE_FD_BROKER) return -ENOTSOCK;
            uintptr_t value = (uintptr_t)args[operation == 209 ? 3 : 1];
            uintptr_t size_address = (uintptr_t)args[operation == 209 ? 4 : 2];
            if (!guest_memory(s, size_address, sizeof(uint32_t), false) ||
                !guest_memory(s, size_address, sizeof(uint32_t), true)) return -EFAULT;
            uint32_t requested;
            copy_bytes((unsigned char *)&requested, (const void *)size_address, sizeof(requested));
            if (requested > INT32_MAX) return -EINVAL;
            size_t limit = operation == 209 ? sizeof(uint32_t) : SUCRUNE_SOCKET_ADDRESS_LIMIT;
            size_t capacity = requested < limit ? requested : limit;
            unsigned char bytes[SUCRUNE_SOCKET_ADDRESS_LIMIT];
            size_t length = 0;
            if (resource->kind == SUCRUNE_FD_LOCAL && sucrune_guest_network_contains(&s->network, resource->handle)) {
                int result = sucrune_guest_network_control(&s->network, resource->handle,
                    operation == 209 ? SUCRUNE_NET_GETOPT : SUCRUNE_NET_NAME,
                    operation == 209 ? (int)args[1] : (operation == 205 ? 1 : 0),
                    operation == 209 ? (int)args[2] : 0, NULL, 0, bytes, capacity, &length);
                if (result != 0) return result;
                size_t copied = length < capacity ? length : capacity;
                if (copied != 0U && !guest_memory(s, value, copied, true)) return -EFAULT;
                if (copied != 0U) copy_bytes((void *)value, bytes, copied);
                uint32_t reported = (uint32_t)length;
                copy_bytes((void *)size_address, (const unsigned char *)&reported, sizeof(reported));
                return 0;
            }
            struct local_call_context call = {.state = s};
            struct sucrune_local_io io = local_io(&call);
            (void)pthread_mutex_unlock(&s->state_lock);
            int result = operation == 209 ? sucrune_socket_get_option(&io, (int32_t)args[0],
                (int)args[1], (int)args[2], bytes, capacity, &length) :
                sucrune_socket_get_name(&io, (int32_t)args[0], operation == 205 ? 1 : 0, bytes, capacity, &length);
            (void)pthread_mutex_lock(&s->state_lock);
            if (result != 0) return result;
            if (length > sizeof(bytes)) return -EIO;
            size_t copied = length < capacity ? length : capacity;
            if (!guest_memory(s, size_address, sizeof(uint32_t), true) ||
                (copied != 0U && !guest_memory(s, value, copied, true))) return -EFAULT;
            if (copied != 0U) copy_bytes((void *)value, bytes, copied);
            uint32_t reported = (uint32_t)length;
            copy_bytes((void *)size_address, (const unsigned char *)&reported, sizeof(reported));
            return 0;
        }
        case 19: case 20: case 21: case 22: case 59: case 73: {
            if (!s->linux_mode) return -ENOSYS;
            struct local_call_context call = {.state = s, .pipe_output = operation == 59 ? (uintptr_t)args[0] : 0U};
            struct sucrune_local_io io = local_io(&call);
            if (operation == 19 || operation == 20) {
                (void)pthread_mutex_unlock(&s->state_lock);
                int result = operation == 19 ? sucrune_local_eventfd2(&io, (uint32_t)args[0], (int)args[1]) : sucrune_local_epoll_create1(&io, (int)args[0]);
                (void)pthread_mutex_lock(&s->state_lock); return result;
            }
            if (operation == 59) {
                if (!guest_memory(s, (uintptr_t)args[0], 8U, true)) return -EFAULT;
                int32_t pair[2];
                (void)pthread_mutex_unlock(&s->state_lock);
                int result = sucrune_local_pipe2(&io, (int)args[1], pair);
                (void)pthread_mutex_lock(&s->state_lock);
                /* commit published both FDs and copied out their numbers in
                 * one table-lock transaction. Never roll back by stale IDs. */
                return result;
            }
            if (operation == 21) {
                struct sucrune_local_event event;
                if ((int)args[1] != EPOLL_CTL_DEL) {
                    if (!guest_memory(s, (uintptr_t)args[3], sizeof(event), false)) return -EFAULT;
                    copy_bytes((unsigned char *)&event, (void *)(uintptr_t)args[3], sizeof(event));
                }
                (void)pthread_mutex_unlock(&s->state_lock);
                int result = sucrune_local_epoll_ctl(&io, (int32_t)args[0], (int)args[1], (int32_t)args[2], (int)args[1] == EPOLL_CTL_DEL ? NULL : &event);
                (void)pthread_mutex_lock(&s->state_lock); return result;
            }
            if (operation == 22) {
                if ((int32_t)args[2] <= 0) return -EINVAL;
                size_t count = (int32_t)args[2] > (int32_t)SUCRUNE_LOCAL_IO_LIMIT ? SUCRUNE_LOCAL_IO_LIMIT : (size_t)(int32_t)args[2];
                if (!guest_memory(s, (uintptr_t)args[1], count * sizeof(struct sucrune_local_event), true)) return -EFAULT;
                if (args[4] != 0U) return args[5] == 8U ? -ENOTSUP : -EINVAL;
                struct sucrune_local_event events[SUCRUNE_LOCAL_IO_LIMIT];
                int wake=can_receive_child(s) ? sucrune_processes_wake_fd(s->processes) : -1;
                (void)pthread_mutex_unlock(&s->state_lock);
                int result = sucrune_local_epoll_interruptible(&io, (int32_t)args[0], events, (int32_t)args[2], (int32_t)args[3], NULL, (size_t)args[5],wake);
                (void)pthread_mutex_lock(&s->state_lock);
                if (result > 0 && !guest_memory(s, (uintptr_t)args[1], (size_t)result * sizeof(events[0]), true)) return -EFAULT;
                if (result > 0) copy_bytes((void *)(uintptr_t)args[1], (unsigned char *)events, (size_t)result * sizeof(events[0]));
                return result;
            }
            if (args[1] > s->descriptors.limit) return -EINVAL;
            if (args[3] != 0U) return args[4] == 8U ? -ENOTSUP : -EINVAL;
            size_t count = (size_t)args[1];
            struct sucrune_local_pollfd small_fds[SUCRUNE_LOCAL_IO_LIMIT], *fds=small_fds;
            size_t bytes=count*sizeof(*fds);
            io.descriptor_limit=s->descriptors.limit;
            struct sucrune_local_timespec timeout, remaining;
            if (count && (!guest_memory(s,(uintptr_t)args[0],bytes,false) || !guest_memory(s,(uintptr_t)args[0],bytes,true))) return -EFAULT;
            if (args[2] != 0U) {
                if (!guest_memory(s, (uintptr_t)args[2], sizeof(timeout), true)) return -EFAULT;
                copy_bytes((unsigned char *)&timeout, (void *)(uintptr_t)args[2], sizeof(timeout));
            }
            if (count>SUCRUNE_LOCAL_IO_LIMIT) {
                fds=mmap(NULL,bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
                if(fds==MAP_FAILED) return -errno;
            }
            copy_bytes((unsigned char *)fds, (void *)(uintptr_t)args[0], bytes);
            (void)pthread_mutex_unlock(&s->state_lock);
            int result = sucrune_local_ppoll(&io, fds, count, args[2] == 0U ? NULL : &timeout, &remaining, NULL, (size_t)args[4]);
            (void)pthread_mutex_lock(&s->state_lock);
            if (result >= 0 && count && !guest_memory(s, (uintptr_t)args[0], bytes, true)) result=-EFAULT;
            if ((result >= 0 || result == -EINTR) && args[2] != 0U && !guest_memory(s, (uintptr_t)args[2], sizeof(remaining), true)) result=-EFAULT;
            if (result >= 0) copy_bytes((void *)(uintptr_t)args[0], (unsigned char *)fds, bytes);
            if ((result >= 0 || result == -EINTR) && args[2] != 0U) copy_bytes((void *)(uintptr_t)args[2], (unsigned char *)&remaining, sizeof(remaining));
            if(fds!=small_fds) (void)munmap(fds,bytes);
            return result;
        }
        case 23: return sucrune_fds_duplicate(&s->descriptors, args[0], 0U, 0U);
        case 24:
            if ((args[2] & ~(uint64_t)O_CLOEXEC) != 0U) return -EINVAL;
            return sucrune_fds_replace(&s->descriptors, args[0], args[1], args[2] != 0U ? 1U : 0U);
        case 221: {
            int64_t result = prepare_exec(s, args);
            if (result < 0) s->exec_failed_before_commit++;
            return result;
        }
        case 227: return s->linux_mode ? linux_memory_call(s, operation, args) : -ENOSYS;
        case 214: case 215: case 222: case 226: case 233:
            return s->linux_mode ? linux_memory_call(s, operation, args) : sucrune_memory_call(&s->memory, operation, args);
        case SUCRUNE_BROKER_SENDFILE: {
            if (!s->linux_mode) return -ENOSYS;
            struct sucrune_fd_resource *dst = sucrune_fds_get(&s->descriptors, args[0]);
            struct sucrune_fd_resource *src = sucrune_fds_get(&s->descriptors, args[1]);
            if (dst == NULL || src == NULL) return -EBADF;
            if (dst->kind != SUCRUNE_FD_BROKER || src->kind != SUCRUNE_FD_BROKER ||
                sucrune_pty_slave_handle(dst->handle) || sucrune_pty_slave_handle(src->handle)) return -EINVAL;
            if (args[3] > INT64_MAX) return -EINVAL;
            uintptr_t pointer = (uintptr_t)args[2];
            int64_t offset = -1;
            if (pointer != 0U) {
                if (!guest_memory(s, pointer, sizeof(offset), false) ||
                    !guest_memory(s, pointer, sizeof(offset), true)) return -EFAULT;
                copy_bytes((void *)&offset, (const void *)pointer, sizeof(offset));
                if (offset < 0) return -EINVAL;
            }
            request.args[0] = dst->handle; request.args[1] = src->handle;
            request.args[2] = (int64_t)args[3]; request.args[3] = offset;
            int64_t sent = exchange(s->broker, &request, &response);
            if (sent < 0) return sent;
            if (response.size != 0U || (uint64_t)sent > args[3] ||
                (pointer != 0U && sent > INT64_MAX - offset)) return -EPROTO;
            if (pointer != 0U) {
                offset += sent;
                copy_bytes((void *)pointer, (const void *)&offset, sizeof(offset));
            }
            return sent;
        }
        case 67: case 68: {
            struct sucrune_fd_resource *resource = sucrune_fds_get(&s->descriptors, args[0]);
            int proc=proc_descriptor(s,args[0]);
            if(proc!=0) {
                if(operation==68) return -EBADF;
                if(args[3]>INT64_MAX) return -EINVAL;
                size_t count=args[2]>SUCRUNE_IO_LIMIT?SUCRUNE_IO_LIMIT:(size_t)args[2];
                if(count != 0U && !guest_memory(s,(uintptr_t)args[1],count,true)) return -EFAULT;
                return sucrune_proc_read(&s->proc,proc,(void *)(uintptr_t)args[1],count,0,(int64_t)args[3]);
            }
            if (resource == NULL) return -EBADF;
            if (resource->kind != SUCRUNE_FD_BROKER) return -ESPIPE;
            if (operation == 67 && resource->read_fd >= 0) {
                int64_t got = guest_direct_read(s, &resource->read_fd, args, true);
                if (resource->read_fd >= 0) return got;
            }
            if (s->linux_mode && operation == 68 && args[2] > SUCRUNE_IO_LIMIT && !sucrune_pty_slave_handle(resource->handle))
                return bulk_file_write(s,resource->handle,args[1],args[2],true,args[3],&request,&response);
            if (s->linux_mode && operation == 67 && args[2] > SUCRUNE_IO_LIMIT && !sucrune_pty_slave_handle(resource->handle))
                return bulk_file_read(s,resource->handle,args[1],args[2],true,args[3],&request,&response);
            size_t count = args[2] > SUCRUNE_IO_LIMIT ? SUCRUNE_IO_LIMIT : (size_t)args[2];
            if (count != 0U && !guest_memory(s, (uintptr_t)args[1], count, operation == 67)) return -EFAULT;
            if (args[3] > INT64_MAX) return -EINVAL;
            request.args[0] = resource->handle; request.args[1] = (int64_t)count; request.args[2] = (int64_t)args[3];
            if (operation == 68) { copy_bytes(request.data, (void *)(uintptr_t)args[1], count); request.size = (uint32_t)count; }
            else { output = (uintptr_t)args[1]; output_size = count; }
            break;
        }
        case 99: /* Robust-mutex owner-death recovery is not implemented. */
            if (!s->linux_mode) break;
            return -ENOSYS;
        case 98: {
            if (!s->linux_mode) return -ENOSYS;
            if ((args[1] & ~UINT64_C(0x1ff)) != 0U) return -EINVAL;
            int command = (int)args[1] & FUTEX_CMD_MASK;
            if (command != FUTEX_WAIT && command != FUTEX_WAKE && command != FUTEX_WAIT_BITSET &&
                command != FUTEX_WAKE_BITSET && command != FUTEX_REQUEUE && command != FUTEX_CMP_REQUEUE && command != FUTEX_WAKE_OP)
                return -ENOSYS;
            if (args[0] % sizeof(uint32_t) != 0U) return -EINVAL;
            if (!guest_memory(s, (uintptr_t)args[0], sizeof(uint32_t), true)) return -EFAULT;
            if ((command == FUTEX_REQUEUE || command == FUTEX_CMP_REQUEUE || command == FUTEX_WAKE_OP) &&
                (args[4] % sizeof(uint32_t) != 0U || !guest_memory(s, (uintptr_t)args[4], sizeof(uint32_t), true))) return -EFAULT;
            struct timespec timeout;
            uintptr_t fourth = (uintptr_t)args[3];
            if ((command == FUTEX_WAIT || command == FUTEX_WAIT_BITSET) && args[3] != 0U) {
                if (!guest_memory(s, fourth, sizeof(timeout), false)) return -EFAULT;
                copy_bytes((unsigned char *)&timeout, (void *)fourth, sizeof(timeout));
                if (timeout.tv_sec < 0 || timeout.tv_nsec < 0 || timeout.tv_nsec >= 1000000000L) return -EINVAL;
                fourth = (uintptr_t)&timeout;
            }
            (void)pthread_mutex_unlock(&s->state_lock);
            long result = syscall(SYS_futex, (void *)(uintptr_t)args[0], (int)args[1], (uint32_t)args[2],
                fourth, (void *)(uintptr_t)args[4], (uint32_t)args[5]);
            int saved = errno; (void)pthread_mutex_lock(&s->state_lock);
            return result < 0 ? -saved : result;
        }
        case 261: { /* Query limits only; never modify host-process limits. */
            if (!s->linux_mode || args[0] != 0U || args[2] != 0U) return -EPERM;
            if (args[3] == 0U) return 0;
            if (!guest_memory(s, (uintptr_t)args[3], sizeof(struct rlimit), true)) return -EFAULT;
            struct rlimit limit;
            if (syscall(SYS_prlimit64, 0, (int)args[1], NULL, &limit) != 0) return -errno;
            if (args[1] == RLIMIT_NOFILE) limit.rlim_cur = limit.rlim_max = s->descriptors.limit;
            copy_bytes((void *)(uintptr_t)args[3], (unsigned char *)&limit, sizeof(limit)); return 0;
        }
        case 65: case 66: { /* Linux iovec is two 64-bit words on AArch64. */
            if(proc_descriptor(s,args[0])!=0) return operation==66?-EBADF:-EOPNOTSUPP;
            struct guest_iovec { uint64_t address, length; } vector;
            struct sucrune_fd_resource *resource = sucrune_fds_get(&s->descriptors, args[0]);
            if (resource == NULL) return -EBADF;
            if (s->linux_mode && resource->kind == SUCRUNE_FD_LOCAL) {
                int type = sucrune_guest_network_type(&s->network, resource->handle);
                struct sucrune_arm64_msghdr wire = {.vectors = args[1], .vector_count = args[2]};
                uint64_t call[6] = {args[0], 0U, 0U, 0U, 0U, 0U};
                if (type == SOCK_DGRAM) return guest_datagram(s, operation == 65 ? 212 : 211, call, &wire);
                if (type == SOCK_STREAM) {
                    if (args[2] > 1024U) return -EINVAL;
                    return guest_stream_message(s, operation == 65 ? 212 : 211, call, &wire);
                }
            }
            if (resource->kind != SUCRUNE_FD_BROKER && resource->kind != SUCRUNE_FD_LOCAL &&
                ((operation == 65 && resource->kind != SUCRUNE_FD_INPUT) ||
                 (operation == 66 && resource->kind == SUCRUNE_FD_INPUT))) return -EBADF;
            if (args[2] > 1024U) return -EINVAL;
            if (!guest_memory(s, (uintptr_t)args[1], (size_t)args[2] * sizeof(vector), false)) return -EFAULT;
            if (s->linux_mode && resource->kind != SUCRUNE_FD_BROKER) {
                struct iovec vectors[1024];
                uint64_t length = 0U;
                for (size_t i = 0; i < (size_t)args[2]; i++) {
                    copy_bytes((unsigned char *)&vector, (void *)(uintptr_t)(args[1] + i * sizeof(vector)), sizeof(vector));
                    if (vector.length > INT64_MAX - length) return -EINVAL;
                    if (vector.length != 0U && !guest_memory(s, (uintptr_t)vector.address, (size_t)vector.length, operation == 65)) return -EFAULT;
                    vectors[i] = (struct iovec){.iov_base = (void *)(uintptr_t)vector.address, .iov_len = (size_t)vector.length};
                    length += vector.length;
                }
                if (resource->handle < 0) return 0;
                bool input_resource = resource->kind == SUCRUNE_FD_INPUT;
                int retained = fcntl(resource->handle, F_DUPFD_CLOEXEC, 16);
                if (retained < 0) return -errno;
                (void)pthread_mutex_unlock(&s->state_lock);
                long result;
                do { result = syscall(operation == 65 ? SYS_readv : SYS_writev, retained, vectors, (int)args[2]); }
                while (result < 0 && errno == EINTR);
                int saved = errno; (void)close(retained);
                (void)pthread_mutex_lock(&s->state_lock);
                if (input_resource && operation == 65 && result > 0) s->input_read += (uint64_t)result;
                return result < 0 ? -saved : result;
            }
            int64_t total = 0;
            for (size_t i = 0; i < (size_t)args[2]; i++) {
                copy_bytes((unsigned char *)&vector, (void *)(uintptr_t)(args[1] + i * sizeof(vector)), sizeof(vector));
                if (vector.length == 0U) continue;
                uint64_t call[6] = { args[0], vector.address, vector.length, 0, 0, 0 };
                int64_t result = guest_call(s, operation == 66 ? 64 : 63, call);
                if (result < 0) return total != 0 ? total : result;
                total += result;
                if ((uint64_t)result < vector.length) break;
            }
            return total;
        }
        case 43: case 44: {
            if (!s->linux_mode) return -ENOSYS;
            uintptr_t dest=(uintptr_t)args[1];
            struct statfs volume={0};
            if (!guest_memory(s,dest,sizeof(volume),true)) return -EFAULT;
            if (operation==43) {
                error=path_arg(s,&request,(uintptr_t)args[0]);
                if (error) return -error;
                const char *path=(const char *)request.data;
                const char *device=sucrune_device_path(request.data);
                if (sucrune_proc_path(path)) {
                    struct sucrune_arm64_stat st;
                    int rc=proc_path_stat(s,path,&st);
                    if(rc<0) return rc;
                    device="/proc";
                }
                if (device) {
                    if (statfs(device,&volume)<0) return -errno;
                    memcpy((void *)dest,&volume,sizeof(volume)); return 0;
                }
                request.args[0]=AT_FDCWD;
            } else {
                struct sucrune_fd_resource *res=sucrune_fds_get(&s->descriptors,args[0]);
                if (!res) return -EBADF;
                if(res->kind!=SUCRUNE_FD_BROKER) {
                    if(proc_descriptor(s,args[0])) { if(statfs("/proc",&volume)<0) return -errno; }
                    else if(fstatfs(res->handle,&volume)<0) return -errno;
                    memcpy((void *)dest,&volume,sizeof(volume)); return 0;
                }
                request.args[0]=res->handle;
            }
            int64_t rc=exchange(s->broker,&request,&response);
            if(rc<0) return rc;
            if(rc || response.size!=sizeof(volume)) return -EPROTO;
            memcpy((void *)dest,response.data,sizeof(volume)); return 0;
        }
        case 80: case 79: {
            output = (uintptr_t)args[operation == 80 ? 1 : 2];
            output_size = sizeof(struct sucrune_arm64_stat);
            if (!guest_memory(s, output, output_size, true)) return -EFAULT;
            if (operation == 79 && (args[3] & AT_EMPTY_PATH) != 0U) {
                if ((args[3] & ~(uint64_t)(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW)) != 0U) return -EINVAL;
                if (!guest_memory(s, (uintptr_t)args[1], 1U, false)) return -EFAULT;
                if (*(const volatile unsigned char *)(uintptr_t)args[1] == 0U && (int32_t)args[0] != AT_FDCWD) {
                    uint64_t call[6] = {args[0], args[2], 0U, 0U, 0U, 0U};
                    return guest_call(s, 80, call);
                }
                args[3] &= ~(uint64_t)AT_EMPTY_PATH;
            }
            request.args[0] = (int64_t)args[0];
            if (operation == 80) {
                struct sucrune_fd_resource *resource = sucrune_fds_get(&s->descriptors, args[0]);
                if (resource == NULL) return -EBADF;
                if(proc_descriptor(s,args[0])!=0) {
                    struct sucrune_arm64_stat st;
                    int rc=sucrune_proc_stat(&s->proc,resource->handle,&st);
                    if(rc==0) memcpy((void *)output,&st,sizeof(st));
                    return rc;
                }
                if (resource->kind != SUCRUNE_FD_BROKER) {
                    struct sucrune_arm64_stat st = { .mode = 0010600, .nlink = 1, .block_size = 4096 };
                    if (s->linux_mode && resource->handle >= 0) {
                        struct stat native;
                        if (fstat(resource->handle, &native) != 0) return -errno;
                        st = guest_stat(&native);
                    }
                    copy_bytes((void *)output, (unsigned char *)&st, sizeof(st)); return 0;
                }
                request.args[0] = resource->handle;
            } else {
                request.args[1] = (int64_t)args[3]; error = proc_at_path_arg(s,&request,args[0],(uintptr_t)args[1]);
                const char *device = error == 0 && s->linux_mode ? sucrune_device_path(request.data) : NULL;
                if (device != NULL) {
                    if ((args[3] & ~(uint64_t)(AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW)) != 0U) return -EINVAL;
                    struct stat native;
                    if (lstat(device, &native) != 0) return -errno;
                    struct sucrune_arm64_stat st = guest_stat(&native);
                    copy_bytes((void *)output, (const unsigned char *)&st, sizeof(st));
                    return 0;
                }
                if(error==0 && s->linux_mode && sucrune_proc_path((const char *)request.data)) {
                    if((args[3]&~(uint64_t)(AT_NO_AUTOMOUNT|AT_SYMLINK_NOFOLLOW))!=0U) return -EINVAL;
                    struct sucrune_arm64_stat st;
                    int rc=proc_path_stat(s,(const char *)request.data,&st);
                    if(rc==0) memcpy((void *)output,&st,sizeof(st));
                    return rc;
                }
                if(error==0 && request.data[0]!='/' && proc_descriptor(s,args[0])!=0) return -EOPNOTSUPP;
                if (error == 0) error = directory_handle(s, args[0], request.data, &request.args[0]);
            }
            break;
        }
        case SUCRUNE_BROKER_FSYNC: case SUCRUNE_BROKER_FDATASYNC: {
            if (!s->linux_mode) return -ENOSYS;
            struct sucrune_fd_resource *resource = sucrune_fds_get(&s->descriptors, args[0]);
            if (resource == NULL) return -EBADF;
            if (resource->kind != SUCRUNE_FD_BROKER) return -EINVAL;
            request.args[0] = resource->handle;
            break;
        }
        case SUCRUNE_BROKER_FLOCK: {
            if (!s->linux_mode) return -ENOSYS;
            struct sucrune_fd_resource *resource = sucrune_fds_get(&s->descriptors, args[0]);
            if (resource == NULL) return -EBADF;
            if (resource->kind != SUCRUNE_FD_BROKER) return -EOPNOTSUPP;
            request.args[0] = resource->handle;
            request.args[1] = (int64_t)args[1];
            if (args[1] == LOCK_EX || args[1] == LOCK_SH) {
                /* Retain the open description across concurrent close/reuse.
                 * A contended guest must never block the project broker. */
                int held = sucrune_fds_hold(&s->descriptors, args[0]);
                if (held < 0) return held;
                request.args[1] |= LOCK_NB;
                int64_t locked;
                const struct timespec delay = {.tv_nsec = 10000000};
                while ((locked = exchange(s->broker, &request, &response)) == -EWOULDBLOCK) {
                    (void)pthread_mutex_unlock(&s->state_lock);
                    (void)nanosleep(&delay, NULL);
                    (void)pthread_mutex_lock(&s->state_lock);
                    collect_child_signal(s);
                    struct sucrune_signal_thread *signals = current_signals(s);
                    if ((signals->pending & ~signals->mask) != 0) { locked = -EINTR; break; }
                }
                int dropped = sucrune_fds_drop(&s->descriptors, (unsigned int)held);
                return locked == 0 && dropped != 0 ? dropped : locked;
            }
            break;
        }
        case 25: return descriptor_fcntl(s, args);
        case 29: {
            struct sucrune_fd_resource *resource = sucrune_fds_get(&s->descriptors, args[0]);
            if (resource == NULL) return -EBADF;
            if (!s->linux_mode) return -ENOTTY;
            if (args[1] == FIOCLEX || args[1] == FIONCLEX)
                return sucrune_fds_set_flags(&s->descriptors, args[0], args[1] == FIOCLEX ? SUCRUNE_FD_CLOEXEC : 0U);
            enum sucrune_pty_kind terminal=resource->kind==SUCRUNE_FD_LOCAL ? sucrune_pty_kind(&s->ptys,resource->handle) : SUCRUNE_PTY_NONE;
            if (resource->kind==SUCRUNE_FD_BROKER && sucrune_pty_slave_handle(resource->handle)) {
                if (args[1]!=FIONBIO) return broker_slave_ioctl(s,resource->handle,args[1],args[2]);
                if (!guest_memory(s,(uintptr_t)args[2],sizeof(int),false)) return -EFAULT;
                int enable=0;copy_bytes((unsigned char *)&enable,(void *)(uintptr_t)args[2],sizeof(enable));
                uint64_t query[6]={args[0],F_GETFL,0,0,0,0};
                int64_t flags=descriptor_fcntl(s,query);
                if (flags<0) return flags;
                query[1]=F_SETFL;query[2]=((uint64_t)flags&~(uint64_t)O_NONBLOCK)|(enable!=0?O_NONBLOCK:0);
                return descriptor_fcntl(s,query);
            }
            if (terminal!=SUCRUNE_PTY_NONE && args[1]!=FIONBIO)
                return terminal_ioctl(s,resource->handle,terminal,args[1],args[2]);
            if (args[1] != FIONBIO && args[1] != FIONREAD) {
                if (resource->kind == SUCRUNE_FD_LOCAL && sucrune_guest_network_contains(&s->network, resource->handle))
                    return network_interface_query(s, (unsigned long)args[1], (uintptr_t)args[2]);
                return -ENOTTY;
            }
            if (resource->kind == SUCRUNE_FD_BROKER || resource->handle < 0) return -ENOTTY;
            if (!guest_memory(s, (uintptr_t)args[2], sizeof(int), args[1] == FIONREAD)) return -EFAULT;
            int value = 0;
            if (args[1] == FIONBIO) copy_bytes((unsigned char *)&value, (void *)(uintptr_t)args[2], sizeof(value));
            int network_type = sucrune_guest_network_type(&s->network, resource->handle);
            if (args[1] == FIONBIO && (network_type == SOCK_DGRAM || network_type == SOCK_STREAM)) {
                uint64_t query[6] = {args[0], F_GETFL};
                int64_t flags = descriptor_fcntl(s, query);
                if (flags < 0) return flags;
                query[1] = F_SETFL;
                query[2] = ((uint64_t)flags & ~(uint64_t)O_NONBLOCK) | (value != 0 ? O_NONBLOCK : 0);
                return descriptor_fcntl(s, query);
            }
            if (args[1] == FIONREAD && sucrune_guest_network_echo_domain(&s->network, resource->handle)) {
                /* Query the next packet only. Its private source-address header
                 * is absent from the guest ICMP datagram. */
                unsigned char byte;
                ssize_t framed = recv(resource->handle, &byte, 1, MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT);
                if (framed < 0 && errno != EAGAIN) return -errno;
                if (framed > 0 && framed < (ssize_t)SUCRUNE_NET_ECHO_SOURCE_BYTES) return -EPROTO;
                value = framed <= 0 ? 0 : (int)(framed - SUCRUNE_NET_ECHO_SOURCE_BYTES);
            } else if (ioctl(resource->handle, (unsigned int)args[1], &value) != 0) return -errno;
            if (args[1] == FIONREAD) copy_bytes((void *)(uintptr_t)args[2], (unsigned char *)&value, sizeof(value));
            return 0;
        }
        case 96: /* Never overwrite Android pthread's clear-child-tid address. */
            if (args[0] != 0U && !guest_memory(s, (uintptr_t)args[0], sizeof(int), true)) return -EFAULT;
            if (s->linux_mode) {
                struct sucrune_guest_thread *thread = sucrune_thread_current();
                if (thread != NULL) sucrune_thread_set_clear_tid(thread, (uintptr_t)args[0]);
                else s->main_clear_tid = (uintptr_t)args[0];
                return current_signals(s)->tid;
            }
            return s->gate.thread_id;
        case 168: { /* Linux getcpu: both output pointers are optional. */
            if (!s->linux_mode) return -ENOSYS;
            unsigned int cpu, node;
            if ((args[0] && !guest_memory(s, (uintptr_t)args[0], sizeof(cpu), true)) ||
                (args[1] && !guest_memory(s, (uintptr_t)args[1], sizeof(node), true))) return -EFAULT;
            if (syscall(SYS_getcpu, &cpu, &node, NULL) < 0) return -errno;
            if (args[0]) copy_bytes((void *)(uintptr_t)args[0], (unsigned char *)&cpu, sizeof(cpu));
            if (args[1]) copy_bytes((void *)(uintptr_t)args[1], (unsigned char *)&node, sizeof(node));
            return 0;
        }
        case 172: return syscall(SYS_getpid);
        case 173: return s->linux_mode ? (int64_t)getppid() : -ENOSYS;
        case 154: return s->linux_mode ? sucrune_processes_set_group(s->processes,(int32_t)args[0],(int32_t)args[1]) : -ENOSYS;
        case 155: case 156:
            return s->linux_mode ? sucrune_processes_query_group(s->processes,(int32_t)args[0],operation==156) : -ENOSYS;
        case 160: { /* Same Linux kernel; the guest has a private node name. */
            if (!s->linux_mode) return -ENOSYS;
            struct utsname name;
            _Static_assert(sizeof(name) == 6U * 65U, "ARM64 Linux utsname ABI");
            if (!guest_memory(s, (uintptr_t)args[0], sizeof(name), true)) return -EFAULT;
            if (uname(&name) != 0) return -errno;
            memset(name.nodename, 0, sizeof(name.nodename));
            memcpy(name.nodename, "sucrune", sizeof("sucrune"));
            memset(name.domainname, 0, sizeof(name.domainname));
            memcpy(name.domainname, "(none)", sizeof("(none)"));
            copy_bytes((void *)(uintptr_t)args[0], (unsigned char *)&name, sizeof(name));
            return 0;
        }
        case 179: {
            struct sysinfo data={0};
            _Static_assert(sizeof(data)==112,"Linux arm64 sysinfo ABI");
            if(!s->linux_mode) return -ENOSYS;
            if(!guest_memory(s,(uintptr_t)args[0],sizeof(data),true)) return -EFAULT;
            if(sysinfo(&data)<0) return -errno;
            memcpy((void *)(uintptr_t)args[0],&data,sizeof(data)); return 0;
        }
        case 123: {
            if(!s->linux_mode) return -ENOSYS;
            int64_t tid=current_signals(s)->tid;
            if((int32_t)args[0]!=0 && (int32_t)args[0]!=tid && (int32_t)args[0]!=getpid()) return -ESRCH;
            cpu_set_t mask;
            size_t length=args[1]>sizeof(mask) ? sizeof(mask) : (size_t)args[1];
            long rc=syscall(SYS_sched_getaffinity,(pid_t)args[0],length,&mask);
            if(rc<0) return -errno;
            if(!guest_memory(s,(uintptr_t)args[2],(size_t)rc,true)) return -EFAULT;
            memcpy((void *)(uintptr_t)args[2],&mask,(size_t)rc); return rc;
        }
        case 120: case 121: { /* Query only the calling guest's real host thread. */
            if (!s->linux_mode) return -ENOSYS;
            int64_t tid = current_signals(s)->tid;
            if ((int64_t)args[0] != 0 && (int64_t)args[0] != tid) return -ESRCH;
            if (operation == 120) {
                long result = syscall(SYS_sched_getscheduler, (pid_t)tid);
                return result < 0 ? -errno : result;
            }
            struct sched_param parameter;
            _Static_assert(sizeof(parameter) == sizeof(int32_t), "ARM64 Linux sched_param ABI");
            if (!guest_memory(s, (uintptr_t)args[1], sizeof(parameter), true)) return -EFAULT;
            if (syscall(SYS_sched_getparam, (pid_t)tid, &parameter) != 0) return -errno;
            copy_bytes((void *)(uintptr_t)args[1], (unsigned char *)&parameter, sizeof(parameter));
            return 0;
        }
        case 178: return s->linux_mode ? current_signals(s)->tid : s->gate.thread_id;
        case 158: {
            if (!s->linux_mode) return -ENOSYS;
            if (args[0] > INT32_MAX) return -EINVAL;
            long count = syscall(SYS_getgroups, 0, NULL);
            if (count < 0) return -errno;
            if (args[0] == 0U || count == 0) return count;
            if (args[0] < (uint64_t)count) return -EINVAL;
            if (!guest_memory(s, (uintptr_t)args[1], (size_t)count * sizeof(gid_t), true)) return -EFAULT;
            long result = syscall(SYS_getgroups, count, (void *)(uintptr_t)args[1]);
            return result < 0 ? -errno : result;
        }
        case 174: return syscall(SYS_getuid);
        case 175: return syscall(SYS_geteuid);
        case 176: return syscall(SYS_getgid);
        case 177: return syscall(SYS_getegid);
        case 134: {
            if (!s->linux_mode) return -ENOSYS;
            struct sucrune_signal_memory memory = signal_memory(s);
            int rc=sucrune_signals_action(&s->signal_process,&memory,args[0],(uintptr_t)args[1],(uintptr_t)args[2],args[3]);
            if(rc==0 && args[1] && s->inherited && s->inherited->scope.lease>=0)
                sucrune_scope_disposition((unsigned int)args[0],s->signal_process.actions[args[0]].handler,current_signals(s)->mask);
            return rc;
        }
        case 129: case 130: case 131:
            if (!s->linux_mode) return -ENOSYS;
            if(operation==129) {
                int32_t pid=(int32_t)args[0], signo=(int32_t)args[1];
                if(pid!=(int32_t)getpid()) return sucrune_processes_signal_child(s->processes,pid,signo);
                return sucrune_signals_self(&s->signal_process,current_signals(s),129U,pid,signo,0);
            }
            return sucrune_signals_self(&s->signal_process, current_signals(s), (unsigned int)operation,
                (int64_t)args[0], (int64_t)args[1], (int64_t)args[2]);
        case 135: { /* Private guest mask; never block the host SIGSYS path. */
            if (s->linux_mode) {
                struct sucrune_signal_memory memory = signal_memory(s);
                int rc=sucrune_signals_mask(current_signals(s), &memory, args[0], (uintptr_t)args[1], (uintptr_t)args[2], args[3]);
                if(rc==0 && args[1] && s->inherited && s->inherited->scope.lease>=0) {
                    const unsigned int sigs[]={SIGHUP,SIGINT,SIGTERM};
                    for(size_t i=0;i<3;i++) sucrune_scope_disposition(sigs[i],s->signal_process.actions[sigs[i]].handler,current_signals(s)->mask);
                }
                return rc;
            }
            if (args[3] != sizeof(uint64_t) || args[0] > 2U) return -EINVAL;
            if ((args[1] != 0U && !guest_memory(s, (uintptr_t)args[1], 8U, false)) ||
                (args[2] != 0U && !guest_memory(s, (uintptr_t)args[2], 8U, true))) return -EFAULT;
            uint64_t mask = 0, before = s->guest_signal_mask;
            if (args[1] != 0U) copy_bytes((unsigned char *)&mask, (void *)(uintptr_t)args[1], 8U);
            if (args[2] != 0U) copy_bytes((void *)(uintptr_t)args[2], (unsigned char *)&before, 8U);
            if (args[1] != 0U) {
                if (args[0] == 0U) s->guest_signal_mask |= mask;
                else if (args[0] == 1U) s->guest_signal_mask &= ~mask;
                else s->guest_signal_mask = mask;
                s->guest_signal_mask &= ~((UINT64_C(1) << (SIGKILL - 1)) | (UINT64_C(1) << (SIGSTOP - 1)));
            }
            return 0;
        }
        case 153: { /* times(2), clock ticks from this guest runner's kernel accounting. */
            if (!s->linux_mode) return -ENOSYS;
            struct tms ticks;
            if (args[0] && !guest_memory(s, args[0], sizeof(ticks), true)) return -EFAULT;
            long elapsed = syscall(SYS_times, args[0] ? &ticks : NULL);
            if (elapsed < 0) return -errno;
            if (args[0]) memcpy((void *)(uintptr_t)args[0], &ticks, sizeof(ticks));
            return elapsed;
        }
        case 165: { /* getrusage(2) */
            if (!s->linux_mode) return -ENOSYS;
            struct rusage usage;
            if (!guest_memory(s, args[1], sizeof(usage), true)) return -EFAULT;
            if (syscall(SYS_getrusage, (int)args[0], &usage) < 0) return -errno;
            memcpy((void *)(uintptr_t)args[1], &usage, sizeof(usage));
            return 0;
        }
        case 169: {
            struct timeval now;
            struct timezone zone;
            if ((args[0] != 0U && !guest_memory(s, (uintptr_t)args[0], sizeof(now), true)) ||
                (args[1] != 0U && !guest_memory(s, (uintptr_t)args[1], sizeof(zone), true))) return -EFAULT;
            if (syscall(SYS_gettimeofday, args[0] == 0U ? NULL : &now, args[1] == 0U ? NULL : &zone) != 0) return -errno;
            if (args[0] != 0U) copy_bytes((void *)(uintptr_t)args[0], (unsigned char *)&now, sizeof(now));
            if (args[1] != 0U) copy_bytes((void *)(uintptr_t)args[1], (unsigned char *)&zone, sizeof(zone));
            return 0;
        }
        case 113: case 114: {
            if (args[0] != CLOCK_REALTIME && args[0] != CLOCK_MONOTONIC && args[0] != CLOCK_PROCESS_CPUTIME_ID &&
                args[0] != CLOCK_THREAD_CPUTIME_ID && args[0] != CLOCK_MONOTONIC_RAW &&
                args[0] != CLOCK_REALTIME_COARSE && args[0] != CLOCK_MONOTONIC_COARSE && args[0] != CLOCK_BOOTTIME) return -EINVAL;
            if ((args[1] != 0U || operation == 113) && !guest_memory(s, (uintptr_t)args[1], sizeof(struct timespec), true)) return -EFAULT;
            struct timespec now;
            if (syscall(operation == 113 ? SYS_clock_gettime : SYS_clock_getres, (int)args[0], &now) != 0) return -errno;
            if (args[1] != 0U) copy_bytes((void *)(uintptr_t)args[1], (unsigned char *)&now, sizeof(now));
            return 0;
        }
        case 278: {
            size_t count = args[1] > SUCRUNE_IO_LIMIT ? SUCRUNE_IO_LIMIT : (size_t)args[1];
            if ((args[2] & ~UINT64_C(3)) != 0U) return -EINVAL;
            if (!guest_memory(s, (uintptr_t)args[0], count, true)) return -EFAULT;
            long result = syscall(SYS_getrandom, (void *)(uintptr_t)args[0], count, (unsigned int)args[2]);
            return result < 0 ? -errno : result;
        }
        case 64: case 63: case 61: {
            struct sucrune_fd_resource *resource = sucrune_fds_get(&s->descriptors, args[0]);
            if (resource == NULL) return -EBADF;
            if (operation == 63 && resource->read_fd >= 0) {
                int64_t got = guest_direct_read(s, &resource->read_fd, args, false);
                if (resource->read_fd >= 0) return got;
            }
            if (s->linux_mode && resource->kind == SUCRUNE_FD_LOCAL && operation != 61 &&
                sucrune_guest_network_contains(&s->network, resource->handle)) {
                uint64_t call[6] = {args[0], args[1], args[2], 0U, 0U, 0U};
                return guest_call(s, operation == 63 ? 207 : 206, call);
            }
            if (s->linux_mode && operation == 63 && args[2] > SUCRUNE_IO_LIMIT &&
                resource->kind == SUCRUNE_FD_BROKER && !sucrune_pty_slave_handle(resource->handle))
                return bulk_file_read(s,resource->handle,args[1],args[2],false,0U,&request,&response);
            if (s->linux_mode && operation == 64 && args[2] > SUCRUNE_IO_LIMIT &&
                resource->kind == SUCRUNE_FD_BROKER && !sucrune_pty_slave_handle(resource->handle))
                return bulk_file_write(s,resource->handle,args[1],args[2],false,0U,&request,&response);
            size_t count = args[2] > SUCRUNE_IO_LIMIT ? SUCRUNE_IO_LIMIT : (size_t)args[2];
            /* A zero-length read/write has no guest memory to validate. Still
             * dispatch the operation: bad FDs, access modes and file types
             * must keep their real errors. */
            if (count != 0U && !guest_memory(s, (uintptr_t)args[1], count, operation != 64)) return -EFAULT;
            if(proc_descriptor(s,args[0])!=0) {
                if(operation==64) return -EBADF;
                return sucrune_proc_read(&s->proc,resource->handle,(void *)(uintptr_t)args[1],count,operation==61,-1);
            }
            if (resource->kind != SUCRUNE_FD_BROKER) {
                if (operation == 61) return -ENOTDIR;
                if (resource->kind != SUCRUNE_FD_LOCAL && ((operation == 63 && resource->kind != SUCRUNE_FD_INPUT) ||
                    (operation == 64 && resource->kind == SUCRUNE_FD_INPUT))) return -EBADF;
                if (resource->handle < 0) return 0; /* Shell's initial finite stdin is empty. */
                int handle = resource->handle;
                bool input_resource = resource->kind == SUCRUNE_FD_INPUT;
                if (s->linux_mode) {
                    handle = fcntl(handle, F_DUPFD_CLOEXEC, 16);
                    if (handle < 0) return -errno;
                    (void)pthread_mutex_unlock(&s->state_lock);
                }
                long result;
                do { result = syscall(operation == 63 ? SYS_read : SYS_write,
                    handle, (void *)(uintptr_t)args[1], count); } while (result < 0 && errno == EINTR);
                int saved = errno;
                if (s->linux_mode) { (void)close(handle); (void)pthread_mutex_lock(&s->state_lock); }
                if (operation == 63 && input_resource && result > 0) s->input_read += (uint64_t)result;
                return result < 0 ? -saved : result;
            }
            if (operation!=61 && sucrune_pty_slave_handle(resource->handle))
                return broker_slave_io(s,args[0],operation==64,(uintptr_t)args[1],count);
            request.args[0] = resource->handle; request.args[1] = (int64_t)count;
            if (operation == 64) { copy_bytes(request.data, (void *)(uintptr_t)args[1], count); request.size = (uint32_t)count; }
            else { output = (uintptr_t)args[1]; output_size = count; }
            break;
        }
        case 17:
            output_size = args[1] > SUCRUNE_IO_LIMIT ? SUCRUNE_IO_LIMIT : (size_t)args[1];
            output = (uintptr_t)args[0];
            if (!guest_memory(s, output, output_size, true)) return -EFAULT;
            request.args[0] = (int64_t)output_size;
            break;
        case 56: { // openat: reserve guest capacity before the broker performs file side effects.
            error = proc_at_path_arg(s,&request,args[0],(uintptr_t)args[1]);
            if (error != 0) return -error;
            int available = sucrune_fds_available(&s->descriptors);
            if (available < 0) return available;
            const char *device = s->linux_mode ? sucrune_device_path(request.data) : NULL;
            if (device != NULL) {
                int id = strcmp(device, "/dev/null") == 0 ? SUCRUNE_LL_NULL : SUCRUNE_LL_OTHER_SPECIAL;
                int rc = ll_special_open(s, id, args[2], 0);
                return rc < 0 ? rc : open_guest_device(s, device, args[2]);
            }
            int net_file = s->linux_mode ? sucrune_proc_net_file((const char *)request.data) : 0;
            if (s->linux_mode && !net_file && sucrune_proc_path((const char *)request.data)) {
                int handle;
                int rc=sucrune_proc_open(&s->proc,s->processes,s->broker,(const char *)request.data,args[2],&handle);
                if(rc<0) return rc;
                struct sucrune_arm64_stat st;
                rc = sucrune_proc_stat(&s->proc, handle, &st);
                if (!rc) rc = ll_special_open(s, SUCRUNE_LL_OTHER_SPECIAL, args[2], S_ISDIR(st.mode));
                if (rc < 0) { sucrune_proc_close(&s->proc, handle); return rc; }
                int descriptor=sucrune_fds_add(&s->descriptors,SUCRUNE_FD_LOCAL,handle,(int)(args[2]&(O_DIRECTORY|O_NONBLOCK)),
                    (args[2]&O_CLOEXEC)!=0U?SUCRUNE_FD_CLOEXEC:0U);
                if(descriptor<0) sucrune_proc_close(&s->proc,handle);
                return descriptor;
            }
            if (s->linux_mode && request.data[0]!='/' && proc_descriptor(s,args[0])!=0) return -EOPNOTSUPP;
            if (s->linux_mode && sucrune_pty_path((const char *)request.data)) {
                int rc = ll_special_open(s, SUCRUNE_LL_OTHER_SPECIAL, args[2], 0);
                if (rc < 0) return rc;
                const char *path=(const char *)request.data;
                if (strcmp(path,"/dev/ptmx")==0) return broker_terminal_open(s,-1,args[2],true);
                if (strcmp(path,"/dev/tty")==0) return publish_terminal(s,
                    sucrune_pty_session_open(&s->ptys,&s->descriptors,s->broker,args[2]),args[2]);
                for (size_t i=0;i<SUCRUNE_PTY_ENDPOINTS;i++) if (s->ptys.entries[i].kind==SUCRUNE_PTY_MASTER) {
                    char owned[48]; (void)snprintf(owned,sizeof(owned),"/dev/pts/%d",s->ptys.entries[i].number);
                    if (strcmp(path,owned)==0) return broker_terminal_open(s,s->ptys.entries[i].number,args[2],false);
                }
                return -ENOENT;
            }
            if (net_file) {
                int rc = sucrune_proc_net_open_flags(args[2]);
                if (rc == 0) rc = ll_special_open(s, SUCRUNE_LL_OTHER_SPECIAL, args[2], 0);
                if (rc < 0) return rc;
                request.operation = SUCRUNE_BROKER_PROC_NET_OPEN;
                request.size = 0;
                request.args[0] = net_file;
                request.args[1] = (int64_t)(args[2] & O_CLOEXEC);
                request.args[2] = s->owner.guest_uid;
            } else {
                error = directory_handle(s, args[0], request.data, &request.args[0]);
                if (error != 0) return -error;
                request.args[1] = (int64_t)(args[2] & ~(uint64_t)O_CLOEXEC);
                if (s->linux_mode && (args[2] & O_CREAT) != 0U) {
                    request.args[2] = (int64_t)(args[3] & 0777U);
                    request.args[3] = 1;
                }
            }
            int read_fd;
            int64_t opened = open_project_file(s, &request, &response, &read_fd);
            if (opened < 0) return opened;
            int descriptor = sucrune_fds_add(&s->descriptors, SUCRUNE_FD_BROKER, (int)opened, (int)(args[2] & O_PATH),
                (args[2] & O_CLOEXEC) != 0U ? SUCRUNE_FD_CLOEXEC : 0U);
            if (descriptor < 0) {
                if (read_fd >= 0) (void)close(read_fd);
                (void)release_descriptor(s, SUCRUNE_FD_BROKER, (int)opened);
            } else sucrune_fds_get(&s->descriptors, (uint64_t)descriptor)->read_fd = read_fd;
            return descriptor;
        }
        case 34: // mkdirat
            error = path_arg(s, &request, (uintptr_t)args[1]);
            if (error == 0) error = directory_handle(s, args[0], request.data, &request.args[0]);
            if (s->linux_mode) {
                request.args[2] = (int64_t)(args[2] & 0777U);
                request.args[3] = 1;
            }
            break;
        case SUCRUNE_BROKER_UMASK:
            if (!s->linux_mode) return -ENOSYS;
            request.args[0] = (int64_t)(args[0] & 0777U);
            break;
        case 35: // unlinkat
            request.args[1] = (int64_t)args[2];
            error = path_arg(s, &request, (uintptr_t)args[1]);
            if (error == 0 && s->linux_mode && sucrune_proc_path((const char *)request.data)) return -EROFS;
            if (error == 0) error = directory_handle(s, args[0], request.data, &request.args[0]);
            break;
        case 36: { /* symlinkat(target, dirfd, linkpath): the target is literal. */
            if (!s->linux_mode) return -ENOSYS;
            error = path_arg(s, &request, (uintptr_t)args[0]);
            size_t offset = request.size;
            if (error == 0) error = path_arg(s, &request, (uintptr_t)args[2]);
            if (error == 0 && sucrune_proc_path((const char *)request.data + offset)) return -EROFS;
            if (error == 0) error = directory_handle(s, args[1], request.data + offset, &request.args[0]);
            break;
        }
        case 37: { // linkat: translate guest directory descriptors, never send guest FD numbers as handles.
            if (!s->linux_mode) return -ENOSYS;
            if ((args[4] & ~(uint64_t)(AT_EMPTY_PATH | AT_SYMLINK_FOLLOW)) != 0U) return -EINVAL;
            for (size_t i=0;i<2;i++) {
                size_t offset=request.size;
                error=path_arg(s,&request,(uintptr_t)args[i*2+1]);
                if (error != 0) return -error;
                if(sucrune_proc_path((const char *)request.data+offset)) return -EROFS;
                request.args[i]=AT_FDCWD;
                if (request.data[offset]=='/' || (int)args[i*2]==AT_FDCWD) continue;
                struct sucrune_fd_resource *base=sucrune_fds_get(&s->descriptors,args[i*2]);
                if (!base) return -EBADF;
                if (base->kind!=SUCRUNE_FD_BROKER) return -ENOTDIR;
                request.args[i]=base->handle;
            }
            request.args[2]=(int64_t)args[4];
            break;
        }
        case 38:
            for (size_t i = 0; i < 2U; i++) {
                size_t offset = request.size;
                error = path_arg(s, &request, (uintptr_t)args[i * 2U + 1U]);
                if (error != 0) break;
                if (s->linux_mode && sucrune_proc_path((const char *)request.data + offset)) return -EROFS;
                error = directory_handle(s, args[i * 2U], request.data + offset, &request.args[i]);
                if (error != 0) break;
            }
            break;
        case 49: error = path_arg(s, &request, (uintptr_t)args[0]); break;
        case 50: {
            if (!s->linux_mode) return -ENOSYS;
            struct sucrune_fd_resource *dir = sucrune_fds_get(&s->descriptors, args[0]);
            if (dir == NULL) return -EBADF;
            if (dir->kind != SUCRUNE_FD_BROKER) return -ENOTDIR;
            request.args[0] = dir->handle;
            break;
        }
        case 46: case 47: { // ftruncate/fallocate on the broker-owned open file description
            if (!s->linux_mode) return -ENOSYS;
            struct sucrune_fd_resource *r = sucrune_fds_get(&s->descriptors, args[0]);
            if (r == NULL) return -EBADF;
            if (r->kind != SUCRUNE_FD_BROKER) return -EINVAL;
            request.args[0] = r->handle;
            request.args[1] = (int64_t)args[1];
            if (operation == 47) {
                request.args[2] = (int64_t)args[2];
                request.args[3] = (int64_t)args[3];
            }
            break;
        }
        case SUCRUNE_BROKER_UTIMENSAT: {
            if (!s->linux_mode) return -ENOSYS;
            struct timespec times[2];
            if (args[2] != 0U) {
                if (!guest_memory(s, (uintptr_t)args[2], sizeof(times), false)) return -EFAULT;
                copy_bytes((unsigned char *)times, (const unsigned char *)(uintptr_t)args[2], sizeof(times));
                if (times[0].tv_nsec == UTIME_OMIT && times[1].tv_nsec == UTIME_OMIT) return 0;
            }
            if ((args[3] & ~(uint64_t)(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW)) != 0U) return -EINVAL;
            request.args[1] = (int64_t)args[3];
            if (!args[1]) {
                if ((int32_t)args[0] == AT_FDCWD) return -EFAULT;
                if (args[3] != 0U) return -EINVAL;
                request.args[1] = AT_EMPTY_PATH;
                request.size = 1U; /* already zero-initialized */
            } else {
                error = path_arg(s, &request, (uintptr_t)args[1]);
                if (error != 0) return -error;
                if (sucrune_proc_path((const char *)request.data)) return -EROFS;
            }
            error = directory_handle(s, args[0], request.data, &request.args[0]);
            if (error != 0) return -error;
            if (args[2] != 0U) {
                request.args[2] = 1;
                memcpy(request.data + request.size, times, sizeof(times));
                request.size += (uint32_t)sizeof(times);
            }
            break;
        }
        case 53: { // fchmodat: the ARM64 Linux kernel ABI has three arguments.
            if (!s->linux_mode) return -ENOSYS;
            if ((args[2] & ~UINT64_C(0777)) != 0U) return -EINVAL;
            error = path_arg(s, &request, (uintptr_t)args[1]);
            if (error != 0) return -error;
            if (sucrune_proc_path((const char *)request.data)) return -EROFS;
            error = directory_handle(s, args[0], request.data, &request.args[0]);
            request.args[1] = (int64_t)args[2];
            break;
        }
        case 52: {
            if (!s->linux_mode) return -ENOSYS;
            struct sucrune_fd_resource *resource = sucrune_fds_get(&s->descriptors, args[0]);
            if (resource == NULL) return -EBADF;
            if (resource->kind != SUCRUNE_FD_BROKER) return -EPERM;
            if ((args[1] & ~UINT64_C(0777)) != 0U) return -EINVAL;
            request.args[0] = resource->handle;
            request.args[1] = (int64_t)args[1];
            break;
        }
        case 57: return sucrune_fds_close(&s->descriptors, args[0]);
        case 62: {
            struct sucrune_fd_resource *resource = sucrune_fds_get(&s->descriptors, args[0]);
            if (resource == NULL) return -EBADF;
            if(proc_descriptor(s,args[0])!=0) return sucrune_proc_seek(&s->proc,resource->handle,(int64_t)args[1],(int)args[2]);
            if (s->linux_mode && resource->kind == SUCRUNE_FD_LOCAL) {
                struct stat st;
                if (fstat(resource->handle, &st) == 0 && S_ISCHR(st.st_mode) &&
                    (st.st_rdev == makedev(1, 3) || st.st_rdev == makedev(1, 9))) {
                    off_t offset = lseek(resource->handle, (off_t)args[1], (int)args[2]);
                    return offset < 0 ? -errno : offset;
                }
            }
            if (resource->kind != SUCRUNE_FD_BROKER) return -ESPIPE;
            request.args[0] = resource->handle; request.args[1] = (int64_t)args[1]; request.args[2] = (int64_t)args[2]; break;
        }
        case 101: case 115: {
            const bool clock_sleep = operation == 115;
            if (clock_sleep && !s->linux_mode) return -ENOSYS;
            const int clock = clock_sleep ? (int)args[0] : CLOCK_MONOTONIC;
            if (clock != CLOCK_MONOTONIC && clock != CLOCK_REALTIME && clock != CLOCK_BOOTTIME) return -EINVAL;
            if (clock_sleep && (args[1] & ~(uint64_t)TIMER_ABSTIME) != 0U) return -EINVAL;
            const bool absolute = clock_sleep && args[1] == TIMER_ABSTIME;
            const uintptr_t input = (uintptr_t)args[clock_sleep ? 2 : 0];
            const uintptr_t remaining = absolute ? 0U : (uintptr_t)args[clock_sleep ? 3 : 1];
            if (!guest_memory(s, input, sizeof(struct timespec), false) ||
                (remaining != 0U && !guest_memory(s, remaining, sizeof(struct timespec), true))) return -EFAULT;
            struct timespec delay, remain = {0};
            copy_bytes((unsigned char *)&delay, (const unsigned char *)input, sizeof(delay));
            if (delay.tv_sec < 0 || delay.tv_nsec < 0 || delay.tv_nsec >= 1000000000L) return -EINVAL;
            if (absolute) {
                struct timespec now;
                if (clock_gettime(clock, &now) != 0) return -errno;
                if (delay.tv_sec > now.tv_sec) {
                    uint64_t seconds = (uint64_t)delay.tv_sec - (uint64_t)now.tv_sec;
                    if (seconds > 60U || (seconds == 60U && delay.tv_nsec > now.tv_nsec)) return -EINVAL;
                }
            } else if (delay.tv_sec > 60) return -EINVAL;
            if (s->linux_mode) (void)pthread_mutex_unlock(&s->state_lock);
            long result = clock_sleep ? syscall(SYS_clock_nanosleep, clock, (int)args[1], &delay, &remain) :
                                        syscall(SYS_nanosleep, &delay, &remain);
            int saved = errno;
            if (s->linux_mode) (void)pthread_mutex_lock(&s->state_lock);
            if (result < 0 && saved == EINTR && remaining != 0U) {
                if (!guest_memory(s, remaining, sizeof(remain), true)) return -EFAULT;
                copy_bytes((void *)remaining, (const unsigned char *)&remain, sizeof(remain));
            }
            return result < 0 ? -saved : result;
        }
        case 48: case 439: {
            if (!s->linux_mode) return -ENOSYS;
            const uint64_t allowed = AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;
            uint64_t flags = operation == 439 ? args[3] : 0U;
            if ((args[2] & ~UINT64_C(7)) != 0U || (flags & ~allowed) != 0U) return -EINVAL;
            error = proc_at_path_arg(s,&request,args[0],(uintptr_t)args[1]);
            if (error != 0) return -error;
            const char *path = (const char *)request.data;
            const char *device = sucrune_device_path(request.data);
            if (device != NULL) {
                if (sucrune_device_readonly(device) && (args[2] & W_OK)) return -EACCES;
                return access(device, (int)args[2]) == 0 ? 0 : -errno;
            }
            if(sucrune_proc_path(path)) {
                struct sucrune_arm64_stat st;
                int rc=proc_path_stat(s,path,&st);
                if(rc!=0) return rc;
                if((args[2]&W_OK)!=0U || ((args[2]&X_OK)!=0U && (st.mode&S_IFMT)!=S_IFDIR)) return -EACCES;
                return 0;
            }
            if (path[0] == '\0' && (flags & AT_EMPTY_PATH) == 0U) return -ENOENT;
            request.args[0] = (int64_t)args[0];
            if (path[0] != '/' && (int64_t)args[0] != AT_FDCWD) {
                struct sucrune_fd_resource *resource = sucrune_fds_get(&s->descriptors, args[0]);
                if (resource == NULL) return -EBADF;
                if (resource->kind != SUCRUNE_FD_BROKER) return path[0] == '\0' ? -ENOTSUP : -ENOTDIR;
                request.args[0] = resource->handle;
            }
            request.args[1] = (int64_t)args[2]; request.args[2] = (int64_t)flags;
            break;
        }
        case 78: {
            if (!s->linux_mode) return -ENOSYS;
            if (args[3] == 0U) return -EINVAL;
            output_size = args[3] > SUCRUNE_IO_LIMIT ? SUCRUNE_IO_LIMIT : (size_t)args[3];
            output = (uintptr_t)args[2];
            if (!guest_memory(s, output, output_size, true)) return -EFAULT;
            error = path_arg(s, &request, (uintptr_t)args[1]);
            if (error != 0) return -error;
            const char *path = (const char *)request.data;
            if (sucrune_device_path(request.data) != NULL) return -EINVAL;
            if (strcmp(path, "/proc/self/exe") == 0) {
                if (s->current_program == NULL || s->current_program->path == NULL) return -ENOENT;
                size_t bytes = strlen(s->current_program->path);
                if (bytes > output_size) bytes = output_size;
                copy_bytes((void *)output, (const unsigned char *)s->current_program->path, bytes);
                return (int64_t)bytes; /* No NUL; readlink truncation is successful. */
            }
            if(sucrune_proc_path(path)) return -ENOENT;
            request.args[0] = (int64_t)args[0];
            if (path[0] != '/' && (int64_t)args[0] != AT_FDCWD) {
                struct sucrune_fd_resource *resource = sucrune_fds_get(&s->descriptors, args[0]);
                if (resource == NULL) return -EBADF;
                if (resource->kind != SUCRUNE_FD_BROKER) return path[0] == '\0' ? -ENOENT : -ENOTDIR;
                request.args[0] = resource->handle;
            }
            request.args[1] = (int64_t)output_size;
            break;
        }
        default: s->unsupported++; s->last_unsupported = operation; return -ENOSYS;
    }
    if (error != 0) return -error;
    if(s->linux_mode && (operation==34 || operation==35 || operation==49) &&
       sucrune_proc_path((const char *)request.data)) return operation==49?-EOPNOTSUPP:-EROFS;
    int64_t result = exchange(s->broker, &request, &response);
    if (result >= 0 && output != 0U) {
        bool stat_result = operation == 79 || operation == 80;
        if ((stat_result ? (result != 0 || response.size != sizeof(struct sucrune_arm64_stat)) : ((uint64_t)result != response.size)) || response.size > output_size) return -EIO;
        if (s->linux_mode && stat_result) {
            struct sucrune_arm64_stat st;
            memcpy(&st, response.data, sizeof(st));
            sucrune_project_stat_owner(&st, &s->owner);
            copy_bytes((void *)output, (const unsigned char *)&st, sizeof(st));
        } else {
            copy_bytes((void *)output, response.data, response.size);
        }
    }
    return result;
}

static _Noreturn void process_group_exit(struct shell_state *s, int code, int termination) {
    struct sucrune_thread_stats stats = {0};
    sucrune_threads_stats(s->threads, &stats);
    char report[3072];
    (void)snprintf(report, sizeof(report),
        "{\"schema_version\":1,\"kind\":\"linux\",\"status\":\"%s\",\"exit_code\":%d,"
        "\"stage\":\"process_exit_group\",\"message\":\"The runner will exit and the parent must reap the entire process.\","
        "\"error_number\":%d,\"pid\":%ld,\"uid\":%ld,\"syscalls\":%llu,\"page_size\":%ld,"
        "\"cleanup_mode\":\"process_exit_group\",\"thread_joined\":false,\"handler_restored\":false,"
        "\"descendant_waits_before_exit\":\"not_verified\","
        "\"memory_policy\":\"%s\","
        "\"returned_to_host\":false,\"report_on_host_tls\":true,\"on_alt_stack\":true,"
        "\"threads_created\":%u,\"threads_joined\":%u,\"threads_live_before_exit\":%u,\"threads_peak\":%u,"
        "\"fd_limit\":%u,\"fd_peak\":%u,\"fds_live_before_exit\":%u,\"resources_live_before_exit\":%u,\"termination_signal\":%d,"
        "\"signal_deliveries\":%u,\"signal_returns\":%u,\"unsupported_syscalls\":%llu,\"last_unsupported_syscall\":%d,"
        "\"stdin_bytes_read\":%llu,\"direct_read_calls\":%llu,\"direct_read_bytes\":%llu,\"guest_direct_read_bytes\":%llu}",
        s->error == 0 ? "exited" : "failed", code, s->error, (long)getpid(), (long)getuid(), (unsigned long long)s->syscalls, s->page,
        s->linux_allow_rwx ? "linux-jit" : "wx", stats.created, stats.joined, stats.live, stats.peak,
        s->descriptors.limit, s->descriptors.peak, s->descriptors.count, s->descriptors.resource_count,
        termination, s->signal_deliveries, s->signal_returns, (unsigned long long)s->unsupported, (int)s->last_unsupported,
        (unsigned long long)s->input_read, (unsigned long long)s->direct_read_calls, (unsigned long long)s->direct_read_bytes,
        (unsigned long long)s->guest_direct_read_bytes);
    if (s->inherited!=NULL) sucrune_exec_child_exit(s->error==0 ? code : 126,termination);
    sucrune_linux_exit_group(report);
}
static void return_to_host(struct shell_state *s, ucontext_t *uc) {
    struct sucrune_guest_thread *thread = sucrune_thread_current();
    if (thread != NULL) { sucrune_thread_exit(thread, uc); return; }
    uc->uc_mcontext.regs[0] = (uint64_t)(uintptr_t)&s->host;
    uc->uc_mcontext.sp = s->host.sp;
    uc->uc_mcontext.pc = (uint64_t)(uintptr_t)&sucrune_guest_return;
}
static void signal_bridge(struct shell_state *s, ucontext_t *uc, int returning) {
    struct sucrune_signal_cpu cpu;
    struct sucrune_signal_thread *signals = current_signals(s);
    int error = sucrune_thread_cpu_capture(uc, &cpu);
    struct sucrune_signal_memory memory = signal_memory(s);
    if (error == 0 && returning) {
        error = sucrune_signals_return(signals, &memory, &cpu);
        if (error == 0) s->signal_returns++;
    }
    int termination = 0, delivery = SUCRUNE_SIGNAL_NONE;
    if (error == 0) {
        delivery = sucrune_signals_deliver(&s->signal_process, signals, &memory, &cpu, &termination);
        if (delivery < 0) error = delivery;
    }
    if (error == 0 && delivery != SUCRUNE_SIGNAL_TERMINATE) error = sucrune_thread_cpu_apply(uc, &cpu);
    if (error != 0) {
        s->stage = "guest_signal"; s->message = "Cannot restore or deliver the Linux signal frame."; s->error = -error;
        struct sucrune_thread_stats stats = {0}; sucrune_threads_stats(s->threads, &stats);
        if (stats.created != stats.joined) process_group_exit(s, 159, 0);
        return_to_host(s, uc);
    } else if (delivery == SUCRUNE_SIGNAL_TERMINATE) {
        s->termination_signal = termination; s->exited = 1; s->exit_code = 128 + termination;
        struct sucrune_thread_stats stats = {0}; sucrune_threads_stats(s->threads, &stats);
        if (stats.created != stats.joined) process_group_exit(s, 128 + termination, termination);
        return_to_host(s, uc);
    } else if (delivery == SUCRUNE_SIGNAL_ENTERED) s->signal_deliveries++;
}
static void handle_shell(int number, siginfo_t *info, void *context) {
    struct shell_state *s = atomic_load_explicit(&active_shell, memory_order_acquire);
    if (number != SIGSYS || info == NULL || context == NULL || s == NULL ||
        info->si_code != SYS_SECCOMP || info->si_errno != (int)SHELL_TAG || info->si_arch != AUDIT_ARCH_AARCH64) _exit(159);
    ucontext_t *uc = context;
    if (s->linux_mode && pthread_mutex_lock(&s->state_lock) != 0) _exit(159);
    struct sucrune_guest_thread *thread = s->linux_mode ? sucrune_thread_current() : NULL;
    struct sucrune_signal_gate *gate = thread == NULL ? &s->gate : sucrune_thread_gate(thread);
    if (s->linux_mode) {
        if (!linux_executable_resume(s, (uintptr_t)uc->uc_mcontext.pc)) _exit(159);
    } else if (!in_range((uintptr_t)s->image.base, s->image.size, (uintptr_t)uc->uc_mcontext.pc, 0U)) _exit(159);
    unsigned char marker;
    if (thread == NULL ? !in_range(s->alt_low, s->alt_high - s->alt_low, (uintptr_t)&marker, 1U) : !sucrune_thread_on_altstack(thread, (uintptr_t)&marker)) _exit(159);
    s->alt_seen = 1;
    if (gate->last_guest_tpidr != gate->host->tpidr_el0) s->tls_seen = 1;
    s->syscalls++;
    if (info->si_syscall == 93 || info->si_syscall == 94) {
        int code = (int)(uc->uc_mcontext.regs[0] & 255U);
        struct sucrune_thread_stats stats = {0}; sucrune_threads_stats(s->threads, &stats);
        if (s->linux_mode && info->si_syscall == 94 && stats.created != stats.joined) process_group_exit(s, code, 0);
        if (thread == NULL) { s->exited = 1; s->exit_code = code; }
        return_to_host(s, uc);
    } else if (s->linux_mode && info->si_syscall == 220) {
        struct sucrune_signal_cpu cpu;
        int error = sucrune_thread_cpu_capture(uc, &cpu);
        uint64_t flags = uc->uc_mcontext.regs[0];
        uintptr_t stack = (uintptr_t)uc->uc_mcontext.regs[1], ptid = (uintptr_t)uc->uc_mcontext.regs[2];
        uintptr_t tls = (uintptr_t)uc->uc_mcontext.regs[3], ctid = (uintptr_t)uc->uc_mcontext.regs[4];
        if ((flags & CLONE_THREAD) == 0U) {
            struct sucrune_vfork_lease lease = {.read_fd = -1};
            int64_t result = error;
            /* Linux ignores parent_tid and TLS arguments without their
             * corresponding flags. glibc's vfork clone uses a child stack,
             * while Go passes a null stack and an unused parent_tid address. */
            if (result == 0 && stack != 0U) {
                if ((flags & (CLONE_VM|CLONE_VFORK)) != (CLONE_VM|CLONE_VFORK)) {
                    if (s->trace_faults) {
                        static const char message[]="[sucrune-fork] unsupported clone-stack\n";
                        (void)write(s->error_output,message,sizeof(message)-1U);
                    }
                    result = -EOPNOTSUPP;
                }
                else if (stack < 16U || (stack & 15U) != 0U || !guest_memory(s,stack-16U,16U,true)) result = -EFAULT;
                else cpu.sp = stack;
            }
            if (result == 0) {
                struct sucrune_process_snapshot snapshot = {.cpu=cpu, .tls=gate->last_guest_tpidr,
                    .child_tid=ctid, .flags=flags, .space=&s->space, .fixed_space=&s->fixed_space, .descriptors=&s->descriptors,
                    .trace_syscalls=s->trace_syscalls, .trace_faults=s->trace_faults, .build_profile=s->build_profile,
                    .broker=s->broker, .owner=s->owner, .signal_mask=current_signals(s)->mask, .signal_actions=&s->signal_process,
                    .signal_stack=current_signals(s)->altstack,
                    .ptys=&s->ptys, .network=&s->network, .runner=sucrune_linux_runner_path(), .linux_jit=s->linux_allow_rwx ? 1U : 0U,
                    .exec_depth=(unsigned int)s->exec_count};
                /* The supervisor forks without acquiring this lock. Keep each
                 * VMA and open-description alias stable through the COW cut. */
                result = sucrune_processes_fork(s->processes, &snapshot, &lease);
            }
            uc->uc_mcontext.regs[0] = (uint64_t)result;
            (void)pthread_mutex_unlock(&s->state_lock);
            sucrune_processes_finish_vfork(&lease);
            return;
        }
        if ((flags & CLONE_SETTLS) == 0U) tls = gate->last_guest_tpidr;
        if (error == 0 && (stack < 16U || !guest_memory(s, stack - 16U, 16U, true) ||
            (tls != 0U && !guest_memory(s, tls, 1U, false)))) error = -EFAULT;
        if (error == 0 && (((flags & CLONE_PARENT_SETTID) != 0U && !guest_memory(s, ptid, 4U, true)) ||
            ((flags & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID)) != 0U && !guest_memory(s, ctid, 4U, true)))) error = -EFAULT;
        int64_t result = error;
        if (error == 0) {
            uint64_t mask = current_signals(s)->mask;
            (void)pthread_mutex_unlock(&s->state_lock);
            result = sucrune_threads_clone(s->threads, flags, stack, ptid, tls, ctid, mask, &cpu);
            (void)pthread_mutex_lock(&s->state_lock);
        }
        uc->uc_mcontext.regs[0] = (uint64_t)result;
    } else if (s->linux_mode && info->si_syscall == 72) {
        struct sucrune_signal_thread *signals=current_signals(s);
        uint64_t original=signals->mask;
        unsigned int depth=signals->depth;
        uint64_t args[6];
        for(size_t i=0;i<6;i++) args[i]=uc->uc_mcontext.regs[i];
        int saved=errno;
        int result=guest_pselect(s,args);
        errno=saved;
        uc->uc_mcontext.regs[0]=(uint64_t)(int64_t)result;
        collect_child_signal(s);
        if(signals->pending!=0U) signal_bridge(s,uc,0);
        if(signals->depth>depth) {
            struct sucrune_signal_frame *frame=(void *)signals->frames[depth];
            frame->context.mask=original;
        } else signals->mask=original;
    } else if (s->linux_mode && info->si_syscall == 139) {
        signal_bridge(s, uc, 1);
    } else {
        uint64_t args[6];
        for (size_t i = 0; i < 6U; i++) args[i] = uc->uc_mcontext.regs[i];
        int saved = errno;
        int64_t result;
        if (s->linux_mode && info->si_syscall == 132) {
            struct sucrune_signal_memory memory = signal_memory(s);
            result = sucrune_signals_altstack(&current_signals(s)->altstack, &memory,
                (uintptr_t)uc->uc_mcontext.sp, (uintptr_t)args[0], (uintptr_t)args[1]);
        } else result = guest_call(s, info->si_syscall, args);
        if (s->trace_syscalls && s->syscalls <= 4096) {
            char line[80];
            int length = snprintf(line, sizeof(line), "[sucrune %llu] syscall %d errno %d\n",
                (unsigned long long)s->syscalls, info->si_syscall, result < 0 && result >= -4095 ? (int)-result : 0);
            if (length > 0 && (size_t)length < sizeof(line)) (void)write(s->error_output, line, (size_t)length);
        }
        errno = saved;
        if (s->exec_pending != 0) {
            /* Successful exec never resumes the old instruction. Leave the
             * signal frame first; teardown/loading run on the host stack/TLS. */
            uc->uc_mcontext.regs[0] = (uint64_t)(uintptr_t)&s->host;
            uc->uc_mcontext.sp = s->host.sp;
            uc->uc_mcontext.pc = (uint64_t)(uintptr_t)&sucrune_guest_return;
        } else {
            uc->uc_mcontext.regs[0] = (uint64_t)result;
            if (s->linux_mode) collect_child_signal(s);
            if (s->linux_mode && current_signals(s)->pending != 0U) signal_bridge(s, uc, 0);
        }
    }
    if (s->linux_mode) (void)pthread_mutex_unlock(&s->state_lock);
}

static int filter(const struct sucrune_elf_image *image) {
    uintptr_t low = (uintptr_t)image->base, high = low + image->size;
    if ((low >> 32U) != (high >> 32U)) { errno = ERANGE; return -1; }
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (unsigned int)offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (unsigned int)offsetof(struct seccomp_data, instruction_pointer) + 4U),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)(low >> 32U), 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (unsigned int)offsetof(struct seccomp_data, instruction_pointer)),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, (uint32_t)low, 0, 2),
        BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, (uint32_t)high, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP | SHELL_TAG),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = { .len = (unsigned short)(sizeof(code) / sizeof(code[0])), .filter = code };
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}
static size_t filter_range(struct sock_filter *code, uintptr_t low, uintptr_t high) {
    const unsigned int ip = (unsigned int)offsetof(struct seccomp_data, instruction_pointer);
    struct sock_filter block[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, ip + 4U),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, (uint32_t)(low >> 32U), 0, 9),
        BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, (uint32_t)(high >> 32U), 8, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)(low >> 32U), 0, 2),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, ip),
        BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, (uint32_t)low, 0, 5),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, ip + 4U),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)(high >> 32U), 0, 2),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, ip),
        BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, (uint32_t)high, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP | SHELL_TAG),
    };
    memcpy(code, block, sizeof(block)); return sizeof(block) / sizeof(block[0]);
}
static int linux_filter(const struct shell_state *s) {
    struct sock_filter code[32] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (unsigned int)offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    };
    size_t used = 3U;
    used += filter_range(code + used, s->space.base, s->space.base + s->space.size);
    if (s->fixed_space.base != 0U) used += filter_range(code + used, s->fixed_space.base, s->fixed_space.base + s->fixed_space.size);
    code[used++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    struct sock_fprog program = { .len = (unsigned short)used, .filter = code };
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}
static int guarded(size_t usable, long page, void **mapping, size_t *size, uintptr_t *low, uintptr_t *high) {
    *size = usable + 2U * (size_t)page;
    void *memory = mmap(NULL, *size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) return -1;
    *mapping = memory; *low = (uintptr_t)memory + (size_t)page; *high = *low + usable;
    return mprotect((void *)*low, usable, PROT_READ | PROT_WRITE);
}
static uintptr_t push_string(uintptr_t *cursor, const char *value) {
    size_t length = strlen(value) + 1U; *cursor -= length;
    memcpy((void *)*cursor, value, length); return *cursor;
}
static int prepare_stack(struct shell_state *s, size_t argc, const char *const *argv,
        size_t envc, const char *const *envp, const char *execfn) {
    if (s->linux_mode) {
        s->stack_size = STACK_SIZE + 2U * (size_t)s->page;
        int64_t mapped = sucrune_space_map(&s->space, 0U, s->stack_size, 0U, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS);
        if (mapped < 0) { errno = (int)-mapped; return -1; }
        s->stack = (void *)(uintptr_t)mapped; s->stack_low = (uintptr_t)mapped + (size_t)s->page; s->stack_high = s->stack_low + STACK_SIZE;
        int error = sucrune_space_protect(&s->space, s->stack_low, STACK_SIZE, PROT_READ | PROT_WRITE);
        if (error != 0) { errno = -error; return -1; }
    } else if (guarded(STACK_SIZE, s->page, &s->stack, &s->stack_size, &s->stack_low, &s->stack_high) != 0) return -1;
    uintptr_t cursor = s->stack_high;
    uintptr_t executable_name = push_string(&cursor, execfn);
    cursor = (cursor - 16U) & ~(uintptr_t)15U;
    uintptr_t random = cursor;
    long result = syscall(SYS_getrandom, (void *)random, 16U, 0U);
    if (result != 16) { if (result >= 0) errno = EIO; return -1; }
    uint64_t auxiliary[] = {
        AT_PHDR, s->image.phdr, AT_PHENT, s->image.phentsize, AT_PHNUM, s->image.phnum,
        AT_PAGESZ, (uint64_t)s->page, AT_BASE, s->interpreter.load_bias, AT_ENTRY, s->image.entry,
        AT_UID, getuid(), AT_EUID, geteuid(), AT_GID, getgid(), AT_EGID, getegid(), AT_SECURE, 0,
        /* The normalized signal/clone profile preserves FPSIMD, not SVE/SME.
         * Advertise conservative guest capabilities so libc/V8 do not select
         * vector state that this runtime cannot restore. */
        AT_HWCAP, s->linux_mode ? getauxval(AT_HWCAP) & ~(unsigned long)HWCAP_SVE : getauxval(AT_HWCAP),
        AT_HWCAP2, s->linux_mode ? 0U : getauxval(AT_HWCAP2),
        AT_RANDOM, random, AT_EXECFN, executable_name, AT_NULL, 0 };
    /* Leave the pointer/auxv table directly on the guest stack so hundreds
     * of source-file arguments do not require a second array on a host stack. */
    size_t text_size = 0;
    for (size_t i=0; i<argc; i++) text_size += strlen(argv[i]) + 1U;
    for (size_t i=0; i<envc; i++) text_size += strlen(envp[i]) + 1U;
    size_t vector_size = (argc + envc + 3U) * sizeof(uint64_t) + sizeof(auxiliary);
    if (text_size + vector_size + 15U > cursor - s->stack_low) { errno = E2BIG; return -1; }
    s->stack_pointer = (cursor - text_size - vector_size) & ~(uintptr_t)15U;
    uint64_t *words = (uint64_t *)s->stack_pointer;
    uint64_t *args = words + 1;
    uint64_t *environment = args + argc + 1;
    words[0] = argc;
    args[argc] = 0;
    environment[envc] = 0;
    memcpy(environment + envc + 1, auxiliary, sizeof(auxiliary));
    /* Linux stores the actual strings in ascending argv order, then envp.
     * libuv uses this contiguous argv span to update the process title. */
    for (size_t i = envc; i > 0; --i) environment[i - 1] = push_string(&cursor, envp[i - 1]);
    for (size_t i = argc; i > 0; --i) args[i - 1] = push_string(&cursor, argv[i - 1]);
    return 0;
}
static void problem(struct shell_state *s, const char *stage, const char *message, int error) {
    s->stage = stage; s->message = message; s->error = error;
}
static int linux_image_bytes(struct shell_state *s, const char *path, unsigned int index, void **bytes, size_t *size) {
    if (s->exec_pending) {
        *bytes = s->pending.images[index];
        *size = s->pending.image_sizes[index];
        s->pending.images[index] = NULL;
        return *bytes == NULL ? ENOEXEC : 0;
    }
    if (s->inherited != NULL)
        return sucrune_exec_read_snapshot(index == 0U ? s->inherited->image_fd : s->inherited->interp_fd, bytes, size);
    return index == 0U ? snapshot_program(s, path, bytes, size) : snapshot_file(s, path, bytes, size, NULL);
}
static int load_linux_image(struct shell_state *s, const char *path) {
    void *bytes = NULL; size_t size = 0;
    int error = linux_image_bytes(s, path, 0, &bytes, &size);
    if (error != 0) { problem(s, "linux_snapshot", "Cannot read project ELF.", error); return -1; }
    struct sucrune_linux_plan plan;
    enum sucrune_elf_error valid = sucrune_linux_validate(bytes, size, (size_t)s->page, &plan);
    if (valid != SUCRUNE_ELF_OK) { free(bytes); problem(s, "linux_elf", sucrune_elf_error_message(valid), ENOEXEC); return -1; }
    if (!s->exec_pending) {
        error = sucrune_space_init(&s->space, (size_t)64U * 1024U * 1024U * 1024U, (size_t)s->page);
        if (error == 0 && s->linux_allow_rwx) error = sucrune_space_set_rwx_policy(&s->space, 1);
    }
    struct sucrune_guest_space *target = &s->space;
    if (error == 0 && plan.load.fixed_address) {
        if (!s->exec_pending)
            error = sucrune_space_init_exact(&s->fixed_space, plan.load.virtual_base, plan.load.image_size, (size_t)s->page);
        target = &s->fixed_space;
    }
    if (error != 0) { free(bytes); problem(s, "linux_reserve", "Cannot reserve Linux guest address space.", -error); return -1; }
    valid = sucrune_linux_map(bytes, size, &plan, target, &s->image);
    free(bytes); bytes = NULL;
    if (valid != SUCRUNE_ELF_OK) { problem(s, "linux_map", sucrune_elf_error_message(valid), errno); return -1; }
    s->linux_entry = s->image.entry;
    if (!s->exec_pending && s->inherited!=NULL && (s->inherited->interp_fd>=0)!=(plan.interpreter[0]!='\0')) {
        problem(s,"linux_interpreter","Inherited interpreter snapshot does not match the ELF.",ENOEXEC); return -1;
    }
    if (plan.interpreter[0] != '\0') {
        error = linux_image_bytes(s, plan.interpreter, 1, &bytes, &size);
        if (error != 0) { problem(s, "linux_interpreter", "Cannot read the requested Linux interpreter.", error); return -1; }
        struct sucrune_linux_plan interpreter;
        valid = sucrune_linux_validate(bytes, size, (size_t)s->page, &interpreter);
        if (valid != SUCRUNE_ELF_OK || interpreter.load.fixed_address || interpreter.interpreter[0] != '\0') {
            free(bytes); problem(s, "linux_interpreter", "Interpreter must be a valid ET_DYN without PT_INTERP.", ENOEXEC); return -1;
        }
        valid = sucrune_linux_map(bytes, size, &interpreter, &s->space, &s->interpreter);
        free(bytes);
        if (valid != SUCRUNE_ELF_OK) { problem(s, "linux_interpreter_map", sucrune_elf_error_message(valid), errno); return -1; }
        s->linux_entry = s->interpreter.entry;
    }
    int64_t trampoline = sucrune_space_map(&s->space, 0U, (size_t)s->page, 0U, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS);
    if (trampoline < 0) { problem(s, "linux_signal_trampoline", "Cannot reserve the guest signal restorer.", (int)-trampoline); return -1; }
    const uint32_t restorer[] = {UINT32_C(0xd2801168), UINT32_C(0xd4000001), UINT32_C(0xd4200000)};
    memcpy((void *)(uintptr_t)trampoline, restorer, sizeof(restorer));
    error = sucrune_space_protect(&s->space, (uintptr_t)trampoline, (size_t)s->page, PROT_READ | PROT_EXEC);
    if (error != 0) { problem(s, "linux_signal_trampoline", "Cannot protect the guest signal restorer.", -error); return -1; }
    s->signal_restorer = (uintptr_t)trampoline;
    int64_t brk = sucrune_space_map(&s->space, 0U, 64U * 1024U * 1024U, 0U, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS);
    if (brk < 0) { problem(s, "linux_brk", "Cannot reserve initial Linux data break.", (int)-brk); return -1; }
    s->linux_brk_base = s->linux_brk = (uintptr_t)brk;
    return 0;
}
static int load_image(struct shell_state *s, const struct sucrune_program *program) {
    if (s->linux_mode) return load_linux_image(s, program->path);
    size_t size = (size_t)((uintptr_t)program->end - (uintptr_t)program->start);
    if (program->static_program != 0 && s->parser_checks == 0) {
        s->parser_checks = sucrune_elf_program_selftest();
        if (s->parser_checks == 0) { problem(s, "parser_selftest", "Static program parser self-test failed.", EINVAL); return -1; }
    }
    enum sucrune_elf_error load = program->static_program != 0 ?
        sucrune_elf_load_program(program->start, size, &s->image) : sucrune_elf_load(program->start, size, &s->image);
    if (load != SUCRUNE_ELF_OK) {
        problem(s, "elf_load", sucrune_elf_error_message(load),
            (load == SUCRUNE_ELF_MAP_FAILED || load == SUCRUNE_ELF_PROTECT_FAILED) ? errno : 0);
        return -1;
    }
    if (program->static_program != 0) {
        struct sucrune_elf_image collision;
        uint32_t before = *(const uint32_t *)s->image.entry;
        enum sucrune_elf_error duplicate = sucrune_elf_load_program(program->start, size, &collision);
        s->collision_rejected = duplicate == SUCRUNE_ELF_MAP_FAILED && errno == EADDRINUSE && *(const uint32_t *)s->image.entry == before;
        sucrune_elf_unload(&collision);
        if (!s->collision_rejected) { problem(s, "image_collision", "Fixed image collision was not rejected safely.", EINVAL); return -1; }
    }
    return 0;
}
static int release_guest(struct shell_state *s) {
    int result = 0;
    if (s->linux_mode) {
        s->heap_peak = s->space.peak_accessible_bytes + s->fixed_space.peak_accessible_bytes;
        int first = sucrune_space_destroy(&s->space), second = sucrune_space_destroy(&s->fixed_space);
        memset(&s->image, 0, sizeof(s->image)); memset(&s->interpreter, 0, sizeof(s->interpreter));
        s->stack = NULL; s->stack_size = 0;
        if (first != 0 || second != 0) { problem(s, "linux_cleanup", "Cannot release guest address reservations.", first != 0 ? -first : -second); return -1; }
        return 0;
    }
    if (s->memory.peak > s->heap_peak) s->heap_peak = s->memory.peak;
    if (s->stack != NULL) {
        if (munmap(s->stack, s->stack_size) != 0) { problem(s, "cleanup", "Cannot release guest stack.", errno); result = -1; }
        else { s->stack = NULL; s->stack_size = 0; s->stack_low = 0; s->stack_high = 0; s->stack_pointer = 0; }
    }
    sucrune_elf_unload(&s->image);
    sucrune_memory_destroy(&s->memory);
    memset(&s->memory, 0, sizeof(s->memory));
    return result;
}
static int replace_guest(struct shell_state *s) {
    /* The signal trampoline has committed to replacement. Fixed ET_EXEC images
     * share an address, so teardown precedes loading; a subsequent resource or
     * broker failure terminates this execution instead of returning into freed
     * code. Invalid path/vector requests never reach this point. */
    const struct sucrune_program *target = s->pending.program;
    if (s->linux_mode) {
        // Keep both reservations: stacked seccomp filters continue to own these ranges.
        int error = sucrune_space_unmap(&s->space, s->space.base, s->space.size);
        if (error == 0 && s->fixed_space.base != 0U)
            error = sucrune_space_unmap(&s->fixed_space, s->fixed_space.base, s->fixed_space.size);
        if (error != 0) { problem(s, "exec_memory", "Cannot reset guest address space.", -error); return -1; }
        memset(&s->image, 0, sizeof(s->image));
        memset(&s->interpreter, 0, sizeof(s->interpreter));
        memcpy(s->replaced_path, s->pending.linux_path, strlen(s->pending.linux_path) + 1U);
        s->replaced_program = *s->current_program;
        s->replaced_program.path = s->replaced_path;
        target = &s->replaced_program;
        s->main_clear_tid = 0;
        s->signal_thread.depth = 0;
        s->signal_thread.altstack = (struct sucrune_signal_stack){0};
        for (unsigned int sig = 1; sig <= SUCRUNE_SIGNAL_COUNT; sig++) {
            if (s->signal_process.actions[sig].handler != 1U)
                s->signal_process.actions[sig] = (struct sucrune_signal_action){0};
        }
    } else if (release_guest(s) != 0) return -1;
    if (load_image(s, target) != 0) return -1;
    if (!s->linux_mode && target->static_program != 0 && sucrune_memory_init(&s->memory, (size_t)s->page) != 0) {
        problem(s, "exec_memory", "Cannot reserve replacement guest memory.", errno); return -1;
    }
    if (prepare_stack(s, s->pending.argc, s->pending.argv, s->pending.envc, s->pending.envp,
            s->linux_mode ? s->pending.execfn : target->path) != 0) {
        problem(s, "exec_stack", "Cannot construct replacement initial stack.", errno); return -1;
    }
    /* Filters cannot be removed from a thread. At most EXEC_LIMIT additional
     * image filters are installed. The manager deadline spans the whole chain. Released data regions are never executable. */
    if ((s->linux_mode ? linux_filter(s) : filter(&s->image)) != 0) {
        problem(s, "exec_seccomp", "Cannot install replacement image filter.", errno); return -1;
    }
    /* CLOEXEC belongs to each guest descriptor. A saved/duplicated alias may
     * survive even when another alias closes; the broker only owns resources. */
    int committed = sucrune_fds_exec(&s->descriptors);
    if (committed < 0) {
        problem(s, "exec_descriptors", "Cannot commit executable descriptor state.", -committed); return -1;
    }
    s->current_program = target;
    if(s->inherited && s->inherited->scope.lease>=0) {
        sucrune_scope_name(target->path);
        const unsigned int sigs[]={SIGHUP,SIGINT,SIGTERM};
        for(size_t i=0;i<3;i++) sucrune_scope_disposition(sigs[i],s->signal_process.actions[sigs[i]].handler,current_signals(s)->mask);
    }
    s->exec_pending = 0;
    s->exec_count++;
    return 0;
}
static int prepare_child(void *opaque, struct sucrune_guest_thread *thread) {
    (void)thread; struct shell_state *s = opaque;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) != 0) return -errno;
    return linux_filter(s) == 0 ? 0 : -errno;
}
static void child_signal(void *opaque, struct sucrune_guest_thread *thread, int number, siginfo_t *info, void *context) {
    (void)opaque; (void)thread; handle_shell(number, info, context);
}
static int write_thread_tid(void *opaque, uintptr_t address, int32_t tid) {
    struct shell_state *s = opaque;
    (void)pthread_mutex_lock(&s->state_lock);
    int result = 0;
    if ((address & 3U) != 0U || !guest_memory(s, address, 4U, true)) result = -EFAULT;
    else atomic_store_explicit((_Atomic int32_t *)address, tid, memory_order_release);
    (void)pthread_mutex_unlock(&s->state_lock); return result;
}
static int clear_thread_tid(void *opaque, uintptr_t address) {
    struct shell_state *s = opaque;
    (void)pthread_mutex_lock(&s->state_lock);
    /* Linux silently ignores an inaccessible clear_child_tid during exit. */
    if ((address & 3U) == 0U && guest_memory(s, address, 4U, true)) {
        atomic_store_explicit((_Atomic int32_t *)address, 0, memory_order_release);
        (void)syscall(SYS_futex, (void *)address, FUTEX_WAKE, 1, NULL, NULL, 0);
    }
    (void)pthread_mutex_unlock(&s->state_lock); return 0;
}
static void *execute(void *argument) {
    struct shell_state *s = argument;
    if (guarded(ALT_SIZE, s->page, &s->alternate, &s->alternate_size, &s->alt_low, &s->alt_high) != 0) {
        problem(s, "signal_stack", "Cannot allocate signal stack.", errno); return NULL;
    }
    stack_t stack = { .ss_sp = (void *)s->alt_low, .ss_size = ALT_SIZE, .ss_flags = 0 };
    if (sigaltstack(&stack, NULL) != 0) { problem(s, "signal_stack", "Cannot activate signal stack.", errno); return NULL; }
    sigset_t mask; sigfillset(&mask); sigdelset(&mask, SIGSYS);
    sigdelset(&mask, SIGSEGV); sigdelset(&mask, SIGBUS); sigdelset(&mask, SIGILL);
    sigdelset(&mask, SIGFPE); sigdelset(&mask, SIGABRT);
    int error = pthread_sigmask(SIG_SETMASK, &mask, NULL);
    if (error != 0) { problem(s, "signal_mask", "Cannot unblock SIGSYS.", error); return NULL; }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) != 0) { problem(s, "no_new_privs", "Cannot enable no_new_privs.", errno); return NULL; }
    atomic_store_explicit(&active_shell, s, memory_order_release);
    s->gate.host = &s->host; s->gate.handler = handle_shell; s->gate.thread_id = syscall(SYS_gettid);
    if (s->linux_mode) sucrune_signals_init(&s->signal_process, &s->signal_thread, getpid(), s->gate.thread_id, getuid());
    if (s->inherited!=NULL) {
        uint64_t permitted=~((UINT64_C(1)<<(SIGKILL-1))|(UINT64_C(1)<<(SIGSTOP-1)));
        s->signal_thread.mask=s->inherited->signal_mask&permitted;
        for (unsigned int sig=1;sig<=64;sig++) if ((s->inherited->ignored_signals&permitted)&(UINT64_C(1)<<(sig-1U)))
            s->signal_process.actions[sig].handler=1U;
        if(s->inherited->scope.lease>=0) {
            const unsigned int sigs[]={SIGHUP,SIGINT,SIGTERM};
            for(size_t i=0;i<3;i++) sucrune_scope_disposition(sigs[i],s->signal_process.actions[sigs[i]].handler,s->signal_thread.mask);
        }
    }
    atomic_store_explicit(&sucrune_active_signal_gate, &s->gate, memory_order_release);
    if ((s->linux_mode ? linux_filter(s) : filter(&s->image)) != 0) { problem(s, "seccomp", "Cannot install guest filter.", errno); return NULL; }
    s->tls_restored = true;
    for (;;) {
        /* Each image gets an immutable owner-range snapshot. The fatal handler
         * may run on any thread, including one interrupted inside state_lock. */
        if (s->trace_faults && (unsigned int)s->exec_count <= EXEC_LIMIT) {
            static struct sucrune_fault_snapshot images[EXEC_LIMIT + 1U];
            struct sucrune_fault_snapshot *map = &images[(unsigned int)s->exec_count];
            *map = (struct sucrune_fault_snapshot){.ranges = {
                {(uintptr_t)s->image.base, s->image.size},
                {(uintptr_t)s->interpreter.base, s->interpreter.size},
                {s->fixed_space.base, s->fixed_space.size},
                {s->space.base, s->space.size}
            }};
            atomic_store_explicit(&sucrune_fault_map, map, memory_order_release);
        }
        (void)sucrune_guest_enter(s->linux_mode ? s->linux_entry : s->image.entry, s->stack_pointer, &s->host, s->linux_mode);
        uint64_t host_tls, host_x18;
        __asm__ volatile("mrs %0, tpidr_el0" : "=r"(host_tls));
        __asm__ volatile("mov %0, x18" : "=r"(host_x18));
        if (s->linux_mode) (void)pthread_mutex_lock(&s->state_lock);
        s->tls_restored = s->tls_restored && host_tls == s->host.tpidr_el0 && host_x18 == s->host.x18;
        s->returned = true;
        if (!s->tls_restored) {
            problem(s, "host_context", "Guest did not restore host context.", EFAULT);
            if (s->linux_mode) (void)pthread_mutex_unlock(&s->state_lock);
            break;
        }
        s->host_context_restores++;
        if (s->exec_pending != 0) {
            if (s->linux_mode) (void)pthread_mutex_unlock(&s->state_lock);
            if (replace_guest(s) != 0) break; continue;
        }
        if (s->error == 0) {
            if (s->exited == 1) problem(s, "complete", "The Linux guest exited.", 0);
            else problem(s, "guest_return", "Guest returned without Linux exit.", 0);
        }
        if (s->linux_mode) (void)pthread_mutex_unlock(&s->state_lock);
        break;
    }
    return NULL;
}

static int run_guest(int broker, const struct sucrune_program *program_spec, size_t argc, const char *const *argv,
        size_t envc, const char *const *envp, const char *cwd, int output, int error_output, char *report, size_t capacity, int input) {
    if (report == NULL || capacity == 0) { if (input >= 0) (void)close(input); return 1; }
    bool program = program_spec != NULL;
    struct shell_state s = { .broker = broker, .output = output, .error_output = error_output,
        .stage = "initializing", .message = "Guest did not complete.", .exit_code = -1, .program = program, .input = input,
        .linux_mode = program && program_spec->static_program == 2, .state_lock = PTHREAD_MUTEX_INITIALIZER };
    sucrune_guest_network_init(&s.network, broker);
    sucrune_pty_init(&s.ptys);
    s.inherited=s.linux_mode ? sucrune_linux_exec_state() : NULL;
    if (s.inherited!=NULL) {
        sucrune_fds_init_empty(&s.descriptors,release_descriptor,&s);
        s.linux_allow_rwx=s.inherited->linux_jit!=0U;
        s.build_profile=s.inherited->build_profile!=0U;
        s.exec_count=(sig_atomic_t)s.inherited->exec_depth;
    } else sucrune_fds_init(&s.descriptors, input, output, error_output, O_RDONLY, O_WRONLY, release_descriptor, &s);
    s.descriptors.descriptor_closed=record_descriptor_closed;
    s.may_have_record_locks=s.inherited!=NULL;
    struct sucrune_scope scope=s.inherited ? s.inherited->scope : (struct sucrune_scope){-1,-1};
    bool locked = false;
    if (s.linux_mode) {
        struct ucred peer;
        socklen_t peer_size = sizeof(peer);
        if (getsockopt(broker, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) != 0) {
            problem(&s, "broker_identity", "Cannot read project broker credentials.", errno);
            goto finish;
        }
        if (peer_size != sizeof(peer)) {
            problem(&s, "broker_identity", "Invalid project broker credentials.", EPROTO);
            goto finish;
        }
        s.owner = (struct sucrune_project_owner) {
            .broker_uid = peer.uid, .broker_gid = peer.gid, .guest_uid = geteuid(), .guest_gid = getegid()
        };
        int count = getgroups(0, NULL);
        if (count < 0) { problem(&s, "guest_identity", "Cannot query guest groups.", errno); goto finish; }
        if (count != 0) {
            s.supplementary_groups = calloc((size_t)count, sizeof(gid_t));
            if (s.supplementary_groups == NULL) { problem(&s, "guest_identity", "Cannot store guest groups.", ENOMEM); goto finish; }
            int actual = getgroups(count, s.supplementary_groups);
            if (actual < 0) { problem(&s, "guest_identity", "Cannot read guest groups.", errno); goto finish; }
            s.owner.groups = s.supplementary_groups;
            s.owner.group_count = (size_t)actual;
        }
        sucrune_fds_enable_linux(&s.descriptors);
        int aliases = sucrune_fds_enable_aliases(&s.descriptors, create_local_alias, close_local_alias, &s);
        if (aliases != 0) { problem(&s, "local_descriptors", "Cannot prepare stable guest descriptor aliases.", -aliases); goto finish; }
        if (s.inherited!=NULL) {
            int restored=sucrune_exec_restore_fds(s.inherited,&s.descriptors,&s.ptys,&s.network);
            if (restored!=0) {problem(&s,"exec_descriptors","Cannot restore inherited descriptions.",-restored);goto finish;}
            struct sucrune_request commit={.magic=SUCRUNE_BROKER_MAGIC,.operation=SUCRUNE_BROKER_EXEC_COMMIT};
            struct sucrune_response reply;
            int64_t committed=exchange(s.broker,&commit,&reply);
            if (committed!=0 || reply.size!=0U) {problem(&s,"exec_commit","Cannot commit close-on-exec.",committed<0 ? (int)-committed : EPROTO);goto finish;}
        }
    }
    if (argc == 0U || argc > (s.linux_mode ? SUCRUNE_GUEST_EXEC_ARGS : BUNDLED_EXEC_ARGS) ||
        envc > SUCRUNE_GUEST_EXEC_ENV || argv == NULL || (envc != 0U && envp == NULL) ||
        cwd == NULL || strlen(cwd) >= SUCRUNE_PATH_LIMIT || broker < 0 || output < 0 || error_output < 0) {
        problem(&s, "arguments", "Invalid guest execution arguments.", EINVAL); goto finish;
    }
    size_t string_bytes = 0;
    for (size_t i = 0; i < argc + envc; i++) {
        const char *value = i < argc ? argv[i] : envp[i - argc];
        if (value == NULL || strlen(value) > SCRIPT_LIMIT || string_bytes > SCRIPT_LIMIT + 64U - strlen(value)) {
            problem(&s, "arguments", "Guest arguments exceed their limit.", E2BIG); goto finish;
        }
        string_bytes += strlen(value) + 1U;
    }
    if (s.linux_mode && s.inherited==NULL) for (size_t i = 0; i < envc; i++) {
        if (!strcmp(envp[i],"SUCRUNE_PROCESS_SCOPE=project") && scope.bus<0) {
            scope.bus=sucrune_scope_start();
            if(scope.bus<0) {problem(&s,"project_scope","Cannot create project process scope.",-scope.bus);goto finish;}
        }
        if (strcmp(envp[i], "SUCRUNE_FD_PROFILE=build") == 0) s.build_profile = true;
        if (strcmp(envp[i], "SUCRUNE_TRACE_SYSCALLS=1") == 0) s.trace_syscalls = true;
        if (strcmp(envp[i], "SUCRUNE_TRACE_FAULTS=1") == 0 && sucrune_linux_is_runner()) s.trace_faults = true;
        const char *prefix = "SUCRUNE_MEMORY_POLICY=";
        if (strncmp(envp[i], prefix, strlen(prefix)) != 0) continue;
        const char *value = envp[i] + strlen(prefix);
        if (strcmp(value, "linux-jit") == 0) s.linux_allow_rwx = true;
        else if (strcmp(value, "wx") == 0) s.linux_allow_rwx = false;
        else { problem(&s, "arguments", "Unknown Linux memory policy.", EINVAL); goto finish; }
    }
    if (pthread_mutex_trylock(&shell_lock) != 0) { problem(&s, "busy", "Worker is already running.", EBUSY); goto finish; }
    locked = true;
    s.page = sysconf(_SC_PAGESIZE);
    s.current_program = program ? program_spec : sucrune_program_find_path("/bin/sucrune-sh");
    struct sucrune_request request = { .magic = SUCRUNE_BROKER_MAGIC, .operation = 49 };
    struct sucrune_response response;
    request.size = (uint32_t)(strlen(cwd) + 1U); memcpy(request.data, cwd, request.size);
    int64_t changed = s.inherited==NULL ? exchange(broker, &request, &response) : 0;
    if (changed < 0) { problem(&s, "cwd", "Cannot enter the project working directory.", (int)-changed); goto finish; }
    if (s.current_program == NULL || load_image(&s, s.current_program) != 0) goto finish;
    const char *execfn = s.current_program->path;
    if (s.linux_mode && (s.pending.scripts.count || (s.inherited != NULL && s.inherited->script))) {
        memcpy(s.pending.argv, argv, argc * sizeof(*argv));
        int error = script_arguments(&s, execfn, &argc, s.pending.argv, envc, envp);
        if (!error) error = executable_abspath(&s, s.pending.argv[0], s.replaced_path);
        if (error != 0) { problem(&s, "linux_script", "Cannot prepare script interpreter arguments.", error); goto finish; }
        s.replaced_program = *s.current_program;
        s.replaced_program.path = s.replaced_path;
        s.current_program = &s.replaced_program;
        argv = s.pending.argv;
    }
    if (program && !s.linux_mode && sucrune_memory_init(&s.memory, (size_t)s.page) != 0) { problem(&s, "memory", "Cannot reserve guest memory arena.", errno); goto finish; }
    if (prepare_stack(&s, argc, argv, envc, envp, execfn) != 0) { problem(&s, "stack", "Cannot construct guest initial stack.", errno); goto finish; }
    struct sigaction handler, previous;
    memset(&handler, 0, sizeof(handler));
    handler.sa_sigaction = sucrune_signal_entry; handler.sa_flags = SA_SIGINFO | SA_ONSTACK; sigfillset(&handler.sa_mask);
    if (sigaction(SIGSYS, &handler, &previous) != 0) { problem(&s, "signal", "Cannot install SIGSYS handler.", errno); goto finish; }
    const int fatal_signals[] = {SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT};
    struct sigaction fatal_previous[5], fatal_handler;
    memset(&fatal_handler, 0, sizeof(fatal_handler));
    fatal_handler.sa_handler = sucrune_guest_fatal_signal; fatal_handler.sa_flags = SA_ONSTACK;
    if (s.trace_faults) {
        atomic_store_explicit(&sucrune_fault_map, NULL, memory_order_release);
        fatal_handler.sa_sigaction = sucrune_guest_trace_fault;
        fatal_handler.sa_flags |= SA_SIGINFO;
    }
    sigfillset(&fatal_handler.sa_mask);
    size_t fatal_count = 0;
    for (; fatal_count < 5U; fatal_count++) {
        if (sigaction(fatal_signals[fatal_count], &fatal_handler, &fatal_previous[fatal_count]) != 0) {
            problem(&s, "fatal_signal", "Cannot install guest fault handler.", errno); break;
        }
    }
    pthread_t thread;
    if (fatal_count == 5U && s.linux_mode) {
        const struct sucrune_thread_callbacks callbacks = {.prepare = prepare_child, .signal = child_signal,
            .write_tid = write_thread_tid, .clear_tid = clear_thread_tid};
        int error = sucrune_linux_is_runner() ? sucrune_threads_create(&callbacks, &s, &s.threads) : -ENOTSUP;
        if (error != 0) problem(&s, "thread_supervisor", "Cannot start the Linux thread supervisor.", -error);
        else {
            if(scope.bus>=0 && argc && argv[0]) {
                const char *name=strrchr(argv[0],'/');
                (void)prctl(PR_SET_NAME,(unsigned long)(name?name+1:argv[0]),0UL,0UL,0UL);
            }
            error = sucrune_processes_create(&s.processes,scope);
            if (error != 0) problem(&s, "process_supervisor", "Cannot start the Linux process supervisor.", -error);
        }
    }
    if (fatal_count == 5U && s.error == 0) {
        int error = pthread_create(&thread, NULL, execute, &s);
        if (error != 0) problem(&s, "thread", "Cannot start guest thread.", error);
        else {
            if (pthread_join(thread, NULL) != 0) _exit(120); s.joined = true;
            if (s.linux_mode && s.main_clear_tid != 0U) (void)clear_thread_tid(&s, s.main_clear_tid);
        }
    }
    if (s.threads != NULL) {
        int error = sucrune_threads_join(s.threads);
        sucrune_threads_stats(s.threads, &s.thread_stats);
        int destroyed = sucrune_threads_destroy(s.threads); s.threads = NULL;
        if (error != 0 || destroyed != 0) problem(&s, "thread_cleanup", "Cannot finish guest thread cleanup.", error != 0 ? -error : -destroyed);
    }
    /* The Android wrapper adopts descendants and each has a project lease.
     * This is a dedicated ELF process; _exit disposes its observer threads.
     * Never destroy their mutexes or unmap the guest stack underneath them. */
    if(s.inherited && scope.bus>=0 && s.exited && s.error==0)
        sucrune_exec_child_exit(s.exit_code,s.termination_signal);
    if (s.processes != NULL) {
        int error = sucrune_processes_destroy(s.processes, &s.process_stats);
        s.processes = NULL;
        if (error != 0) problem(&s, "process_cleanup", "Cannot reap guest child processes.", -error);
    }
    atomic_store_explicit(&active_shell, NULL, memory_order_release);
    atomic_store_explicit(&sucrune_active_signal_gate, NULL, memory_order_release);
    for (size_t i = 0; i < fatal_count; i++) {
        if (sigaction(fatal_signals[i], &fatal_previous[i], NULL) != 0) problem(&s, "signal_restore", "Cannot restore fault handler.", errno);
    }
    if (sigaction(SIGSYS, &previous, NULL) != 0) problem(&s, "signal_restore", "Cannot restore SIGSYS handler.", errno);
    else s.restored = true;
finish:
    {
        int descriptor_cleanup = sucrune_fds_destroy(&s.descriptors);
        if (descriptor_cleanup < 0) problem(&s, "cleanup_descriptors", "Cannot finish guest descriptor cleanup.", -descriptor_cleanup);
    }
    (void)release_guest(&s);
    free(s.supplementary_groups);
    free(s.pending.images[0]);
    free(s.pending.images[1]);
    if (s.alternate != NULL && munmap(s.alternate, s.alternate_size) != 0) problem(&s, "cleanup", "Cannot release signal stack.", errno);
    bool success = s.exited == 1 && s.returned && s.joined && s.restored && s.tls_restored && s.error == 0 && strcmp(s.stage, "complete") == 0;
    int length = snprintf(report, capacity,
        "{\"schema_version\":1,\"kind\":\"%s\",\"status\":\"%s\",\"exit_code\":%d,\"stage\":\"%s\",\"message\":\"%s\","
        "\"error_number\":%d,\"syscalls\":%llu,\"pid\":%ld,\"uid\":%ld,\"page_size\":%ld,"
        "\"returned_to_host\":%s,\"thread_joined\":%s,\"handler_restored\":%s,\"on_alt_stack\":%s,"
        "\"guest_tls_seen\":%s,\"host_tls_restored\":%s,\"signal_gate_entries\":%llu,\"heap_peak_bytes\":%zu,"
        "\"unsupported_syscalls\":%llu,\"last_unsupported_syscall\":%d,\"program_parser_checks\":%d,\"image_collision_rejected\":%s,\"stdin_bytes_read\":%llu,"
        "\"direct_read_calls\":%llu,\"direct_read_bytes\":%llu,\"guest_direct_read_bytes\":%llu,"
        "\"exec_count\":%d,\"exec_limit\":%u,\"exec_failed_before_commit\":%d,\"last_program\":\"%s\",\"host_context_restores\":%u,"
        "\"fd_limit\":%u,\"fd_peak\":%u,\"fds_live\":%u,\"resources_live\":%u,"
        "\"network_resources_live\":%u,\"network_resources_peak\":%u,"
        "\"signal_deliveries\":%u,\"signal_returns\":%u,\"termination_signal\":%d,"
        "\"processes_created\":%u,\"processes_waited\":%u,\"processes_cleanup_reaped\":%u,\"processes_killed\":%u,\"processes_live\":%u,"
        "\"cleanup_mode\":\"joined\",\"memory_policy\":\"%s\",\"threads_created\":%u,\"threads_joined\":%u,\"threads_peak\":%u,\"threads_live\":%u}",
        s.linux_mode ? "linux" : (program ? "program" : "shell"), success ? "exited" : "failed", (int)s.exit_code, s.stage, s.message, s.error, (unsigned long long)s.syscalls,
        (long)getpid(), (long)getuid(), s.page, s.returned ? "true" : "false", s.joined ? "true" : "false",
        s.restored ? "true" : "false", s.alt_seen ? "true" : "false",
        s.tls_seen ? "true" : "false", s.tls_restored ? "true" : "false", (unsigned long long)s.gate.switches,
        s.heap_peak, (unsigned long long)s.unsupported, (int)s.last_unsupported, s.parser_checks, s.collision_rejected ? "true" : "false", (unsigned long long)s.input_read,
        (unsigned long long)s.direct_read_calls, (unsigned long long)s.direct_read_bytes, (unsigned long long)s.guest_direct_read_bytes,
        (int)s.exec_count, EXEC_LIMIT, (int)s.exec_failed_before_commit,
        s.current_program == NULL ? "" : s.current_program->id, s.host_context_restores,
        s.descriptors.limit, s.descriptors.peak, s.descriptors.count, s.descriptors.resource_count,
        s.network.count, s.network.peak,
        s.signal_deliveries, s.signal_returns, s.termination_signal,
        s.process_stats.created, s.process_stats.waited, s.process_stats.cleanup_reaped, s.process_stats.killed, s.process_stats.live,
        s.linux_allow_rwx ? "linux-jit" : "wx", s.thread_stats.created, s.thread_stats.joined, s.thread_stats.peak, s.thread_stats.live);
    if (length < 0 || (size_t)length >= capacity) (void)snprintf(report, capacity, "{\"status\":\"failed\",\"stage\":\"report_buffer\"}");
    if (locked) (void)pthread_mutex_unlock(&shell_lock);
    (void)pthread_mutex_destroy(&s.state_lock);
    if (s.inherited!=NULL) sucrune_exec_child_exit(success ? s.exit_code : 126,success ? s.termination_signal : 0);
    return success ? 0 : 1;
}
int sucrune_shell_run(int broker, const char *script, const char *cwd, int output, int error_output, char *report, size_t capacity) {
    const char *arguments[] = {"sucrune-sh", "-c", script};
    const char *environment[] = {"SUCRUNE=1"};
    return run_guest(broker, NULL, 3U, arguments, 1U, environment, cwd, output, error_output, report, capacity, -1);
}
int sucrune_program_run(int broker, const char *program, size_t argc, const char *const *argv,
        size_t envc, const char *const *envp, const char *cwd, int output, int error_output, char *report, size_t capacity, int input) {
    const struct sucrune_program *selected = sucrune_program_find(program);
    if (selected == NULL || argc > 64U || (argc != 0U && argv == NULL)) {
        if (input >= 0) (void)close(input);
        (void)snprintf(report, capacity, "{\"schema_version\":1,\"kind\":\"program\",\"status\":\"failed\",\"stage\":\"arguments\",\"message\":\"Unknown bundled program or invalid arguments.\"}"); return 1;
    }
    const char *arguments[65]; arguments[0] = selected->id;
    for (size_t i = 0; i < argc; i++) arguments[i + 1U] = argv[i];
    return run_guest(broker, selected, argc + 1U, arguments, envc, envp, cwd, output, error_output, report, capacity, input);
}
int sucrune_linux_run(int broker, const char *path, size_t argc, const char *const *argv,
        size_t envc, const char *const *envp, const char *cwd, int output, int error_output, char *report, size_t capacity, int input) {
    if (sucrune_linux_exec_state()!=NULL) {
        const struct sucrune_program child={.id="linux",.name="Project Linux executable",.version="",.path=path,.static_program=2};
        return run_guest(broker,&child,argc,argv,envc,envp,cwd,output,error_output,report,capacity,input);
    }
    if (path == NULL || path[0] != '/' || strlen(path) >= SUCRUNE_PATH_LIMIT || argc > 64U || (argc != 0U && argv == NULL)) {
        if (input >= 0) (void)close(input);
        (void)snprintf(report, capacity, "{\"schema_version\":1,\"kind\":\"linux\",\"status\":\"failed\",\"stage\":\"arguments\",\"message\":\"Invalid Linux path or arguments.\"}"); return 1;
    }
    const struct sucrune_program program = { .id = "linux", .name = "Project Linux executable", .version = "", .path = path, .static_program = 2 };
    const char *arguments[65]; arguments[0] = path;
    for (size_t i = 0; i < argc; i++) arguments[i + 1U] = argv[i];
    return run_guest(broker, &program, argc + 1U, arguments, envc, envp, cwd, output, error_output, report, capacity, input);
}
#else
int sucrune_shell_run(int broker, const char *script, const char *cwd, int output, int error_output, char *report, size_t capacity) {
    (void)broker; (void)script; (void)cwd; (void)output; (void)error_output;
    (void)snprintf(report, capacity, "{\"schema_version\":1,\"kind\":\"shell\",\"status\":\"unsupported\",\"exit_code\":-1,\"stage\":\"architecture\",\"message\":\"Native ARM64 is required.\"}");
    return 1;
}
int sucrune_program_run(int broker, const char *program, size_t argc, const char *const *argv,
        size_t envc, const char *const *envp, const char *cwd, int output, int error_output, char *report, size_t capacity, int input) {
    (void)broker; (void)program; (void)argc; (void)argv; (void)envc; (void)envp; (void)cwd; (void)output; (void)error_output;
    if (input >= 0) (void)close(input);
    (void)snprintf(report, capacity, "{\"schema_version\":1,\"kind\":\"program\",\"status\":\"unsupported\",\"exit_code\":-1,\"stage\":\"architecture\",\"message\":\"Native ARM64 is required.\"}"); return 1;
}
int sucrune_linux_run(int broker, const char *path, size_t argc, const char *const *argv,
        size_t envc, const char *const *envp, const char *cwd, int output, int error_output, char *report, size_t capacity, int input) {
    (void)broker; (void)path; (void)argc; (void)argv; (void)envc; (void)envp; (void)cwd; (void)output; (void)error_output;
    if (input >= 0) (void)close(input);
    (void)snprintf(report, capacity, "{\"schema_version\":1,\"kind\":\"linux\",\"status\":\"unsupported\",\"stage\":\"architecture\",\"message\":\"Native ARM64 is required.\"}"); return 1;
}
#endif
