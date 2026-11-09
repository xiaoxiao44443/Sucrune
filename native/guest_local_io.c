#include "guest_local_io.h"
#include "guest_fds.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

_Static_assert(sizeof(time_t) == 8U, "local I/O requires 64-bit time_t");
static int creators(const struct sucrune_local_io *io) {
    return io != NULL && io->ops.reserve != NULL && io->ops.commit != NULL && io->ops.cancel != NULL;
}
static int lookups(const struct sucrune_local_io *io) {
    return io != NULL && io->ops.acquire_many != NULL && io->ops.release_many != NULL;
}
static int mask_error(const uint64_t *mask, size_t size) {
    return mask == NULL ? 0 : (size != sizeof(*mask) ? -EINVAL : -ENOTSUP);
}
static int pin_error(const struct sucrune_local_pin *pin) {
    if (pin->error < 0) return pin->error;
    return pin->error != 0 || pin->host_fd < 0 ? -EIO : 0;
}
static int publish(struct sucrune_local_io *io, uintptr_t reservation, int *host,
                   size_t count, int flags, int32_t *guest) {
    struct sucrune_local_new_fd descriptors[2];
    int32_t result[2] = {-1, -1};
    int error = 0;
    for (size_t i = 0U; i < count; i++) {
        int status = fcntl(host[i], F_GETFL);
        if (status < 0) { error = -errno; break; }
        descriptors[i] = (struct sucrune_local_new_fd){host[i], status,
            (flags & O_CLOEXEC) != 0 ? SUCRUNE_LOCAL_CLOEXEC : 0U};
    }
    if (error == 0) error = io->ops.commit(io->context, reservation, count, descriptors, result);
    if (error == 0) {
        for (size_t i = 0U; i < count; i++) guest[i] = result[i];
        return 0;
    }
    for (size_t i = 0U; i < count; i++) (void)close(host[i]);
    io->ops.cancel(io->context, reservation);
    return error < 0 ? error : -EIO;
}
int sucrune_local_file_poll_fd(int open_flags) {
    int fd = open(SUCRUNE_FILE_POLL_PATH, O_RDONLY | O_CLOEXEC | (open_flags & O_PATH));
    return fd < 0 ? -errno : fd;
}
int sucrune_local_pipe2(struct sucrune_local_io *io, int flags, int32_t guest_fds[2]) {
    if (!creators(io) || guest_fds == NULL || (flags & ~(O_NONBLOCK | O_CLOEXEC)) != 0) return -EINVAL;
    uintptr_t reservation = 0U;
    int error = io->ops.reserve(io->context, 2U, &reservation);
    if (error != 0) return error < 0 ? error : -EIO;
    int host[2];
    if (pipe2(host, flags | O_CLOEXEC) != 0) {
        error = -errno; io->ops.cancel(io->context, reservation); return error;
    }
    return publish(io, reservation, host, 2U, flags, guest_fds);
}
int sucrune_local_eventfd2(struct sucrune_local_io *io, uint32_t initial, int flags) {
    if (!creators(io) || (flags & ~(EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC)) != 0) return -EINVAL;
    uintptr_t reservation = 0U;
    int error = io->ops.reserve(io->context, 1U, &reservation);
    if (error != 0) return error < 0 ? error : -EIO;
    int host = eventfd(initial, flags | EFD_CLOEXEC);
    if (host < 0) { error = -errno; io->ops.cancel(io->context, reservation); return error; }
    int32_t guest;
    error = publish(io, reservation, &host, 1U, flags, &guest);
    return error == 0 ? guest : error;
}
int sucrune_local_epoll_create1(struct sucrune_local_io *io, int flags) {
    if (!creators(io) || (flags & ~EPOLL_CLOEXEC) != 0) return -EINVAL;
    uintptr_t reservation = 0U;
    int error = io->ops.reserve(io->context, 1U, &reservation);
    if (error != 0) return error < 0 ? error : -EIO;
    int host = epoll_create1(flags | EPOLL_CLOEXEC);
    if (host < 0) { error = -errno; io->ops.cancel(io->context, reservation); return error; }
    int32_t guest;
    error = publish(io, reservation, &host, 1U, flags, &guest);
    return error == 0 ? guest : error;
}
int sucrune_local_epoll_ctl(struct sucrune_local_io *io, int32_t epfd, int operation,
                            int32_t fd, const struct sucrune_local_event *event) {
    if (!lookups(io) || (operation != EPOLL_CTL_ADD && operation != EPOLL_CTL_MOD && operation != EPOLL_CTL_DEL)) return -EINVAL;
    if (operation != EPOLL_CTL_DEL && event == NULL) return -EFAULT;
    int32_t requested[2] = {epfd, fd};
    struct sucrune_local_pin pins[2];
    memset(pins, 0, sizeof(pins));
    int error = io->ops.acquire_many(io->context, requested, 2U, SUCRUNE_LOCAL_STABLE_CTL, pins);
    if (error != 0) return error < 0 ? error : -EIO;
    error = pin_error(&pins[0]);
    if (error == 0) error = pin_error(&pins[1]);
    if (error == 0) {
        struct epoll_event native = {0};
        if (event != NULL && operation != EPOLL_CTL_DEL) { native.events = event->events; native.data.u64 = event->data; }
        if (epoll_ctl(pins[0].host_fd, operation, pins[1].host_fd,
                      operation == EPOLL_CTL_DEL ? NULL : &native) != 0) error = -errno;
    }
    io->ops.release_many(io->context, SUCRUNE_LOCAL_STABLE_CTL, pins, 2U);
    return error;
}
static int64_t mono_ms(void) {
    struct timespec now;
    if(clock_gettime(CLOCK_MONOTONIC,&now)!=0) return -1;
    return (int64_t)now.tv_sec*1000+now.tv_nsec/1000000;
}
static int wait_with_notice(int epfd,struct epoll_event *events,int limit,int timeout,int wake_fd) {
    if(wake_fd<0 || timeout==0) return epoll_pwait(epfd,events,limit,timeout,NULL);
    int64_t end=0;
    if(timeout>0) {end=mono_ms();if(end<0) return -1;end+=timeout;}
    struct pollfd both[2]={{.fd=epfd,.events=POLLIN},{.fd=wake_fd,.events=POLLIN}};
    for(;;) {
        int ready=epoll_pwait(epfd,events,limit,0,NULL);
        if(ready!=0) return ready;
        int remaining=-1;
        if(timeout>0) {
            int64_t now=mono_ms();if(now<0) return -1;
            if(now>=end) return 0;
            remaining=(int)(end-now);
        }
        ready=poll(both,2,remaining);
        if(ready<=0) return ready;
        if(both[1].revents!=0) {errno=EINTR;return -1;}
        /* Another thread can drain an epoll item after poll reports it. */
    }
}
int sucrune_local_epoll_interruptible(struct sucrune_local_io *io, int32_t epfd,
    struct sucrune_local_event *events, int max_events, int timeout_ms,
    const uint64_t *signal_mask, size_t sigset_size,int wake_fd) {
    if (!lookups(io) || max_events <= 0 || max_events > INT_MAX / (int)sizeof(struct sucrune_local_event)) return -EINVAL;
    if (events == NULL) return -EFAULT;
    int error = mask_error(signal_mask, sigset_size);
    if (error != 0) return error;
    struct sucrune_local_pin pin = {0};
    error = io->ops.acquire_many(io->context, &epfd, 1U, SUCRUNE_LOCAL_RETAINED_WAIT, &pin);
    if (error != 0) return error < 0 ? error : -EIO;
    error = pin_error(&pin);
    if (error == 0) {
        struct epoll_event native[SUCRUNE_LOCAL_IO_LIMIT];
        int limit = max_events > (int)SUCRUNE_LOCAL_IO_LIMIT ? (int)SUCRUNE_LOCAL_IO_LIMIT : max_events;
        int ready = wait_with_notice(pin.host_fd, native, limit, timeout_ms,wake_fd);
        if (ready < 0) error = -errno;
        else {
            for (int i = 0; i < ready; i++) events[i] = (struct sucrune_local_event){native[i].events, 0U, native[i].data.u64};
            error = ready;
        }
    }
    io->ops.release_many(io->context, SUCRUNE_LOCAL_RETAINED_WAIT, &pin, 1U);
    return error;
}
int sucrune_local_epoll_pwait(struct sucrune_local_io *io, int32_t epfd,
    struct sucrune_local_event *events, int max_events, int timeout_ms,
    const uint64_t *signal_mask, size_t sigset_size) {
    return sucrune_local_epoll_interruptible(io,epfd,events,max_events,timeout_ms,signal_mask,sigset_size,-1);
}
static void subtract_elapsed(struct timespec *remaining, const struct timespec *start, const struct timespec *finish) {
    time_t seconds = finish->tv_sec - start->tv_sec;
    long nanoseconds = finish->tv_nsec - start->tv_nsec;
    if (nanoseconds < 0) { seconds--; nanoseconds += 1000000000L; }
    if (seconds < 0) return;
    if (seconds > remaining->tv_sec || (seconds == remaining->tv_sec && nanoseconds >= remaining->tv_nsec)) {
        remaining->tv_sec = 0; remaining->tv_nsec = 0; return;
    }
    remaining->tv_sec -= seconds;
    remaining->tv_nsec -= nanoseconds;
    if (remaining->tv_nsec < 0) { remaining->tv_sec--; remaining->tv_nsec += 1000000000L; }
}
/* A wait drops the state lock. Its pins, IDs and kernel poll array must remain
 * private until it returns. Use a small signal-stack frame for typical waits;
 * mmap larger batches without entering the host heap allocator. */
struct wait_batch {
    struct sucrune_local_pin small_pins[16], *pins;
    struct pollfd small_fds[16], *fds;
    int32_t small_ids[16], *ids;
    size_t mapping_size;
};
static int prepare_batch(struct wait_batch *batch, size_t count) {
    batch->mapping_size = 0U;
    if (count <= sizeof(batch->small_ids) / sizeof(batch->small_ids[0])) {
        batch->pins = batch->small_pins;
        batch->fds = batch->small_fds;
        batch->ids = batch->small_ids;
        return 0;
    }
    size_t bytes = count * (sizeof(*batch->pins) + sizeof(*batch->fds) + sizeof(*batch->ids));
    void *map = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED) return -errno;
    batch->mapping_size = bytes;
    batch->pins = map;
    batch->fds = (struct pollfd *)(batch->pins + count);
    batch->ids = (int32_t *)(batch->fds + count);
    return 0;
}
static void release_batch(const struct wait_batch *batch) {
    if (batch->mapping_size != 0U) (void)munmap(batch->pins, batch->mapping_size);
}
static size_t descriptor_limit(const struct sucrune_local_io *io) {
    return io->descriptor_limit ? io->descriptor_limit : SUCRUNE_FD_LIMIT;
}
int sucrune_local_ppoll(struct sucrune_local_io *io, struct sucrune_local_pollfd *fds,
    size_t count, const struct sucrune_local_timespec *timeout,
    struct sucrune_local_timespec *remaining, const uint64_t *signal_mask, size_t sigset_size) {
    if (!lookups(io) || count > descriptor_limit(io) || count > SUCRUNE_LINUX_FD_LIMIT) return -EINVAL;
    if (count != 0U && fds == NULL) return -EFAULT;
    int error = mask_error(signal_mask, sigset_size);
    if (error != 0) return error;
    struct timespec native_timeout = {0}, zero = {0};
    if (timeout != NULL) {
        if (timeout->seconds < 0 || timeout->nanoseconds < 0 || timeout->nanoseconds >= INT64_C(1000000000)) return -EINVAL;
        native_timeout.tv_sec = (time_t)timeout->seconds; native_timeout.tv_nsec = (long)timeout->nanoseconds;
        /* A callback may fail with EINTR before reaching ppoll. Its caller
         * still performs the raw syscall's timeout copyback on EINTR. */
        if (remaining != NULL) *remaining = *timeout;
    }
    struct wait_batch batch;
    error = prepare_batch(&batch, count);
    if (error) return error;
    size_t requested_count = 0U;
    for (size_t i = 0U; i < count; i++) {
        batch.fds[i] = (struct pollfd){.fd=-1,.events=fds[i].events,.revents=0};
        if (fds[i].fd >= 0) batch.ids[requested_count++] = fds[i].fd;
    }
    if (requested_count != 0U) {
        error = io->ops.acquire_many(io->context, batch.ids, requested_count, SUCRUNE_LOCAL_RETAINED_WAIT, batch.pins);
        if (error != 0) { release_batch(&batch); return error < 0 ? error : -EIO; }
    }
    int invalid_count = 0;
    for (size_t i = 0U, pin = 0U; i < count; i++) {
        if (fds[i].fd < 0) continue;
        error = pin_error(&batch.pins[pin]);
        if (error == -EBADF) invalid_count++;
        else if (error != 0) goto release;
        else batch.fds[i].fd = batch.pins[pin].host_fd;
        pin++;
    }
    {
        struct timespec started = {0}, finished = {0};
        if (invalid_count != 0 && timeout != NULL && clock_gettime(CLOCK_MONOTONIC, &started) != 0) { error = -errno; goto release; }
        struct timespec *wait_timeout = invalid_count != 0 ? &zero : (timeout != NULL ? &native_timeout : NULL);
        long ready = syscall(SYS_ppoll, batch.fds, count, wait_timeout, NULL, sizeof(uint64_t));
        int poll_error = ready < 0 ? errno : 0;
        if (invalid_count != 0 && timeout != NULL) {
            if (clock_gettime(CLOCK_MONOTONIC, &finished) != 0) { error = -errno; goto release; }
            subtract_elapsed(&native_timeout, &started, &finished);
        }
        if (timeout != NULL && remaining != NULL && (ready >= 0 || poll_error == EINTR))
            *remaining = (struct sucrune_local_timespec){(int64_t)native_timeout.tv_sec, (int64_t)native_timeout.tv_nsec};
        if (ready < 0) error = -poll_error;
        else {
            for (size_t i = 0U; i < count; i++)
                fds[i].revents = fds[i].fd >= 0 && batch.fds[i].fd < 0 ? POLLNVAL : batch.fds[i].revents;
            error = (int)ready + invalid_count;
        }
    }
release:
    if (requested_count != 0U) io->ops.release_many(io->context, SUCRUNE_LOCAL_RETAINED_WAIT, batch.pins, requested_count);
    release_batch(&batch);
    return error;
}
int sucrune_local_pselect(struct sucrune_local_io *io, const struct sucrune_local_fdset input[3],
        struct sucrune_local_fdset output[3], const struct sucrune_local_timespec *timeout,
        struct sucrune_local_timespec *remaining, int wake_fd) {
    if (!lookups(io) || input == NULL || output == NULL) return -EINVAL;
    struct sucrune_local_timespec left = {0, 0};
    if (timeout != NULL) {
        if (timeout->seconds < 0 || timeout->nanoseconds < 0 || timeout->nanoseconds >= 1000000000) return -EINVAL;
        left = *timeout;
        if (remaining != NULL) *remaining = left;
    }
    const size_t limit = descriptor_limit(io);
    if (limit > SUCRUNE_LINUX_FD_LIMIT) return -EINVAL;
    size_t count = 0U;
    uint64_t requested[sizeof(input[0].words) / sizeof(uint64_t)];
    for (size_t word = 0; word < sizeof(requested) / sizeof(requested[0]); word++) {
        requested[word] = input[0].words[word] | input[1].words[word] | input[2].words[word];
        if (!requested[word]) continue;
        if (64U * word >= limit || (limit - 64U * word < 64U && requested[word] >> (limit - 64U * word)))
            return -EBADF;
        count += (unsigned int)__builtin_popcountll(requested[word]);
    }
    struct wait_batch batch;
    int error = prepare_batch(&batch, count);
    if (error) return error;
    size_t next = 0U;
    for (size_t word = 0; word < sizeof(requested) / sizeof(requested[0]); word++) {
        for (uint64_t bits = requested[word]; bits; bits &= bits - 1U)
            batch.ids[next++] = (int32_t)(64U * word + (unsigned int)__builtin_ctzll(bits));
    }
    if (count) {
        error = io->ops.acquire_many(io->context, batch.ids, count, SUCRUNE_LOCAL_RETAINED_WAIT, batch.pins);
        if (error) { release_batch(&batch); return error < 0 ? error : -EIO; }
    }
    int high = wake_fd;
    uint64_t small_sets[3U * 16U] = {0}, *sets = small_sets;
    size_t set_bytes = 0U;
    for (size_t i = 0; i < count; i++) {
        error = pin_error(&batch.pins[i]);
        if (error) goto release;
        if (batch.pins[i].host_fd > high) high = batch.pins[i].host_fd;
    }
    /* Linux nr_open defaults to 1M FDs. Cap host alias bitmap allocation. */
    if (high >= 1048576) { error = -EOVERFLOW; goto release; }
    size_t words = high < 0 ? 1U : (size_t)high / 64U + 1U;
    if (words > 16U) {
        set_bytes = 3U * words * sizeof(*sets);
        sets = mmap(NULL, set_bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (sets == MAP_FAILED) { error = -errno; goto release; }
    }
    for (size_t i = 0; i < count; i++) {
        unsigned int guest = (unsigned int)batch.ids[i], host = (unsigned int)batch.pins[i].host_fd;
        uint64_t guest_bit = UINT64_C(1) << (guest % 64U), host_bit = UINT64_C(1) << (host % 64U);
        for (size_t set = 0; set < 3U; set++)
            if (input[set].words[guest / 64U] & guest_bit) sets[set * words + host / 64U] |= host_bit;
    }
    if (wake_fd >= 0) sets[(unsigned int)wake_fd / 64U] |= UINT64_C(1) << ((unsigned int)wake_fd % 64U);
    long ready = syscall(SYS_pselect6, high + 1, sets, sets + words, sets + 2U * words, timeout ? &left : NULL, NULL);
    error = ready < 0 ? -errno : 0;
    if (timeout && remaining && (error == 0 || error == -EINTR)) *remaining = left;
    if (!error) {
        struct sucrune_local_fdset result[3] = {0};
        for (size_t i = 0; i < count; i++) {
            unsigned int guest = (unsigned int)batch.ids[i], host = (unsigned int)batch.pins[i].host_fd;
            uint64_t guest_bit = UINT64_C(1) << (guest % 64U), host_bit = UINT64_C(1) << (host % 64U);
            for (size_t set = 0; set < 3U; set++) if (sets[set * words + host / 64U] & host_bit) {
                result[set].words[guest / 64U] |= guest_bit;
                error++;
            }
        }
        if (error == 0 && wake_fd >= 0 && (sets[(unsigned int)wake_fd / 64U] & (UINT64_C(1) << ((unsigned int)wake_fd % 64U))))
            error = -EINTR;
        if (error >= 0) memcpy(output, result, sizeof(result));
    }
release:
    if (sets != small_sets && sets != MAP_FAILED) (void)munmap(sets, set_bytes);
    if (count) io->ops.release_many(io->context, SUCRUNE_LOCAL_RETAINED_WAIT, batch.pins, count);
    release_batch(&batch);
    return error;
}
