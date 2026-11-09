/* Real Linux/Bionic pipe/eventfd/epoll/ppoll tests. Cross-compilation alone is
 * not execution evidence. No guest ELF, Android app or broker is involved. */
#include "guest_local_io.h"
#include "guest_fds.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>

#define CHECK(test) do { if (!(test)) { fprintf(stderr,"%s:%d: %s (errno=%d)\n",__FILE__,__LINE__,#test,errno); abort(); } } while (0)
struct fixture {
    struct sucrune_fd_table table;
    struct sucrune_local_io io;
    pthread_mutex_t mutex;
    size_t claimed;
    unsigned int cancellations, alias_calls, fail_alias_call;
    int force_commit_error, force_acquire_error, last_created[2];
    atomic_int wait_acquired;
};
static unsigned int cases;
static int release_resource(void *context, enum sucrune_fd_kind kind, int fd) {
    (void)context;
    return kind == SUCRUNE_FD_LOCAL && fd >= 0 && close(fd) != 0 ? -errno : 0;
}
static int create_alias(void *context, enum sucrune_fd_kind kind, int canonical, int *alias) {
    struct fixture *f = context;
    f->alias_calls++;
    if (f->alias_calls == f->fail_alias_call) return -EMFILE;
    if (kind != SUCRUNE_FD_LOCAL || canonical < 0) { *alias = -1; return 0; }
    *alias = fcntl(canonical, F_DUPFD_CLOEXEC, 0);
    return *alias >= 0 ? 0 : -errno;
}
static int close_alias(void *context, enum sucrune_fd_kind kind, int alias) {
    (void)context; (void)kind;
    return close(alias) == 0 ? 0 : -errno;
}
static int reserve(void *context, size_t count, uintptr_t *ticket) {
    struct fixture *f = context;
    CHECK(pthread_mutex_lock(&f->mutex) == 0 && f->claimed == 0U);
    if (count > f->table.limit - f->table.count || count > f->table.limit - f->table.resource_count) {
        CHECK(pthread_mutex_unlock(&f->mutex) == 0); return -EMFILE;
    }
    f->claimed = count; *ticket = (uintptr_t)f; return 0;
}
static int commit(void *context, uintptr_t ticket, size_t count,
                  const struct sucrune_local_new_fd *descriptors, int32_t *guest) {
    struct fixture *f = context;
    CHECK(ticket == (uintptr_t)f && f->claimed == count && count <= 2U);
    int handles[2], statuses[2]; unsigned int flags[2];
    for (size_t i = 0U; i < count; i++) {
        handles[i] = descriptors[i].host_fd; statuses[i] = descriptors[i].status_flags;
        flags[i] = descriptors[i].descriptor_flags; f->last_created[i] = handles[i];
    }
    if (f->force_commit_error != 0) return f->force_commit_error;
    int error = sucrune_fds_add_batch(&f->table, SUCRUNE_FD_LOCAL, handles, statuses, flags, count, guest);
    if (error == 0) { f->claimed = 0U; CHECK(pthread_mutex_unlock(&f->mutex) == 0); }
    return error;
}
static void cancel(void *context, uintptr_t ticket) {
    struct fixture *f = context;
    CHECK(ticket == (uintptr_t)f && f->claimed != 0U);
    f->claimed = 0U; f->cancellations++; CHECK(pthread_mutex_unlock(&f->mutex) == 0);
}
static int acquire(void *context, const int32_t *guest, size_t count,
                   enum sucrune_local_pin_mode mode, struct sucrune_local_pin *pins) {
    struct fixture *f = context;
    if (f->force_acquire_error != 0) return f->force_acquire_error;
    CHECK(pthread_mutex_lock(&f->mutex) == 0);
    for (size_t i = 0U; i < count; i++) {
        pins[i] = (struct sucrune_local_pin){.host_fd=-1,.error=0,.token=0};
        int alias = guest[i] < 0 ? -EBADF : sucrune_fds_alias(&f->table, (uint64_t)guest[i]);
        if (alias < 0) pins[i].error = alias;
        else if (mode == SUCRUNE_LOCAL_STABLE_CTL) pins[i].host_fd = alias;
        else {
            pins[i].host_fd = fcntl(alias, F_DUPFD_CLOEXEC, 0);
            if (pins[i].host_fd < 0) pins[i].error = -errno;
        }
    }
    if (mode == SUCRUNE_LOCAL_RETAINED_WAIT) {
        CHECK(pthread_mutex_unlock(&f->mutex) == 0);
        atomic_store_explicit(&f->wait_acquired, 1, memory_order_release);
    }
    return 0;
}
static void unpin(void *context, enum sucrune_local_pin_mode mode,
                  struct sucrune_local_pin *pins, size_t count) {
    struct fixture *f = context;
    if (mode == SUCRUNE_LOCAL_STABLE_CTL) CHECK(pthread_mutex_unlock(&f->mutex) == 0);
    else for (size_t i = 0U; i < count; i++) if (pins[i].host_fd >= 0) CHECK(close(pins[i].host_fd) == 0);
}
static void setup(struct fixture *f) {
    memset(f, 0, sizeof(*f)); atomic_init(&f->wait_acquired, 0);
    CHECK(pthread_mutex_init(&f->mutex, NULL) == 0);
    sucrune_fds_init(&f->table, -1, -1, -1, O_RDONLY, O_WRONLY, release_resource, f);
    CHECK(sucrune_fds_destroy(&f->table) == 0);
    CHECK(sucrune_fds_enable_aliases(&f->table, create_alias, close_alias, f) == 0);
    f->io = (struct sucrune_local_io){.context=f,.ops={reserve,commit,cancel,acquire,unpin}};
}
static void finish(struct fixture *f) {
    CHECK(f->claimed == 0U && sucrune_fds_destroy(&f->table) == 0);
    CHECK(f->table.count == 0U && f->table.resource_count == 0U);
    CHECK(pthread_mutex_destroy(&f->mutex) == 0); cases++;
}
static int host(struct fixture *f, int guest) { return sucrune_fds_alias(&f->table, (uint64_t)guest); }
static void closed(int fd) { errno = 0; CHECK(fcntl(fd, F_GETFD) == -1 && errno == EBADF); }
static void creation_and_flags(void) {
    struct fixture f; setup(&f); int32_t pair[2] = {-1,-1};
    CHECK(sucrune_local_pipe2(&f.io, O_NONBLOCK | O_CLOEXEC, pair) == 0 && pair[0] == 0 && pair[1] == 1);
    CHECK((fcntl(host(&f,pair[0]),F_GETFL) & (O_ACCMODE|O_NONBLOCK)) == (O_RDONLY|O_NONBLOCK));
    CHECK((fcntl(host(&f,pair[1]),F_GETFL) & (O_ACCMODE|O_NONBLOCK)) == (O_WRONLY|O_NONBLOCK));
    CHECK(sucrune_fds_get_flags(&f.table,(uint64_t)pair[0]) == SUCRUNE_FD_CLOEXEC);
    char byte;
    CHECK(read(host(&f,pair[0]),&byte,1U) == -1 && errno == EAGAIN);
    CHECK(write(host(&f,pair[1]),"p",1U) == 1 && read(host(&f,pair[0]),&byte,1U) == 1 && byte == 'p');
    int event = sucrune_local_eventfd2(&f.io,0U,0);
    CHECK(event == 2 && sucrune_fds_get_flags(&f.table,(uint64_t)event) == 0);
    CHECK((fcntl(host(&f,event),F_GETFD) & FD_CLOEXEC) != 0);
    finish(&f);
}
static void creation_rollback(void) {
    struct fixture f; setup(&f); int32_t pair[2] = {-71,-72};
    f.force_commit_error = -ENOMEM;
    CHECK(sucrune_local_pipe2(&f.io,0,pair) == -ENOMEM && pair[0] == -71 && pair[1] == -72);
    closed(f.last_created[0]); closed(f.last_created[1]);
    CHECK(f.cancellations == 1U && f.table.count == 0U);
    f.force_commit_error = 0; f.fail_alias_call = f.alias_calls + 2U;
    CHECK(sucrune_local_pipe2(&f.io,0,pair) == -EMFILE && pair[0] == -71 && pair[1] == -72);
    closed(f.last_created[0]); closed(f.last_created[1]);
    CHECK(f.cancellations == 2U && f.table.count == 0U && f.table.resource_count == 0U);
    finish(&f);
}
static void pipe_capacity(void) {
    struct fixture f; setup(&f);
    for (unsigned int i = 0U; i < 63U; i++) CHECK(sucrune_local_eventfd2(&f.io,0U,EFD_NONBLOCK) == (int)i);
    unsigned int calls = f.alias_calls; int32_t pair[2] = {-71,-72};
    CHECK(sucrune_local_pipe2(&f.io,0,pair) == -EMFILE && pair[0] == -71 && pair[1] == -72);
    CHECK(f.table.count == 63U && f.alias_calls == calls && f.cancellations == 0U);
    finish(&f);
}
static void eventfd_counter_and_dup(void) {
    struct fixture f; setup(&f);
    int event = sucrune_local_eventfd2(&f.io,2U,EFD_NONBLOCK|EFD_SEMAPHORE);
    CHECK(event >= 0); uint64_t value = 0U;
    CHECK(read(host(&f,event),&value,sizeof(value)) == 8 && value == 1U);
    CHECK(read(host(&f,event),&value,sizeof(value)) == 8 && value == 1U);
    CHECK(read(host(&f,event),&value,sizeof(value)) == -1 && errno == EAGAIN);
    int alias = sucrune_fds_duplicate(&f.table,(uint64_t)event,0U,1U);
    CHECK(alias >= 0 && host(&f,event) != host(&f,alias));
    int flags = fcntl(host(&f,alias),F_GETFL);
    CHECK(fcntl(host(&f,alias),F_SETFL,flags & ~O_NONBLOCK) == 0);
    CHECK((fcntl(host(&f,event),F_GETFL) & O_NONBLOCK) == 0);
    CHECK(fcntl(host(&f,event),F_SETFL,flags) == 0);
    CHECK(sucrune_fds_get_flags(&f.table,(uint64_t)event) == 0 && sucrune_fds_get_flags(&f.table,(uint64_t)alias) == 1);
    finish(&f);
}
static void epoll_data_and_alias_lifetime(void) {
    struct fixture f; setup(&f); int32_t pair[2];
    CHECK(sucrune_local_pipe2(&f.io,O_NONBLOCK,pair) == 0);
    int epfd = sucrune_local_epoll_create1(&f.io,EPOLL_CLOEXEC);
    CHECK(epfd >= 0);
    struct sucrune_local_event event = {EPOLLIN,99U,UINT64_C(0xfedcba9876543210)}, events[64];
    CHECK(sucrune_local_epoll_ctl(&f.io,epfd,EPOLL_CTL_ADD,pair[0],&event) == 0);
    CHECK(write(host(&f,pair[1]),"x",1U) == 1);
    CHECK(sucrune_local_epoll_pwait(&f.io,epfd,events,1024,0,NULL,0U) == 1);
    CHECK(events[0].data == event.data && events[0].padding == 0U && (events[0].events & EPOLLIN) != 0U);
    event.data = UINT64_C(0x8000000000000001);
    CHECK(sucrune_local_epoll_ctl(&f.io,epfd,EPOLL_CTL_MOD,pair[0],&event) == 0);
    CHECK(sucrune_local_epoll_pwait(&f.io,epfd,events,64,0,NULL,8U) == 1 && events[0].data == event.data);
    int alias = sucrune_fds_duplicate(&f.table,(uint64_t)pair[0],0U,0U);
    event.data = UINT64_C(0xffffffffffffffff);
    CHECK(sucrune_local_epoll_ctl(&f.io,epfd,EPOLL_CTL_ADD,alias,&event) == 0);
    CHECK(sucrune_local_epoll_pwait(&f.io,epfd,events,64,0,NULL,8U) == 2);
    CHECK(sucrune_local_epoll_ctl(&f.io,epfd,EPOLL_CTL_DEL,alias,NULL) == 0);
    CHECK(sucrune_local_epoll_ctl(&f.io,epfd,EPOLL_CTL_ADD,alias,&event) == 0);
    CHECK(sucrune_fds_close(&f.table,(uint64_t)pair[0]) == 0);
    CHECK(sucrune_local_epoll_pwait(&f.io,epfd,events,64,0,NULL,8U) == 2);
    CHECK(sucrune_fds_close(&f.table,(uint64_t)alias) == 0);
    CHECK(sucrune_local_epoll_pwait(&f.io,epfd,events,64,0,NULL,8U) == 0);
    finish(&f);
}
static void ppoll_errors_and_timeout(void) {
    struct fixture f; setup(&f); int32_t pair[2];
    CHECK(sucrune_local_pipe2(&f.io,O_NONBLOCK,pair) == 0);
    struct sucrune_local_pollfd descriptors[3] = {{-1,POLLIN,77},{63,POLLIN,77},{pair[1],POLLOUT,77}};
    struct sucrune_local_timespec timeout = {5,0}, remaining = {-1,-1};
    CHECK(sucrune_local_ppoll(&f.io,descriptors,3U,&timeout,&remaining,NULL,8U) == 2);
    CHECK(descriptors[0].revents == 0 && descriptors[1].revents == POLLNVAL && (descriptors[2].revents & POLLOUT) != 0);
    CHECK(timeout.seconds == 5 && remaining.seconds >= 4 && remaining.seconds <= 5);
    timeout = (struct sucrune_local_timespec){0,0}; descriptors[0] = (struct sucrune_local_pollfd){pair[0],POLLIN,77};
    CHECK(sucrune_local_ppoll(&f.io,descriptors,1U,&timeout,&remaining,NULL,8U) == 0 && descriptors[0].revents == 0);
    CHECK(sucrune_local_ppoll(&f.io,NULL,0U,&timeout,&remaining,NULL,8U) == 0);
    finish(&f);
}
static void compare_file_readiness(const char *path, int flags) {
    struct fixture f; setup(&f);
    int real = open(path, flags | O_CLOEXEC);
    CHECK(real >= 0 && real < FD_SETSIZE);
    int local = sucrune_local_file_poll_fd(flags);
    CHECK(local >= 0 && (fcntl(local, F_GETFD) & FD_CLOEXEC));
    int fd = sucrune_fds_add(&f.table, SUCRUNE_FD_LOCAL, local, flags, 0U);
    int32_t pipe[2];
    CHECK(fd >= 0 && sucrune_local_pipe2(&f.io, O_NONBLOCK, pipe) == 0);
    const short events = POLLIN | POLLOUT | POLLPRI | POLLRDNORM | POLLWRNORM;
    struct pollfd expected = {.fd=real, .events=events};
    CHECK(poll(&expected, 1U, 0) == 1);
    struct sucrune_local_pollfd mixed[3] = {{pipe[0], POLLIN, 77}, {fd, events, 77}, {pipe[1], POLLOUT, 77}};
    struct sucrune_local_timespec zero = {0,0};
    CHECK(sucrune_local_ppoll(&f.io, mixed, 3U, &zero, NULL, NULL, 8U) == 2);
    CHECK(mixed[0].revents == 0 && mixed[1].revents == expected.revents && mixed[2].revents == POLLOUT);

    fd_set sets[3];
    for (size_t i = 0U; i < 3U; i++) { FD_ZERO(&sets[i]); FD_SET(real, &sets[i]); }
    struct timespec native_zero = {0};
    int select_result = pselect(real + 1, &sets[0], &sets[1], &sets[2], &native_zero, NULL);
    if (select_result < 0) select_result = -errno;
    uint64_t bit = UINT64_C(1) << (unsigned int)fd;
    struct sucrune_local_fdset input[3] = {0}, output[3] = {0};
    for (size_t set = 0; set < 3U; set++) input[set].words[0] = bit;
    CHECK(sucrune_local_pselect(&f.io,input,output,&zero,NULL,-1) == select_result);
    if (select_result >= 0) for (size_t i = 0U; i < 3U; i++)
        CHECK(output[i].words[0] == (FD_ISSET(real, &sets[i]) ? bit : 0U));

    int native_epfd = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event event = {.events=EPOLLIN};
    CHECK(native_epfd >= 0 && epoll_ctl(native_epfd, EPOLL_CTL_ADD, real, &event) < 0);
    int ctl_error = -errno;
    int epfd = sucrune_local_epoll_create1(&f.io, 0);
    struct sucrune_local_event guest_event = {.events=EPOLLIN};
    CHECK(epfd >= 0 && sucrune_local_epoll_ctl(&f.io, epfd, EPOLL_CTL_ADD, fd, &guest_event) == ctl_error);
    CHECK(close(real) == 0 && close(native_epfd) == 0);
    finish(&f);
}
struct waiter { struct fixture *fixture; int epfd, result; struct sucrune_local_event events[64]; };
static void *wait_thread(void *argument) {
    struct waiter *waiter = argument;
    waiter->result = sucrune_local_epoll_pwait(&waiter->fixture->io,waiter->epfd,waiter->events,64,3000,NULL,8U);
    return NULL;
}
static void wait_retains_epoll_without_table_lock(void) {
    struct fixture f; setup(&f); int32_t pair[2];
    CHECK(sucrune_local_pipe2(&f.io,O_NONBLOCK,pair) == 0);
    int epfd = sucrune_local_epoll_create1(&f.io,0);
    struct sucrune_local_event event = {EPOLLIN,0U,UINT64_C(0x1234aabbccddeeff)};
    CHECK(sucrune_local_epoll_ctl(&f.io,epfd,EPOLL_CTL_ADD,pair[0],&event) == 0);
    atomic_store(&f.wait_acquired,0);
    struct waiter waiter = {.fixture=&f,.epfd=epfd,.result=-1}; pthread_t thread;
    CHECK(pthread_create(&thread,NULL,wait_thread,&waiter) == 0);
    while (atomic_load_explicit(&f.wait_acquired,memory_order_acquire) == 0) (void)sched_yield();
    CHECK(pthread_mutex_trylock(&f.mutex) == 0);
    CHECK(sucrune_fds_close(&f.table,(uint64_t)epfd) == 0);
    CHECK(pthread_mutex_unlock(&f.mutex) == 0);
    CHECK(sucrune_local_eventfd2(&f.io,0U,EFD_NONBLOCK) == epfd);
    CHECK(write(host(&f,pair[1]),"w",1U) == 1);
    CHECK(pthread_join(thread,NULL) == 0 && waiter.result == 1 && waiter.events[0].data == event.data);
    finish(&f);
}
static void high_descriptor_waits(void) {
    struct fixture f; setup(&f);
    struct sucrune_local_fdset input[3] = {0}, output[3] = {0};
    struct sucrune_local_timespec zero = {0,0};
    const uint64_t high_bit = UINT64_C(1) << 63U;
    input[0].words[15] = high_bit; /* FD 1023. */
    CHECK(sucrune_local_pselect(&f.io,input,output,&zero,NULL,-1) == -EBADF);
    sucrune_fds_enable_linux(&f.table);
    f.io.descriptor_limit = f.table.limit;
    int counter = sucrune_local_eventfd2(&f.io,1U,EFD_NONBLOCK);
    CHECK(counter >= 0);
    for (unsigned int slot=992U; slot<1024U; slot++) {
        CHECK(sucrune_fds_replace(&f.table,(uint64_t)counter,slot,0) == (int)slot);
        input[0].words[15] |= UINT64_C(1) << (slot%64U);
    }
    input[1].words[15] = high_bit;
    CHECK(sucrune_local_pselect(&f.io,input,output,&zero,NULL,-1) == 33);
    CHECK(memcmp(input,output,sizeof(input))==0);
    input[2].words[2] = UINT64_C(1); /* An unallocated descriptor within the limit. */
    CHECK(sucrune_local_pselect(&f.io,input,output,&zero,NULL,-1) == -EBADF);
    CHECK(output[2].words[2] == 0 && output[1].words[15] == high_bit);
    struct sucrune_local_pollfd array[1024];
    for (size_t i=0; i<1024U; i++) array[i]=(struct sucrune_local_pollfd){-1,POLLIN,0};
    array[2].fd = 128; array[1023].fd = 1023;
    CHECK(sucrune_local_ppoll(&f.io,array,1024U,&zero,NULL,NULL,8U) == 2);
    CHECK(array[1023].revents==POLLIN && array[2].revents==POLLNVAL && array[2].fd==128);
    finish(&f);
}
static void unsupported_masks_and_invalid_arguments(void) {
    struct fixture f; setup(&f); int32_t pair[2] = {-71,-72};
    CHECK(sucrune_local_pipe2(&f.io,0x40000000,pair) == -EINVAL && pair[0] == -71);
    CHECK(sucrune_local_eventfd2(&f.io,0U,0x40000000) == -EINVAL);
    CHECK(sucrune_local_epoll_create1(&f.io,1) == -EINVAL);
    int epfd = sucrune_local_epoll_create1(&f.io,0);
    struct sucrune_local_event events[64]; uint64_t mask = 0U;
    CHECK(sucrune_local_epoll_pwait(&f.io,epfd,events,0,0,NULL,8U) == -EINVAL);
    CHECK(sucrune_local_epoll_pwait(&f.io,epfd,events,64,0,&mask,8U) == -ENOTSUP);
    CHECK(sucrune_local_epoll_pwait(&f.io,epfd,events,64,0,&mask,128U) == -EINVAL);
    CHECK(sucrune_local_epoll_ctl(&f.io,epfd,EPOLL_CTL_ADD,63,NULL) == -EFAULT);
    CHECK(sucrune_local_epoll_ctl(&f.io,epfd,EPOLL_CTL_DEL,63,NULL) == -EBADF);
    struct sucrune_local_timespec invalid = {-1,0};
    CHECK(sucrune_local_ppoll(&f.io,NULL,0U,&invalid,NULL,NULL,8U) == -EINVAL);
    invalid = (struct sucrune_local_timespec){0,1000000000};
    CHECK(sucrune_local_ppoll(&f.io,NULL,0U,&invalid,NULL,NULL,8U) == -EINVAL);
    CHECK(sucrune_local_ppoll(&f.io,NULL,0U,NULL,NULL,&mask,8U) == -ENOTSUP);
    CHECK(sucrune_local_ppoll(&f.io,NULL,65U,NULL,NULL,NULL,8U) == -EINVAL);
    f.force_acquire_error = -EINTR;
    struct sucrune_local_pollfd descriptor = {epfd,POLLIN,77};
    struct sucrune_local_timespec timeout = {5,123}, remaining = {-99,-99};
    CHECK(sucrune_local_ppoll(&f.io,&descriptor,1U,&timeout,&remaining,NULL,8U) == -EINTR);
    CHECK(remaining.seconds == 5 && remaining.nanoseconds == 123 && descriptor.revents == 77);
    f.force_acquire_error = 0;
    finish(&f);
}
int main(void) {
    (void)alarm(30U);
    creation_and_flags(); creation_rollback(); pipe_capacity(); eventfd_counter_and_dup();
    epoll_data_and_alias_lifetime(); ppoll_errors_and_timeout(); wait_retains_epoll_without_table_lock();
    unsupported_masks_and_invalid_arguments();
    high_descriptor_waits();
    compare_file_readiness("/proc/self/exe", O_RDONLY);
    compare_file_readiness("/", O_RDONLY | O_DIRECTORY);
    compare_file_readiness("/proc/self/exe", O_PATH);
    (void)alarm(0U);
    printf("Local I/O kernel checks: %u/12 passed (pipe/eventfd/epoll/ppoll/pselect, aliases, rollback and retained waits).\n",cases);
    return 0;
}
