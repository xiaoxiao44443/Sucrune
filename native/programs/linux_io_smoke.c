#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

/* Real Linux guest fixture. No Android API or runtime-private entry point.
 * Two writers issue one <=PIPE_BUF writev per record. A reader checks every
 * complete record and sequence, catching split/interleaved writev emulation.
 * A separate guest thread waits on an epoll instance while main closes and
 * reuses its guest descriptor number. The original wait must retain its OFD. */
enum { WRITERS=2, RECORDS=256, RECORD_BYTES=64, WAIT_ATTEMPTS=5 };
_Static_assert(RECORD_BYTES <= PIPE_BUF, "record requires atomic pipe writes");
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "guest coordination must be lock free");
static const uint64_t DATA_FIRST = UINT64_C(0xfedcba9876543210);
static const uint64_t DATA_SECOND = UINT64_C(0x8000000000000001);
static _Atomic int writers_ready, writers_start;
static unsigned char seen[WRITERS][RECORDS];

static _Noreturn void fail(const char *stage, int error) {
    fprintf(stderr,"LINUX_IO_FAIL stage=%s error=%d\n",stage,error);
    fflush(stderr);
    (void)syscall(SYS_exit_group,92);
    _Exit(93);
}
static void require(int condition, const char *stage) { if (!condition) fail(stage,errno); }
static void checked(int result, const char *stage) { if (result != 0) fail(stage,result); }
static void close_fd(int descriptor) { if (close(descriptor) != 0) fail("close",errno); }
static void pause_ms(long milliseconds) {
    struct timespec delay = {.tv_sec=milliseconds/1000L,.tv_nsec=(milliseconds%1000L)*1000000L};
    while (nanosleep(&delay,&delay) != 0) if (errno != EINTR) fail("nanosleep",errno);
}
static void wait_value(_Atomic int *word, int expected, const char *stage) {
    struct timespec began, now;
    require(clock_gettime(CLOCK_MONOTONIC,&began) == 0,"clock");
    while (atomic_load_explicit(word,memory_order_acquire) != expected) {
        require(clock_gettime(CLOCK_MONOTONIC,&now) == 0,"clock");
        if (now.tv_sec-began.tv_sec >= 5) fail(stage,ETIMEDOUT);
        pause_ms(1);
    }
}
static void flags_and_eventfd(void) {
    int pair[2];
    require(pipe2(pair,O_NONBLOCK|O_CLOEXEC) == 0,"pipe2-flags");
    require((fcntl(pair[0],F_GETFD)&FD_CLOEXEC) != 0 && (fcntl(pair[1],F_GETFD)&FD_CLOEXEC) != 0,"pipe-cloexec");
    require((fcntl(pair[0],F_GETFL)&(O_ACCMODE|O_NONBLOCK)) == (O_RDONLY|O_NONBLOCK),"pipe-reader-flags");
    require((fcntl(pair[1],F_GETFL)&(O_ACCMODE|O_NONBLOCK)) == (O_WRONLY|O_NONBLOCK),"pipe-writer-flags");
    unsigned char byte;
    require(read(pair[0],&byte,1U) == -1 && errno == EAGAIN,"pipe-empty");
    require(write(pair[1],"p",1U) == 1 && read(pair[0],&byte,1U) == 1 && byte == 'p',"pipe-roundtrip");
    close_fd(pair[0]); close_fd(pair[1]);
    int event = eventfd(0U,EFD_NONBLOCK|EFD_CLOEXEC);
    require(event >= 0,"eventfd-create");
    int alias = dup(event);
    require(alias >= 0 && alias != event,"eventfd-dup");
    require((fcntl(event,F_GETFD)&FD_CLOEXEC) != 0 && (fcntl(alias,F_GETFD)&FD_CLOEXEC) == 0,"dup-cloexec");
    int flags = fcntl(event,F_GETFL);
    require(flags >= 0 && fcntl(alias,F_SETFL,flags&~O_NONBLOCK) == 0 &&
        (fcntl(event,F_GETFL)&O_NONBLOCK) == 0,"dup-shared-status");
    require(fcntl(event,F_SETFL,flags) == 0,"eventfd-restore-flags");
    uint64_t value = 7U, received = 0U;
    require(write(alias,&value,sizeof(value)) == (ssize_t)sizeof(value),"eventfd-write");
    require(read(event,&received,sizeof(received)) == (ssize_t)sizeof(received) && received == value,"eventfd-counter");
    require(read(alias,&received,sizeof(received)) == -1 && errno == EAGAIN,"eventfd-drained");
    close_fd(event); close_fd(alias);
}
static void expect_alias_events(int epfd) {
    struct epoll_event events[8];
    int ready = epoll_pwait(epfd,events,8,1000,NULL);
    require(ready == 2,"epoll-two-aliases");
    unsigned int found = 0U;
    for (int i=0;i<ready;i++) {
        require((events[i].events&EPOLLIN) != 0U,"epoll-ready-mask");
        if (events[i].data.u64 == DATA_FIRST) found |= 1U;
        else if (events[i].data.u64 == DATA_SECOND) found |= 2U;
        else fail("epoll-data64",i);
    }
    require(found == 3U,"epoll-distinct-data64");
}
static void epoll_aliases(void) {
    int pair[2]; require(pipe2(pair,O_NONBLOCK|O_CLOEXEC) == 0,"alias-pipe");
    int alias = dup(pair[0]), epfd = epoll_create1(EPOLL_CLOEXEC);
    require(alias >= 0 && epfd >= 0,"alias-setup");
    struct epoll_event event = {.events=EPOLLIN,.data={.u64=DATA_FIRST}};
    require(epoll_ctl(epfd,EPOLL_CTL_ADD,pair[0],&event) == 0,"epoll-add-first");
    event.data.u64 = DATA_SECOND;
    require(epoll_ctl(epfd,EPOLL_CTL_ADD,alias,&event) == 0,"epoll-add-dup-alias");
    require(write(pair[1],"a",1U) == 1,"alias-write");
    expect_alias_events(epfd);
    close_fd(pair[0]);
    /* Linux keeps both interests while another FD still owns the same OFD. */
    expect_alias_events(epfd);
    close_fd(alias);
    struct epoll_event events[8];
    require(epoll_pwait(epfd,events,8,0,NULL) == 0,"epoll-last-alias-removes-interest");
    close_fd(pair[1]); close_fd(epfd);
}
static void make_record(unsigned char *record, unsigned int writer, uint32_t sequence) {
    for (unsigned int i=0U;i<RECORD_BYTES;i++) record[i]=(unsigned char)(0x30U+writer*51U+(sequence&15U)+i);
    record[0]=(unsigned char)('A'+writer); record[1]=0x5aU; record[2]=0xa5U; record[3]=0x7eU;
    memcpy(record+4U,&sequence,sizeof(sequence));
}
struct writer { int fd; unsigned int index; };
static void *write_records(void *argument) {
    struct writer *writer = argument;
    atomic_fetch_add_explicit(&writers_ready,1,memory_order_release);
    wait_value(&writers_start,1,"writer-start");
    for (uint32_t sequence=0U;sequence<RECORDS;sequence++) {
        unsigned char record[RECORD_BYTES]; make_record(record,writer->index,sequence);
        struct iovec vectors[2] = {{record,31U},{record+31U,RECORD_BYTES-31U}};
        ssize_t result;
        do { result=writev(writer->fd,vectors,2); } while(result<0 && errno==EINTR);
        if (result != RECORD_BYTES) fail("atomic-writev",result<0 ? errno : (int)result);
    }
    close_fd(writer->fd);
    return NULL;
}
static void validate_record(const unsigned char *record) {
    if (record[0]<'A' || record[0]>='A'+WRITERS) fail("record-writer",record[0]);
    unsigned int writer = (unsigned int)(record[0]-'A');
    uint32_t sequence; memcpy(&sequence,record+4U,sizeof(sequence));
    if (sequence>=RECORDS || seen[writer][sequence]!=0U) fail("record-sequence",(int)sequence);
    unsigned char expected[RECORD_BYTES]; make_record(expected,writer,sequence);
    if (memcmp(record,expected,RECORD_BYTES)!=0) fail("writev-interleaved",(int)sequence);
    seen[writer][sequence]=1U;
}
static void parallel_writev(void) {
    int pair[2]; require(pipe2(pair,O_CLOEXEC)==0,"writev-pipe");
    pthread_t threads[WRITERS]; struct writer writers[WRITERS];
    for (unsigned int i=0U;i<WRITERS;i++) {
        writers[i]=(struct writer){.fd=dup(pair[1]),.index=i};
        require(writers[i].fd>=0,"writer-dup");
        checked(pthread_create(&threads[i],NULL,write_records,&writers[i]),"writer-create");
    }
    close_fd(pair[1]);
    wait_value(&writers_ready,WRITERS,"writers-ready");
    atomic_store_explicit(&writers_start,1,memory_order_release);
    unsigned char bytes[2048], record[RECORD_BYTES]; size_t used=0U; unsigned int records=0U;
    for (;;) {
        ssize_t count=read(pair[0],bytes,sizeof(bytes));
        if (count<0 && errno==EINTR) continue;
        require(count>=0,"record-read");
        if (count==0) break;
        for (size_t i=0U;i<(size_t)count;i++) {
            record[used++]=bytes[i];
            if (used==RECORD_BYTES) {validate_record(record);used=0U;records++;}
        }
    }
    require(used==0U && records==WRITERS*RECORDS,"record-total");
    for (unsigned int i=0U;i<WRITERS;i++) {
        checked(pthread_join(threads[i],NULL),"writer-join");
        for (unsigned int j=0U;j<RECORDS;j++) require(seen[i][j]==1U,"record-missing");
    }
    close_fd(pair[0]);
}
struct epoll_waiter { int epfd, result, error; _Atomic int ready, done; struct epoll_event event; };
static void *wait_old_epoll(void *argument) {
    struct epoll_waiter *waiter = argument;
    atomic_store_explicit(&waiter->ready,1,memory_order_release);
    waiter->result=epoll_pwait(waiter->epfd,&waiter->event,1,3000,NULL);
    waiter->error=waiter->result<0 ? errno : 0;
    atomic_store_explicit(&waiter->done,1,memory_order_release);
    return NULL;
}
static unsigned int retained_epoll(void) {
    for (unsigned int attempt=1U;attempt<=WAIT_ATTEMPTS;attempt++) {
        int pair[2]; require(pipe2(pair,O_NONBLOCK|O_CLOEXEC)==0,"retain-pipe");
        int epfd=epoll_create1(EPOLL_CLOEXEC); require(epfd>=0,"retain-epoll");
        struct epoll_event event={.events=EPOLLIN,.data={.u64=DATA_FIRST}};
        require(epoll_ctl(epfd,EPOLL_CTL_ADD,pair[0],&event)==0,"retain-add");
        struct epoll_waiter waiter={.epfd=epfd,.result=-99};
        atomic_init(&waiter.ready,0); atomic_init(&waiter.done,0);
        pthread_t thread; checked(pthread_create(&thread,NULL,wait_old_epoll,&waiter),"waiter-create");
        wait_value(&waiter.ready,1,"waiter-ready");
        /* A pure guest cannot observe the host's syscall-entry boundary.
         * Allow scheduling time, and retry a detected close-before-entry race
         * instead of counting that race as old-epoll lifetime coverage. */
        pause_ms(100);
        require(atomic_load_explicit(&waiter.done,memory_order_acquire)==0,"waiter-ended-early");
        close_fd(epfd);
        int replacement=eventfd(0U,EFD_NONBLOCK|EFD_CLOEXEC);
        require(replacement==epfd,"guest-fd-reuse");
        require(write(pair[1],"r",1U)==1,"retain-ready-write");
        checked(pthread_join(thread,NULL),"waiter-join");
        close_fd(replacement); close_fd(pair[0]); close_fd(pair[1]);
        if (waiter.result==1) {
            require(waiter.event.data.u64==DATA_FIRST && (waiter.event.events&EPOLLIN)!=0U,"retained-old-event");
            return attempt;
        }
        if (waiter.result<0 && (waiter.error==EBADF || waiter.error==EINVAL)) continue;
        fail("retained-epoll-wait",waiter.result<0 ? waiter.error : ETIMEDOUT);
    }
    fail("retained-epoll-no-observation",EAGAIN);
}
int main(void) {
    flags_and_eventfd(); epoll_aliases(); parallel_writev();
    unsigned int attempts=retained_epoll();
    printf("LINUX_IO_OK pipe2 eventfd epoll_alias data64 writev_atomic records=%u retained_epoll attempts=%u\n",
        WRITERS*RECORDS,attempts);
    return 0;
}
