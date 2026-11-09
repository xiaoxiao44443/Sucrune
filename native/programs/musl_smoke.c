#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/auxv.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* A normal Linux libc program: no Sucrune entry point or syscall wrappers. */
static __thread volatile unsigned int tls_initialized = 0x1234abcdU;
static __thread volatile unsigned int tls_zero;
static volatile unsigned int exec_initialized = 0x11223344U;
static volatile unsigned int exec_zero;
static const char file_contents[] = "Sucrune musl: 中文🙂\n";
extern char **environ;

static int failure(const char *step) {
    int saved = errno;
    if (fprintf(stderr, "musl:fail=%s errno=%d\n", step, saved) < 0)
        printf("musl:fail=%s errno=%d\n", step, saved);
    return 1;
}

static int descriptor_flags_roundtrip(int descriptor) {
    int original = fcntl(descriptor, F_GETFD);
    if (original < 0) { fprintf(stderr, "musl:fd-flags fd=%d get=%d errno=%d\n", descriptor, original, errno); return -1; }
    int changed = original ^ FD_CLOEXEC;
    int set = fcntl(descriptor, F_SETFD, changed);
    int observed = fcntl(descriptor, F_GETFD);
    if (set != 0 || observed != changed) {
        fprintf(stderr, "musl:fd-flags fd=%d original=%d set=%d changed=%d observed=%d errno=%d\n", descriptor, original, set, changed, observed, errno);
        return -1;
    }
    int restored = fcntl(descriptor, F_SETFD, original);
    int after = fcntl(descriptor, F_GETFD);
    if (restored != 0 || after != original) {
        fprintf(stderr, "musl:fd-flags fd=%d restore=%d expected=%d after=%d errno=%d\n", descriptor, restored, original, after, errno);
        return -1;
    }
    return 0;
}

static int selftest(int argc, char **argv) {
    const char *value = getenv("SUCRUNE_TEST");
    printf("musl:argv=%s\n", argc > 2 ? argv[2] : "");
    printf("musl:env=%s\n", value != NULL ? value : "");
    fprintf(stderr, "musl:stderr=ok\n");
    if (descriptor_flags_roundtrip(STDIN_FILENO) != 0 ||
        descriptor_flags_roundtrip(STDOUT_FILENO) != 0 ||
        descriptor_flags_roundtrip(STDERR_FILENO) != 0) return failure("stdio-fd-flags");

    if (tls_initialized != 0x1234abcdU || tls_zero != 0U) return failure("tls-initial");
    tls_initialized = 0x78563412U;
    tls_zero = 0xabcdef12U;
    errno = 0;
    if (open("/sucrune-definitely-missing", O_RDONLY) != -1 || errno != ENOENT) return failure("errno");
    int *errno_address = &errno;
    errno = EDOM;
    (void)getpid();
    if (errno != EDOM || &errno != errno_address || tls_initialized != 0x78563412U || tls_zero != 0xabcdef12U) {
        return failure("tls-after-trap");
    }
    /* Linux permits x18 as a general register. Deliberately give it a value
     * that cannot serve as Android's shadow-call-stack pointer across a trap.
     * The runtime must switch to the host value before any handler C executes,
     * and preserve the guest value in the restored signal register frame. */
    uint64_t saved_x18, observed_x18;
    const uint64_t magic_x18 = UINT64_C(0x123456789abcdef0);
    register long process_id __asm__("x0");
    register long syscall_number __asm__("x8") = 172; /* Linux AArch64 getpid */
    __asm__ volatile("mov %0, x18\n"
                     "mov x18, %3\n"
                     "svc #0\n"
                     "mov %1, x18\n"
                     "mov x18, %0\n"
                     : "=&r"(saved_x18), "=&r"(observed_x18), "=r"(process_id)
                     : "r"(magic_x18), "r"(syscall_number)
                     : "x18", "memory", "cc");
    if (observed_x18 != magic_x18 || process_id <= 0) return failure("x18-after-trap");
    puts("musl:tls=ok");

    const size_t allocation_size = 1024U * 1024U;
    unsigned char *allocation = malloc(allocation_size);
    if (allocation == NULL) return failure("malloc");
    for (size_t index = 0; index < allocation_size; ++index) allocation[index] = (unsigned char)(index * 13U);
    for (size_t index = 0; index < allocation_size; ++index) {
        if (allocation[index] != (unsigned char)(index * 13U)) { free(allocation); return failure("malloc-content"); }
    }
    free(allocation);
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size < 4096 || page_size > 65536) return failure("page-size");
    size_t mapping_size = (size_t)page_size;
    unsigned char *mapping = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) return failure("mmap");
    mapping[0] = 91;
    mapping[mapping_size - 1U] = 73;
    if (mprotect(mapping, mapping_size, PROT_READ) != 0) return failure("mprotect-read");
    if (mapping[0] != 91 || mapping[mapping_size - 1U] != 73) return failure("mmap-content");
    if (mprotect(mapping, mapping_size, PROT_READ | PROT_WRITE) != 0) return failure("mprotect-write");
    mapping[0] = 42;
    if (mprotect(mapping, mapping_size, PROT_NONE) != 0) return failure("mprotect-none");
    errno = 0;
    if (write(STDOUT_FILENO, mapping, 1) != -1 || errno != EFAULT) return failure("none-pointer");
    if (mprotect(mapping, mapping_size, PROT_READ | PROT_WRITE) != 0) return failure("mprotect-restore");
    void *code_page = (void *)((uintptr_t)&selftest & ~((uintptr_t)mapping_size - 1U));
    void *stack_page = (void *)((uintptr_t)&page_size & ~((uintptr_t)mapping_size - 1U));
    errno = 0;
    if (mprotect(code_page, mapping_size, PROT_READ) != -1 || errno != EINVAL) return failure("protect-code-boundary");
    errno = 0;
    if (mprotect(stack_page, mapping_size, PROT_READ) != -1 || errno != EINVAL) return failure("protect-stack-boundary");
    errno = 0;
    if (munmap(stack_page, mapping_size) != -1 || errno != EINVAL) return failure("unmap-stack-boundary");
    errno = 0;
    if (mmap(NULL, mapping_size, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) != MAP_FAILED || errno != EACCES) return failure("executable-memory");
    errno = 0;
    if (mmap(NULL, 128U * 1024U * 1024U, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) != MAP_FAILED || errno != EINVAL) return failure("memory-limit");
    if (munmap(mapping, mapping_size) != 0) return failure("munmap");
    mapping = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) return failure("remap");
    for (size_t index = 0; index < mapping_size; ++index) if (mapping[index] != 0) return failure("remap-zero");
    if (munmap(mapping, mapping_size) != 0) return failure("remap-unmap");
    puts("musl:memory=ok");

    FILE *file = fopen("libc-result.txt", "w+");
    if (file == NULL) return failure("fopen");
    if (descriptor_flags_roundtrip(fileno(file)) != 0) return failure("file-fd-flags");
    if (fwrite(file_contents, 1, sizeof(file_contents) - 1U, file) != sizeof(file_contents) - 1U) return failure("fwrite");
    if (fflush(file) != 0) return failure("fflush");
    struct stat file_stat;
    if (fstat(fileno(file), &file_stat) != 0 || file_stat.st_size != (off_t)(sizeof(file_contents) - 1U) || !S_ISREG(file_stat.st_mode)) return failure("fstat");
    if (fseek(file, 0, SEEK_SET) != 0) return failure("fseek");
    char buffer[sizeof(file_contents)];
    memset(buffer, 0, sizeof(buffer));
    if (fread(buffer, 1, sizeof(buffer) - 1U, file) != sizeof(file_contents) - 1U || strcmp(buffer, file_contents) != 0) return failure("fread");
    if (fclose(file) != 0) return failure("fclose");
    if (stat("libc-result.txt", &file_stat) != 0 || file_stat.st_size != (off_t)(sizeof(file_contents) - 1U)) return failure("stat");
    puts("musl:file=ok");
    puts("musl:ok");
    return 42;
}

static int read_exact(int descriptor, char *buffer, size_t length) {
    size_t used = 0U;
    while (used < length) {
        ssize_t count = read(descriptor, buffer + used, length - used);
        if (count <= 0) return -1;
        used += (size_t)count;
    }
    return 0;
}

static long number_arg(const char *value) {
    char *end = NULL;
    errno = 0;
    long number = strtol(value, &end, 10);
    return errno != 0 || end == value || *end != '\0' || number < 0 ? -1 : number;
}

static int exec_state(int argc, char **argv) {
    if (strcmp(argv[1], "--exec-state") == 0 && argc == 2) {
        int keep = open("exec-state.txt", O_CREAT | O_TRUNC | O_RDWR, 0600);
        int clo_open = open("exec-clo-open.txt", O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
        int clo_fcntl = open("exec-clo-fcntl.txt", O_CREAT | O_TRUNC | O_RDWR, 0600);
        if (keep < 0 || clo_open < 0 || clo_fcntl < 0 || write(keep, "abcdef", 6U) != 6 ||
            lseek(keep, 2, SEEK_SET) != 2 || fcntl(clo_fcntl, F_SETFD, FD_CLOEXEC) != 0 ||
            fcntl(STDERR_FILENO, F_SETFD, FD_CLOEXEC) != 0) return failure("exec-state-prepare-fds");
        if (mkdir("exec-sub", 0700) != 0 && errno != EEXIST) return failure("exec-state-mkdir");
        if (chdir("exec-sub") != 0) return failure("exec-state-chdir");
        char prefix[7];
        if (read_exact(STDIN_FILENO, prefix, sizeof(prefix)) != 0 || memcmp(prefix, "prefix:", sizeof(prefix)) != 0)
            return failure("exec-state-stdin-prefix");
        unsigned char *mapping = mmap(NULL, 1024U * 1024U, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mapping == MAP_FAILED) return failure("exec-state-mmap");
        memset(mapping, 0x5a, 1024U * 1024U);
        tls_initialized = 7U; tls_zero = 8U; exec_initialized = 9U; exec_zero = 10U;
        uint64_t signal_mask = UINT64_C(1) << (SIGUSR1 - 1);
        if (syscall(SYS_rt_sigprocmask, SIG_BLOCK, &signal_mask, NULL, sizeof(signal_mask)) != 0)
            return failure("exec-state-signal-mask");
        if (setenv("EXEC_SHOULD_DISAPPEAR", "old-image", 1) != 0) return failure("exec-state-setenv");
        char keep_text[32], open_text[32], fcntl_text[32], pid_text[32], tid_text[32];
        snprintf(keep_text, sizeof(keep_text), "%d", keep);
        snprintf(open_text, sizeof(open_text), "%d", clo_open);
        snprintf(fcntl_text, sizeof(fcntl_text), "%d", clo_fcntl);
        snprintf(pid_text, sizeof(pid_text), "%ld", (long)getpid());
        snprintf(tid_text, sizeof(tid_text), "%ld", syscall(SYS_gettid));
        char *next[] = {"exec-state-custom-argv0", "--exec-state-post", keep_text, open_text, fcntl_text, pid_text, tid_text, NULL};
        char *environment[] = {"EXEC_VALUE=环境中文🙂", "ONLY_EXEC=1", NULL};
        (void)execve("/bin/musl-smoke", next, environment);
        return failure("exec-state-returned");
    }
    if (strcmp(argv[1], "--exec-state-post") != 0 || argc != 7) return failure("exec-state-post-arguments");
    const char *exec_path = (const char *)getauxval(AT_EXECFN);
    uint64_t signal_mask = 0;
    if (exec_path == NULL || strcmp(exec_path, "/bin/musl-smoke") != 0 || strcmp(argv[0], "exec-state-custom-argv0") != 0)
        return failure("exec-state-execfn");
    if (syscall(SYS_rt_sigprocmask, SIG_SETMASK, NULL, &signal_mask, sizeof(signal_mask)) != 0 ||
        (signal_mask & (UINT64_C(1) << (SIGUSR1 - 1))) == 0U) return failure("exec-state-preserved-signal-mask");
    if ((long)getpid() != number_arg(argv[5]) || syscall(SYS_gettid) != number_arg(argv[6])) return failure("exec-state-identity");
    if (tls_initialized != 0x1234abcdU || tls_zero != 0U || exec_initialized != 0x11223344U || exec_zero != 0U)
        return failure("exec-state-fresh-tls-bss");
    const char *value = getenv("EXEC_VALUE"), *only = getenv("ONLY_EXEC");
    if (value == NULL || strcmp(value, "环境中文🙂") != 0 || only == NULL || strcmp(only, "1") != 0 ||
        getenv("EXEC_SHOULD_DISAPPEAR") != NULL) return failure("exec-state-environment");
    char cwd[128];
    if (getcwd(cwd, sizeof(cwd)) == NULL || strcmp(cwd, "/exec-sub") != 0) return failure("exec-state-cwd");
    int keep = (int)number_arg(argv[2]), clo_open = (int)number_arg(argv[3]), clo_fcntl = (int)number_arg(argv[4]);
    char contents[4];
    if (keep < 3 || clo_open < 3 || clo_fcntl < 3 || fcntl(keep, F_GETFD) != 0 ||
        read_exact(keep, contents, sizeof(contents)) != 0 || memcmp(contents, "cdef", sizeof(contents)) != 0)
        return failure("exec-state-preserved-fd-offset");
    errno = 0;
    if (fcntl(clo_open, F_GETFD) != -1 || errno != EBADF) return failure("exec-state-open-cloexec");
    errno = 0;
    if (fcntl(clo_fcntl, F_GETFD) != -1 || errno != EBADF) return failure("exec-state-fcntl-cloexec");
    errno = 0;
    if (write(STDERR_FILENO, "x", 1U) != -1 || errno != EBADF) return failure("exec-state-stderr-cloexec");
    char remaining[10], extra;
    if (read_exact(STDIN_FILENO, remaining, sizeof(remaining)) != 0 || memcmp(remaining, "remaining\n", sizeof(remaining)) != 0 ||
        read(STDIN_FILENO, &extra, 1U) != 0) return failure("exec-state-stdin-remainder");
    unsigned char *mapping = mmap(NULL, 1024U * 1024U, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) return failure("exec-state-fresh-mmap");
    for (size_t i = 0U; i < 1024U * 1024U; i++) if (mapping[i] != 0U) return failure("exec-state-mmap-zero");
    if (munmap(mapping, 1024U * 1024U) != 0 || close(keep) != 0) return failure("exec-state-close");
    puts("exec:state=ok");
    return 0;
}

static int expect_exec_error(const char *path, char *const arguments[], char *const environment[], int expected) {
    errno = 0;
    int result = execve(path, arguments, environment);
    if (result == -1 && errno == expected) return 0;
    fprintf(stderr, "exec:expected-errno=%d actual=%d result=%d\n", expected, errno, result);
    return -1;
}

static int exec_errors(void) {
    int file = open("exec-errors.txt", O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
    if (file < 3 || write(file, "old-image", 9U) != 9 || lseek(file, 4, SEEK_SET) != 4 ||
        fcntl(STDIN_FILENO, F_SETFD, FD_CLOEXEC) != 0 || fcntl(STDOUT_FILENO, F_SETFD, FD_CLOEXEC) != 0)
        return failure("exec-errors-prepare");
    tls_initialized = 21U; tls_zero = 22U; exec_initialized = 23U; exec_zero = 24U;
    char *normal[] = {"musl-smoke", "echo", "should-not-run", NULL};
    char *empty[] = {NULL};
    if (expect_exec_error("/bin/does-not-exist", normal, empty, ENOENT) != 0 ||
        expect_exec_error((const char *)(uintptr_t)1U, normal, empty, EFAULT) != 0 ||
        expect_exec_error("/bin/musl-smoke", (char *const *)(uintptr_t)1U, empty, EFAULT) != 0 ||
        expect_exec_error("/bin/musl-smoke", normal, (char *const *)(uintptr_t)1U, EFAULT) != 0)
        return failure("exec-errors-pointer-path");
    char *bad_item[] = {"musl-smoke", (char *)(uintptr_t)1U, NULL};
    char *many[67];
    for (size_t i = 0U; i < 66U; i++) many[i] = "argument";
    many[66] = NULL;
    char *many_env[66];
    for (size_t i = 0U; i < 65U; i++) many_env[i] = "NAME=value";
    many_env[65] = NULL;
    if (expect_exec_error("/bin/musl-smoke", bad_item, empty, EFAULT) != 0 ||
        expect_exec_error("/bin/musl-smoke", many, empty, E2BIG) != 0 ||
        expect_exec_error("/bin/musl-smoke", normal, many_env, E2BIG) != 0)
        return failure("exec-errors-array-bounds");
    char *oversized = malloc(65537U);
    if (oversized == NULL) return failure("exec-errors-allocation");
    memset(oversized, 'x', 65536U); oversized[65536] = '\0';
    char *long_argument[] = {"musl-smoke", oversized, NULL};
    int too_big = expect_exec_error("/bin/musl-smoke", long_argument, empty, E2BIG);
    free(oversized);
    if (too_big != 0) return failure("exec-errors-byte-limit");
    char contents[5];
    char eof;
    if (fcntl(file, F_GETFD) != FD_CLOEXEC || fcntl(STDIN_FILENO, F_GETFD) != FD_CLOEXEC ||
        fcntl(STDOUT_FILENO, F_GETFD) != FD_CLOEXEC || read(STDIN_FILENO, &eof, 1U) != 0 ||
        read_exact(file, contents, sizeof(contents)) != 0 ||
        memcmp(contents, "image", sizeof(contents)) != 0 || tls_initialized != 21U || tls_zero != 22U ||
        exec_initialized != 23U || exec_zero != 24U || close(file) != 0) return failure("exec-errors-state-changed");
    puts("exec:errors=ok");
    return 0;
}

static int exec_standard(int argc, char **argv, int descriptor) {
    const char *mode = descriptor == STDIN_FILENO ? "--exec-stdin-cloexec" : "--exec-stdout-cloexec";
    if (argc == 2) {
        if (fcntl(descriptor, F_SETFD, FD_CLOEXEC) != 0) return failure("exec-standard-prepare");
        char *next[] = {"/bin/musl-smoke", (char *)mode, "post", NULL};
        (void)execve(next[0], next, environ);
        return failure("exec-standard-returned");
    }
    if (argc != 3 || strcmp(argv[2], "post") != 0) return failure("exec-standard-arguments");
    char byte = 0;
    errno = 0;
    ssize_t result = descriptor == STDIN_FILENO ? read(descriptor, &byte, 1U) : write(descriptor, &byte, 1U);
    if (result != -1 || errno != EBADF) return failure("exec-standard-not-closed");
    if (descriptor == STDIN_FILENO) puts("exec:stdin-cloexec=ok");
    else fputs("exec:stdout-cloexec=ok\n", stderr);
    return 0;
}

static int exec_chain(int argc, char **argv) {
    long count = argc == 2 ? 0 : argc == 3 ? number_arg(argv[2]) : -1;
    if (count < 0 || count > 32) return failure("exec-chain-count");
    char next_count[16];
    snprintf(next_count, sizeof(next_count), "%ld", count + 1);
    char *next[] = {"/bin/musl-smoke", "--exec-chain", next_count, NULL};
    errno = 0;
    int result = execve(next[0], next, environ);
    if (count != 32 || result != -1 || errno != ELOOP) return failure("exec-chain-limit");
    puts("exec:chain=32");
    return 0;
}

static int fd_aliases(void) {
    int file = open("fd-aliases.txt", O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (file != 3 || write(file, "abcdef", 6U) != 6 || lseek(file, 1, SEEK_SET) != 1)
        return failure("fd-aliases-open");
    int duplicate = dup(file);
    int high = fcntl(file, F_DUPFD, 10);
    int clo = fcntl(file, F_DUPFD_CLOEXEC, 20);
    if (duplicate != 4 || high != 10 || clo != 20 || fcntl(clo, F_GETFD) != FD_CLOEXEC ||
        fcntl(duplicate, F_GETFD) != 0 || fcntl(high, F_GETFD) != 0 ||
        fcntl(file, F_SETFD, FD_CLOEXEC) != 0 || fcntl(duplicate, F_GETFD) != 0)
        return failure("fd-aliases-flags");
    char bytes[8] = {0};
    if (read_exact(duplicate, bytes, 2U) != 0 || memcmp(bytes, "bc", 2U) != 0 ||
        read_exact(high, bytes, 2U) != 0 || memcmp(bytes, "de", 2U) != 0)
        return failure("fd-aliases-shared-read-offset");
    int flags = fcntl(high, F_GETFL);
    if (flags < 0 || fcntl(high, F_SETFL, flags | O_APPEND) != 0 ||
        (fcntl(file, F_GETFL) & O_APPEND) == 0 || lseek(file, 0, SEEK_SET) != 0 ||
        write(clo, "Z", 1U) != 1 || lseek(duplicate, 0, SEEK_CUR) != 7)
        return failure("fd-aliases-shared-append");
    if (fcntl(file, F_SETFL, flags & ~O_APPEND) != 0 || (fcntl(clo, F_GETFL) & O_APPEND) != 0 ||
        lseek(high, 0, SEEK_SET) != 0 || read_exact(duplicate, bytes, 7U) != 0 ||
        memcmp(bytes, "abcdefZ", 7U) != 0 || close(file) != 0)
        return failure("fd-aliases-shared-seek");
    int reused = open("fd-replace-target.txt", O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (reused != 3 || write(reused, "target", 6U) != 6 ||
        dup3(duplicate, reused, O_CLOEXEC) != reused || fcntl(reused, F_GETFD) != FD_CLOEXEC ||
        fcntl(duplicate, F_GETFD) != 0 || lseek(reused, 1, SEEK_SET) != 1 ||
        read_exact(clo, bytes, 2U) != 0 || memcmp(bytes, "bc", 2U) != 0 ||
        dup2(duplicate, duplicate) != duplicate || fcntl(duplicate, F_GETFD) != 0)
        return failure("fd-aliases-replace-and-self-dup2");
    if (close(reused) != 0 || close(duplicate) != 0 || close(high) != 0 || close(clo) != 0)
        return failure("fd-aliases-close");
    file = open("fd-replace-target.txt", O_RDONLY);
    if (file != 3 || read_exact(file, bytes, 6U) != 0 || memcmp(bytes, "target", 6U) != 0 || close(file) != 0)
        return failure("fd-aliases-old-target-preserved");
    puts("fd:aliases=ok");
    return 0;
}

static int fd_errors(void) {
    int source = open("fd-errors-source.txt", O_CREAT | O_TRUNC | O_RDWR, 0600);
    int target = open("fd-errors-target.txt", O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (source != 3 || target != 4 || write(source, "source", 6U) != 6 || write(target, "target", 6U) != 6 ||
        lseek(target, 2, SEEK_SET) != 2 || fcntl(target, F_SETFD, FD_CLOEXEC) != 0)
        return failure("fd-errors-prepare");
#define EXPECT_FD_ERROR(call, expected, label) do { errno = 0; if ((call) != -1 || errno != (expected)) return failure(label); } while (0)
    EXPECT_FD_ERROR(dup(-1), EBADF, "fd-errors-dup-invalid");
    EXPECT_FD_ERROR(dup3(64, target, 0), EBADF, "fd-errors-invalid-source");
    EXPECT_FD_ERROR(dup3(source, 64, 0), EBADF, "fd-errors-invalid-target");
    EXPECT_FD_ERROR(dup3(source, source, 0), EINVAL, "fd-errors-dup3-self");
    EXPECT_FD_ERROR(dup3(source, target, O_NONBLOCK), EINVAL, "fd-errors-dup3-flags");
    EXPECT_FD_ERROR(fcntl(source, F_DUPFD, -1), EINVAL, "fd-errors-negative-minimum");
    EXPECT_FD_ERROR(fcntl(source, F_DUPFD, 64), EINVAL, "fd-errors-large-minimum");
    int status_alias = dup(source);
    if (status_alias != 5 || fcntl(source, F_SETFL, O_NONBLOCK) != 0)
        return failure("fd-errors-enable-nonblock");
    int alias_status = fcntl(status_alias, F_GETFL);
    if (alias_status < 0 || (alias_status & O_NONBLOCK) == 0 || fcntl(status_alias, F_SETFL, 0) != 0)
        return failure("fd-errors-alias-nonblock");
    int source_status = fcntl(source, F_GETFL);
    if (source_status < 0 || (source_status & O_NONBLOCK) != 0 || close(status_alias) != 0)
        return failure("fd-errors-shared-nonblock-state");
    EXPECT_FD_ERROR(fcntl(source, F_SETFL, O_ASYNC), EINVAL, "fd-errors-async-unsupported");
    if (fcntl(target, F_GETFD) != FD_CLOEXEC || lseek(target, 0, SEEK_CUR) != 2)
        return failure("fd-errors-target-mutated");
    int aliases[59];
    for (size_t i = 0U; i < 59U; i++) {
        aliases[i] = dup(source);
        if (aliases[i] != (int)i + 5) return failure("fd-errors-fill-table");
    }
    EXPECT_FD_ERROR(dup(source), EMFILE, "fd-errors-dup-full");
    EXPECT_FD_ERROR(open("fd-errors-target.txt", O_WRONLY | O_TRUNC), EMFILE, "fd-errors-open-full");
    EXPECT_FD_ERROR(open("fd-errors-forbidden.txt", O_CREAT | O_WRONLY, 0600), EMFILE, "fd-errors-create-full");
    if (close(aliases[17]) != 0 || fcntl(source, F_DUPFD_CLOEXEC, aliases[17]) != aliases[17] ||
        fcntl(aliases[17], F_GETFD) != FD_CLOEXEC) return failure("fd-errors-reuse-hole");
    for (size_t i = 0U; i < 59U; i++) if (close(aliases[i]) != 0) return failure("fd-errors-close-aliases");
    char bytes[6];
    if (lseek(target, 0, SEEK_SET) != 0 || read_exact(target, bytes, sizeof(bytes)) != 0 ||
        memcmp(bytes, "target", sizeof(bytes)) != 0 || close(source) != 0 || close(target) != 0)
        return failure("fd-errors-open-full-mutated-file");
    EXPECT_FD_ERROR(open("fd-errors-forbidden.txt", O_RDONLY), ENOENT, "fd-errors-open-full-created-file");
#undef EXPECT_FD_ERROR
    puts("fd:errors=ok");
    return 0;
}

static int fd_exec_aliases(int argc, char **argv) {
    if (argc == 2) {
        int original = open("fd-exec-aliases.txt", O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
        if (original != 3 || write(original, "abcdef", 6U) != 6 || lseek(original, 1, SEEK_SET) != 1)
            return failure("fd-exec-prepare");
        int keep = dup(original);
        int clo = fcntl(original, F_DUPFD_CLOEXEC, 20);
        if (keep != 4 || clo != 20 || dup3(keep, 10, 0) != 10 || fcntl(keep, F_GETFD) != 0)
            return failure("fd-exec-aliases");
        char *next[] = {"/bin/musl-smoke", "--fd-exec-aliases", "post", NULL};
        (void)execve(next[0], next, environ);
        return failure("fd-exec-returned");
    }
    if (argc != 3 || strcmp(argv[2], "post") != 0) return failure("fd-exec-post-arguments");
    errno = 0;
    if (fcntl(3, F_GETFD) != -1 || errno != EBADF) return failure("fd-exec-original-cloexec");
    errno = 0;
    if (fcntl(20, F_GETFD) != -1 || errno != EBADF) return failure("fd-exec-alias-cloexec");
    char bytes[3];
    if (fcntl(4, F_GETFD) != 0 || fcntl(10, F_GETFD) != 0 || read_exact(4, bytes, 2U) != 0 ||
        memcmp(bytes, "bc", 2U) != 0 || read_exact(10, bytes, 2U) != 0 || memcmp(bytes, "de", 2U) != 0)
        return failure("fd-exec-preserved-offset");
    int reused = open("fd-exec-new.txt", O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (reused != 3 || close(reused) != 0 || close(4) != 0 || read_exact(10, bytes, 1U) != 0 ||
        bytes[0] != 'f' || close(10) != 0) return failure("fd-exec-final-alias");
    puts("fd:exec-aliases=ok");
    return 0;
}

static int fd_stdio(void) {
    int saved_input = dup(STDIN_FILENO), saved_output = dup(STDOUT_FILENO), saved_error = dup(STDERR_FILENO);
    if (saved_input != 3 || saved_output != 4 || saved_error != 5 || close(STDIN_FILENO) != 0)
        return failure("fd-stdio-save");
    char bytes[32] = {0};
    if (read_exact(saved_input, bytes, 12U) != 0 || memcmp(bytes, "stdio-input\n", 12U) != 0 ||
        read(saved_input, bytes, 1U) != 0 || write(saved_output, "fd:stdout-alias\n", 16U) != 16)
        return failure("fd-stdio-aliased-pipes");
    if (dup3(saved_error, STDOUT_FILENO, 0) != STDOUT_FILENO ||
        write(STDOUT_FILENO, "fd:stderr-alias\n", 16U) != 16 ||
        dup3(saved_output, STDOUT_FILENO, 0) != STDOUT_FILENO)
        return failure("fd-stdio-error-route");
    int file = open("fd-stdio.txt", O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (file != 0 || write(file, "file-input", 10U) != 10 || lseek(file, 0, SEEK_SET) != 0)
        return failure("fd-stdio-open-lowest-zero");
    struct stat st;
    if (fstat(STDIN_FILENO, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size != 10 ||
        (fcntl(STDIN_FILENO, F_GETFL) & O_ACCMODE) != O_RDWR ||
        read_exact(STDIN_FILENO, bytes, 10U) != 0 || memcmp(bytes, "file-input", 10U) != 0)
        return failure("fd-stdio-file-input");
    if (dup3(file, STDOUT_FILENO, 0) != STDOUT_FILENO || write(STDOUT_FILENO, "-output", 7U) != 7 ||
        lseek(file, 0, SEEK_SET) != 0 || read_exact(file, bytes, 17U) != 0 || memcmp(bytes, "file-input-output", 17U) != 0 ||
        dup3(saved_output, STDOUT_FILENO, 0) != STDOUT_FILENO || close(file) != 0 ||
        dup3(saved_input, STDIN_FILENO, 0) != STDIN_FILENO)
        return failure("fd-stdio-file-output");
    errno = 0;
    if (lseek(saved_input, 0, SEEK_SET) != -1 || errno != ESPIPE) return failure("fd-stdio-pipe-seek");
    errno = 0;
    if (write(saved_input, "x", 1U) != -1 || errno != EBADF) return failure("fd-stdio-input-access");
    errno = 0;
    if (read(saved_output, bytes, 1U) != -1 || errno != EBADF) return failure("fd-stdio-output-access");
    if (close(saved_input) != 0 || close(saved_output) != 0 || close(saved_error) != 0)
        return failure("fd-stdio-close-backups");
    puts("fd:stdio=ok");
    return 0;
}

static int fd_input_alias_loop(void) {
    int alias = dup(STDIN_FILENO);
    if (alias != 3 || close(STDIN_FILENO) != 0) return failure("fd-input-alias-prepare");
    puts("fd:alias-open");
    if (fflush(stdout) != 0) return failure("fd-input-alias-flush");
    struct timespec delay = {.tv_sec = 1, .tv_nsec = 0};
    while (nanosleep(&delay, &delay) != 0) if (errno != EINTR) return failure("fd-input-alias-delay");
    if (close(alias) != 0) return failure("fd-input-alias-final-close");
    puts("fd:alias-closed");
    if (fflush(stdout) != 0) return failure("fd-input-alias-final-flush");
    for (;;) { __asm__ volatile("nop"); }
}

static int fd_capacity(void) {
    /* All slots can hold independent files once the standard descriptors close.
     * Persist the result through fd0 because no captured stream remains open. */
    if (close(0) != 0 || close(1) != 0 || close(2) != 0) return 11;
    int files[64];
    char path[64];
    for (size_t i = 0U; i < 64U; i++) {
        if (i == 0U) memcpy(path, "fd-capacity-result.txt", sizeof("fd-capacity-result.txt"));
        else snprintf(path, sizeof(path), "fd-capacity-%02u.txt", (unsigned int)i);
        files[i] = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
        if (files[i] != (int)i) return 12;
    }
    errno = 0;
    if (open("fd-capacity-overflow.txt", O_CREAT | O_RDWR, 0600) != -1 || errno != EMFILE) return 13;
    if (close(files[42]) != 0) return 14;
    files[42] = open("fd-capacity-reused.txt", O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (files[42] != 42 || write(files[0], "fd:capacity=64\n", 15U) != 15) return 15;
    for (size_t i = 0U; i < 64U; i++) if (close(files[i]) != 0) return 16;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "selftest") == 0) return selftest(argc, argv);
    if (strcmp(argv[1], "exec-path") == 0 && argc >= 3) {
        (void)execve(argv[2], argv + 2, environ);
        return failure("exec-path-returned");
    }
    if (strcmp(argv[1], "--exec-state") == 0 || strcmp(argv[1], "--exec-state-post") == 0) return exec_state(argc, argv);
    if (strcmp(argv[1], "--exec-errors") == 0 && argc == 2) return exec_errors();
    if (strcmp(argv[1], "--exec-stdin-cloexec") == 0) return exec_standard(argc, argv, STDIN_FILENO);
    if (strcmp(argv[1], "--exec-stdout-cloexec") == 0) return exec_standard(argc, argv, STDOUT_FILENO);
    if (strcmp(argv[1], "--exec-chain") == 0) return exec_chain(argc, argv);
    if (strcmp(argv[1], "--fd-aliases") == 0 && argc == 2) return fd_aliases();
    if (strcmp(argv[1], "--fd-errors") == 0 && argc == 2) return fd_errors();
    if (strcmp(argv[1], "--fd-exec-aliases") == 0) return fd_exec_aliases(argc, argv);
    if (strcmp(argv[1], "--fd-stdio") == 0 && argc == 2) return fd_stdio();
    if (strcmp(argv[1], "--fd-stdin-alias-loop") == 0 && argc == 2) return fd_input_alias_loop();
    if (strcmp(argv[1], "--fd-capacity") == 0 && argc == 2) return fd_capacity();
    if (strcmp(argv[1], "--close-stdin-loop") == 0 && argc == 2) {
        if (close(STDIN_FILENO) != 0) return failure("close-stdin");
        if (puts("closed") == EOF || fflush(stdout) != 0) return failure("close-stdin-flush");
        /* Keep the worker alive without reading input or entering the kernel.
         * The manager must finish its feeder on EPIPE before killing us. */
        for (;;) { __asm__ volatile("nop"); }
    }
    if (strcmp(argv[1], "echo") == 0) {
        for (int index = 2; index < argc; ++index) printf("%s%s", index == 2 ? "" : " ", argv[index]);
        putchar('\n');
        return 0;
    }
    if (strcmp(argv[1], "fault") == 0 && argc == 2) {
        puts("musl:fault=start");
        if (fflush(stdout) != 0) return failure("fault-flush");
        /* Cause a synchronous CPU fault after musl established guest TLS.
         * Inline assembly prevents C undefined-behavior optimization from
         * removing or rewriting the intended null-address store. */
        __asm__ volatile("mov x9, #0\nstr xzr, [x9]" : : : "x9", "memory");
        return 1;
    }
    if (strcmp(argv[1], "sleep") == 0 && argc == 3) {
        char *end = NULL;
        errno = 0;
        long seconds = strtol(argv[2], &end, 10);
        if (errno != 0 || end == argv[2] || *end != '\0' || seconds < 0 || seconds > 60) return 2;
        puts("musl:sleep=start");
        if (fflush(stdout) != 0) return failure("sleep-flush");
        struct timespec remaining = { .tv_sec = seconds, .tv_nsec = 0 };
        while (nanosleep(&remaining, &remaining) != 0) if (errno != EINTR) return failure("nanosleep");
        puts("musl:sleep=done");
        return 0;
    }
    fputs("usage: musl-smoke [selftest [value] | echo [args...] | sleep seconds | fault | --close-stdin-loop]\n", stderr);
    return 2;
}
