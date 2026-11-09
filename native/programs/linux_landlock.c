#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(test) do { if (!(test)) { fprintf(stderr, "line %d: %s (errno=%d)\n", __LINE__, #test, errno); exit(1); } } while (0)

static int ruleset(unsigned long long rights) {
    struct landlock_ruleset_attr attr = {.handled_access_fs = rights};
    return (int)syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr.handled_access_fs), 0);
}

static void grant(int rules, const char *path, unsigned long long rights) {
    int fd = open(path, O_PATH | O_CLOEXEC);
    CHECK(fd >= 0);
    struct landlock_path_beneath_attr rule = {.allowed_access = rights, .parent_fd = fd};
    CHECK(syscall(SYS_landlock_add_rule, rules, LANDLOCK_RULE_PATH_BENEATH, &rule, 0) == 0);
    CHECK(close(fd) == 0);
}

static void restrict_and_close(int rules) {
    CHECK(syscall(SYS_landlock_restrict_self, rules, 0) == 0);
    CHECK(close(rules) == 0);
}

static void denied(const char *path, int flags) {
    CHECK(open(path, flags, 0600) == -1 && errno == EACCES);
}

static void check_child(void) {
    CHECK(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1);
    denied("../protected/sentinel", O_WRONLY | O_TRUNC);
    denied("link", O_RDWR);
    int fd = open("from-child", O_WRONLY | O_CREAT, 0600);
    CHECK(fd >= 0 && write(fd, "ok", 2) == 2 && close(fd) == 0);
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "child")) { check_child(); return 0; }
    if (argc == 2 && !strcmp(argv[1], "identity")) { puts("sealed-image-ok"); return 0; }
    long abi = syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    CHECK(abi >= 3);
    CHECK(ruleset(1ULL << 60) == -1 && errno == EINVAL);
    const unsigned long long effects = LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_MAKE_REG |
        LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_TRUNCATE |
        LANDLOCK_ACCESS_FS_REFER;
    int rules = ruleset(effects);
    CHECK(rules >= 0 && fcntl(rules, F_GETFD) == FD_CLOEXEC);
    int saved = open("../protected/sentinel", O_RDWR);
    CHECK(saved >= 0);
    CHECK(symlink("../protected/sentinel", "link") == 0);
    grant(rules, ".", effects);
    CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    int alias = dup(rules);
    CHECK(alias >= 0 && close(rules) == 0);
    restrict_and_close(alias);
    CHECK(ftruncate(saved, 9) == 0 && close(saved) == 0);
    denied("../protected/created", O_WRONLY | O_CREAT);
    denied("link", O_RDONLY | O_TRUNC);
    CHECK(execl("../protected/probe", "probe", "identity", (char *)NULL) == -1 && errno == EACCES);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        check_child();
        execl("./probe", "probe", "child", (char *)NULL);
        _exit(110);
    }
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(rename("from-child", "../protected/moved") == -1 && (errno == EACCES || errno == EXDEV));
    rules = ruleset(effects);
    CHECK(rules >= 0);
    grant(rules, "subdir", effects);
    restrict_and_close(rules);
    denied("from-child", O_WRONLY);
    int inside = open("subdir/nested", O_CREAT | O_WRONLY, 0600);
    CHECK(inside >= 0 && close(inside) == 0);
    puts("landlock-fs-fork-exec-ok");
    return 0;
}
