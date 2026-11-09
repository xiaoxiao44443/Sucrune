/* Parser/builtin regression harness. Fake Linux syscalls exercise short I/O;
 * this never executes the guest on the host and is not Android validation. */
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#define SUCRUNE_SHELL_HOST_TEST 1
#include "shell.c"

struct fake_file { char path[PATH_LIMIT]; char data[SCRIPT_LIMIT + 1U]; size_t size; int directory; };
/* Descriptor flags belong to the FD; offsets and status flags belong to the
 * shared open description. Standard captures are real entries in this model. */
enum fake_kind { FAKE_FILE, FAKE_INPUT, FAKE_OUTPUT, FAKE_ERROR };
struct fake_description { int kind, file, references; size_t position; intptr_t flags; };
struct fake_fd { int object, flags; };
static struct fake_file files[16];
static struct fake_fd descriptors[64];
static struct fake_description descriptions[64];
static char captured_out[SCRIPT_LIMIT + 1U], captured_err[8192];
static size_t out_size, err_size;
static const char *initial_input;
static int initial_closed_mask, initial_cloexec_mask;
static int exec_open_descriptors;
static int exec_stdin_object, exec_stdout_object;
static char fake_cwd[PATH_LIMIT];
static int unknown_syscall;
static jmp_buf replaced_image;
static int exec_calls, exec_succeeded;
static char exec_path[PATH_LIMIT], exec_cwd[PATH_LIMIT];
static char exec_arguments[ARG_LIMIT][WORD_LIMIT];
static char exec_variables[VARIABLE_LIMIT][NAME_LIMIT + VALUE_LIMIT];
static size_t exec_argc, exec_envc;

static int find_file(const char *path) {
    for (int i = 0; i < 16; ++i) if (files[i].path[0] != 0 && equal(files[i].path, path)) return i;
    return -1;
}
static int new_file(const char *path, int directory) {
    for (int i = 0; i < 16; ++i) if (files[i].path[0] == 0) {
        (void)copy(files[i].path, sizeof(files[i].path), path);
        files[i].directory = directory; files[i].size = 0U; return i;
    }
    return -1;
}
static int valid_fd(intptr_t fd) { return fd >= 0 && fd < 64 && descriptors[fd].object >= 0; }
static int allocate_fd(int minimum) {
    for (int fd = minimum; fd < 64; ++fd) if (descriptors[fd].object < 0) return fd;
    return -1;
}
static int close_descriptor(intptr_t fd) {
    if (!valid_fd(fd)) return -9;
    --descriptions[descriptors[fd].object].references;
    descriptors[fd].object = -1; descriptors[fd].flags = 0;
    return 0;
}
static int new_description(int kind, int file, intptr_t flags) {
    for (int index = 0; index < 64; ++index) if (descriptions[index].references == 0) {
        descriptions[index].kind = kind; descriptions[index].file = file;
        descriptions[index].position = 0; descriptions[index].flags = flags;
        descriptions[index].references = 1;
        return index;
    }
    return -1;
}
static int duplicate_descriptor(intptr_t source, int target, int flags) {
    if (!valid_fd(source) || target < 0 || target >= 64) return -9;
    if (valid_fd(target)) (void)close_descriptor(target);
    descriptors[target].object = descriptors[source].object;
    descriptors[target].flags = flags;
    ++descriptions[descriptors[target].object].references;
    return target;
}
intptr_t sucrune_shell_test_syscall(intptr_t number, intptr_t a, intptr_t b,
                                  intptr_t c, intptr_t d, intptr_t e, intptr_t f) {
    (void)e; (void)f;
    if (number == 23 || number == 24 || number == 25) {
        if (!valid_fd(a)) return -9;
        if (number == 24) {
            if (a == b || (c & ~((intptr_t)524288)) != 0) return -22;
            return duplicate_descriptor(a, (int)b, c != 0 ? 1 : 0);
        }
        if (number == 25 && b == F_GETFD) return descriptors[a].flags;
        if (number == 25 && b == F_SETFD) {
            if ((c & ~FD_CLOEXEC) != 0) return -22;
            descriptors[a].flags = (int)c; return 0;
        }
        if (number == 25 && b == 3) return descriptions[descriptors[a].object].flags;
        if (number == 23 || b == 0 || b == F_DUPFD_CLOEXEC) {
            intptr_t minimum = number == 23 ? 0 : c;
            if (minimum < 0 || minimum >= 64) return -22;
            int target = allocate_fd((int)minimum);
            if (target < 0) return -24;
            return duplicate_descriptor(a, target, number == 25 && b == F_DUPFD_CLOEXEC ? 1 : 0);
        }
        return -22;
    }
    if (number == 17) {
        size_t size = length(fake_cwd) + 1U;
        if ((size_t)b < size) return -34;
        (void)memcpy((void *)(uintptr_t)a, fake_cwd, size); return (intptr_t)size;
    }
    if (number == 56 || number == 34 || number == 35 || number == 38 || number == 49) {
        const char *input = (const char *)(uintptr_t)(number == 49 ? a : b);
        char path[PATH_LIMIT];
        if (canonical_path(input, path) != 0) return -1;
        int file = find_file(path);
        if (number == 49) {
            if (file < 0 || files[file].directory == 0) return -20;
            (void)copy(fake_cwd, sizeof(fake_cwd), path); return 0;
        }
        if (number == 34) return file >= 0 ? -17 : (new_file(path, 1) < 0 ? -28 : 0);
        if (number == 35) {
            if (file < 0) return -2;
            if (files[file].directory != 0) return -21;
            files[file].path[0] = 0; return 0;
        }
        if (number == 38) {
            if (file < 0) return -2;
            char target[PATH_LIMIT];
            if (canonical_path((const char *)(uintptr_t)d, target) != 0) return -1;
            int other = find_file(target);
            if (other >= 0 && other != file) files[other].path[0] = 0;
            (void)copy(files[file].path, sizeof(files[file].path), target); return 0;
        }
        if (file < 0 && (c & O_CREAT) != 0) file = new_file(path, 0);
        if (file < 0) return -2;
        if ((c & O_DIRECTORY) != 0 && files[file].directory == 0) return -20;
        if ((c & O_WRONLY) != 0 && files[file].directory != 0) return -21;
        if ((c & O_TRUNC) != 0) files[file].size = 0U;
        int fd = allocate_fd(0);
        if (fd < 0) return -24;
        int object = new_description(FAKE_FILE, file, c & ~((intptr_t)524288));
        if (object < 0) return -24;
        descriptors[fd].object = object;
        descriptors[fd].flags = (c & 524288) != 0 ? 1 : 0;
        return fd;
    }
    if (number == 64) {
        const char *data = (const char *)(uintptr_t)b;
        size_t count = (size_t)c > 7U ? 7U : (size_t)c; /* Deliberate short writes. */
        if (!valid_fd(a)) return -9;
        struct fake_description *fd = &descriptions[descriptors[a].object];
        if ((fd->flags & 3) == 0) return -9;
        if (fd->kind == FAKE_OUTPUT || fd->kind == FAKE_ERROR) {
            char *destination = fd->kind == FAKE_OUTPUT ? captured_out : captured_err;
            size_t *used = fd->kind == FAKE_OUTPUT ? &out_size : &err_size;
            size_t capacity = fd->kind == FAKE_OUTPUT ? sizeof(captured_out) : sizeof(captured_err);
            if (count >= capacity - *used) return -28;
            (void)memcpy(destination + *used, data, count); *used += count; destination[*used] = 0;
            return (intptr_t)count;
        }
        if (fd->kind != FAKE_FILE) return -9;
        struct fake_file *file = &files[fd->file];
        if ((fd->flags & O_APPEND) != 0) fd->position = file->size;
        if (count > SCRIPT_LIMIT - fd->position) return -28;
        (void)memcpy(file->data + fd->position, data, count); fd->position += count;
        if (fd->position > file->size) file->size = fd->position;
        file->data[file->size] = 0; return (intptr_t)count;
    }
    if (number == 63) {
        if (!valid_fd(a)) return -9;
        struct fake_description *fd = &descriptions[descriptors[a].object];
        if ((fd->flags & 3) == O_WRONLY) return -9;
        if (fd->kind != FAKE_FILE && fd->kind != FAKE_INPUT) return -9;
        struct fake_file *file = fd->kind == FAKE_FILE ? &files[fd->file] : NULL;
        if (file != NULL && file->directory != 0) return -21;
        const char *data = file != NULL ? file->data : initial_input;
        size_t size = file != NULL ? file->size : length(initial_input);
        size_t count = (size_t)c > 5U ? 5U : (size_t)c; /* Deliberate short reads. */
        if (count > size - fd->position) count = size - fd->position;
        (void)memcpy((void *)(uintptr_t)b, data + fd->position, count); fd->position += count;
        return (intptr_t)count;
    }
    if (number == 57) {
        return close_descriptor(a);
    }
    if (number == 61) {
        if (!valid_fd(a)) return -9;
        struct fake_description *fd = &descriptions[descriptors[a].object];
        if (fd->position != 0U) return 0;
        if (c < 32) return -22;
        unsigned char entry[32] = {0}; entry[16] = 32U; entry[18] = 8U;
        (void)copy((char *)entry + 19U, 13U, "sample");
        (void)memcpy((void *)(uintptr_t)b, entry, sizeof(entry));
        fd->position = 1U; return 32;
    }
    if (number == 101) return 0;
    if (number == 221) {
        const char *path = (const char *)(uintptr_t)a;
        char *const *args = (char *const *)(uintptr_t)b;
        char *const *env = (char *const *)(uintptr_t)c;
        ++exec_calls;
        if (equal(path, "/denied")) return -13;
        if (!equal(path, "/bin/lua") && !equal(path, "/bin/musl-smoke") &&
            !equal(path, "/bin/sucrune-sh")) return -2;
        if (!copy(exec_path, sizeof(exec_path), path) ||
            !copy(exec_cwd, sizeof(exec_cwd), fake_cwd)) return -7;
        while (args[exec_argc] != NULL) {
            if (exec_argc >= ARG_LIMIT ||
                !copy(exec_arguments[exec_argc], WORD_LIMIT, args[exec_argc])) return -7;
            ++exec_argc;
        }
        while (env[exec_envc] != NULL) {
            if (exec_envc >= VARIABLE_LIMIT ||
                !copy(exec_variables[exec_envc], NAME_LIMIT + VALUE_LIMIT, env[exec_envc])) return -7;
            ++exec_envc;
        }
        /* Model only the syscall's non-returning control transfer. No target
         * ELF, interpreter, or host subprocess executes in this mock test. */
        for (int fd = 0; fd < 64; ++fd)
            if (valid_fd(fd) && (descriptors[fd].flags & FD_CLOEXEC) != 0) (void)close_descriptor(fd);
        exec_open_descriptors = 0;
        for (int fd = 0; fd < 64; ++fd) if (valid_fd(fd)) ++exec_open_descriptors;
        exec_stdin_object = valid_fd(0) ? descriptors[0].object : -1;
        exec_stdout_object = valid_fd(1) ? descriptors[1].object : -1;
        exec_succeeded = 1;
        longjmp(replaced_image, 1);
    }
    unknown_syscall = 1; return -38;
}
static int run_case_with_env(const char *label, const char *script, int expected,
                            const char *output, int stderr_expected, char **environment) {
    (void)memset(frames, 0, sizeof(frames)); (void)memset(variables, 0, sizeof(variables));
    (void)memset(files, 0, sizeof(files)); (void)memset(descriptors, 0, sizeof(descriptors));
    (void)memset(descriptions, 0, sizeof(descriptions));
    for (int fd = 0; fd < 64; ++fd) descriptors[fd].object = -1;
    if (initial_input == NULL) initial_input = "";
    for (int fd = 0; fd < 3; ++fd) if ((initial_closed_mask & (1 << fd)) == 0) {
        descriptors[fd].object = new_description(fd == 0 ? FAKE_INPUT : fd == 1 ? FAKE_OUTPUT : FAKE_ERROR, -1, fd == 0 ? 0 : O_WRONLY);
        descriptors[fd].flags = (initial_cloexec_mask & (1 << fd)) != 0 ? 1 : 0;
    }
    last_status = 0; exit_requested = 0; out_size = 0U; err_size = 0U; unknown_syscall = 0;
    exec_calls = 0; exec_succeeded = 0; exec_argc = 0U; exec_envc = 0U;
    exec_open_descriptors = 0; exec_stdin_object = -1; exec_stdout_object = -1;
    exec_path[0] = 0; exec_cwd[0] = 0;
    captured_out[0] = 0; captured_err[0] = 0; (void)copy(fake_cwd, sizeof(fake_cwd), "/");
    (void)new_file("/", 1);
    char name[] = "sh", flag[] = "-c"; char *args[] = {name, flag, (char *)script, NULL};
    int result = setjmp(replaced_image) == 0 ? shell_main(3, args, environment) : 73;
    int passed = result == expected && equal(captured_out, output) && unknown_syscall == 0 &&
                 (stderr_expected != 0 ? err_size != 0U : err_size == 0U);
    for (int fd = 3; fd < 64; ++fd) if (valid_fd(fd)) passed = 0;
    if (exec_succeeded == 0) for (int fd = 0; fd < 3; ++fd) {
        if ((initial_closed_mask & (1 << fd)) != 0) { if (valid_fd(fd)) passed = 0; }
        else if (!valid_fd(fd) || descriptions[descriptors[fd].object].kind != (fd == 0 ? FAKE_INPUT : fd == 1 ? FAKE_OUTPUT : FAKE_ERROR) ||
                 descriptors[fd].flags != ((initial_cloexec_mask & (1 << fd)) != 0 ? 1 : 0)) passed = 0;
    }
    for (int object = 0; object < 64; ++object) {
        int references = 0;
        for (int fd = 0; fd < 64; ++fd) if (descriptors[fd].object == object) ++references;
        if (references != descriptions[object].references) passed = 0;
    }
    if (passed == 0) printf("FAIL %s: code=%d stdout=[%s] stderr=[%s]\n", label, result, captured_out, captured_err);
    initial_input = NULL; initial_closed_mask = 0; initial_cloexec_mask = 0;
    return passed;
}
static int run_case(const char *label, const char *script, int expected, const char *output, int stderr_expected) {
    return run_case_with_env(label, script, expected, output, stderr_expected, NULL);
}
static int captured_environment(const char *entry) {
    for (size_t i = 0U; i < exec_envc; ++i) if (equal(exec_variables[i], entry)) return 1;
    return 0;
}
int main(void) {
    int passed = 0, expected = 0;
#define CASE(label, script, status, output, errors) do { ++expected; passed += run_case(label, script, status, output, errors); } while (0)
    CASE("quoting", "echo 'a b' \"c;d\" x\\ y", 0, "a b c;d x y\n", 0);
    CASE("variables", "A=hello B=$A; echo \"$B\" '${A}' ${A}; false; echo $?", 0, "hello ${A} hello\n1\n", 0);
    CASE("and-or", "false && echo bad || echo good; true || echo bad && echo yes", 0, "good\nyes\n", 0);
    CASE("comments", "# one\necho first # two\necho a#b", 0, "first\na#b\n", 0);
    CASE("printf", "printf '%s:%s\\n' one two three four; printf '%%\\tend\\n'", 0, "one:two\nthree:four\n%\tend\n", 0);
    CASE("redirect-copy", "printf '%s\\n' alpha > a; echo beta >> a; cp a b; mv b c; cat c; rm a c; rm -f absent", 0, "alpha\nbeta\n", 0);
    CASE("directories", "mkdir -p one/two; cd one; pwd; cd /; touch empty; cat empty; ls", 0, "/one\nsample\n", 0);
    CASE("source", "X=outer; printf '%s\\n' 'X=inner' 'echo $X' > script; source script; echo $X", 0, "inner\ninner\n", 0);
    CASE("nested-isolation", "X=outer; sh -c 'X=inner; mkdir sub; cd sub; echo $X; pwd'; echo $X; pwd", 0, "inner\n/sub\nouter\n/\n", 0);
    CASE("nested-redirect", "sh -c 'echo child' > out; cat out", 0, "child\n", 0);
    CASE("nested-exit", "sh -c 'exit 2' || echo recovered; echo alive", 0, "recovered\nalive\n", 0);
    CASE("script-file", "printf '%s\\n' 'echo script' 'exit 7' > file; sh file; echo $?", 0, "script\n7\n", 0);
    CASE("exit", "echo before; exit 19; echo after", 19, "before\n", 0);
    CASE("sleep", "sleep 0; echo resumed", 0, "resumed\n", 0);
    CASE("pipe-rejected", "echo no | cat", 2, "", 1);
    CASE("background-rejected", "echo no &", 2, "", 1);
    CASE("substitution-rejected", "echo $(pwd)", 2, "", 1);
    CASE("quote-rejected", "echo 'unterminated", 2, "", 1);
    CASE("loop-rejected", "for x in a; do echo bad; done", 2, "", 1);
    CASE("glob-rejected", "echo *", 2, "", 1);
    CASE("fd-redirection-rejected", "echo no 2> errors", 2, "", 1);
    CASE("missing-connector-command", "echo before &&", 2, "before\n", 1);
    CASE("unknown-command", "nonexistent", 127, "", 1);
    CASE("cp-self", "echo retained > a; cp a ./a; cat a", 0, "retained\n", 1);
    CASE("temporary-assignment-rejected", "A=one echo no", 2, "", 1);
    CASE("positional-rejected", "echo $1", 2, "", 1);
    CASE("continuation", "echo one\\\n two", 0, "one two\n", 0);
    CASE("continuation-space", "echo one \\\n two", 0, "one two\n", 0);
    CASE("redirect-comment", "echo no > # comment", 2, "", 1);
    CASE("bad-option-no-side-effects", "mkdir -z; touch -c; rm -r", 2, "", 1);
    CASE("directory-copy", "echo retained > target; cp / target; cat target", 0, "retained\n", 1);
    CASE("exec-missing-continues", "exec /missing || echo recovered; echo $?; echo alive", 0, "recovered\n0\nalive\n", 1);
    CASE("exec-missing-status", "exec /missing; echo $?", 0, "127\n", 1);
    CASE("exec-denied-status", "exec /denied; echo $?", 0, "126\n", 1);
    CASE("exec-no-path-search", "exec lua; echo $?", 0, "2\n", 1);
    CASE("exec-no-argument", "exec; echo $?", 0, "2\n", 1);
    CASE("exec-success-does-not-return", "echo before; exec /bin/lua -e 'print(1)'; echo unreachable", 73, "before\n", 0);
    CASE("exec-nested-replaces-whole-shell", "sh -c 'exec /bin/musl-smoke echo child; echo inner'; echo outer", 73, "", 0);
    CASE("exec-skipped", "false && exec /bin/lua ignored; echo alive", 0, "alive\n", 0);
    CASE("exec-source-file", "printf '%s\\n' 'exec /bin/sucrune-sh -c true' > script; source script; echo unreachable", 73, "", 0);
    ++expected;
    {
        char inherited[] = "INHERITED=parent value";
        char *environment[] = {inherited, NULL};
        int correct = run_case_with_env("exec-argv-env-cwd",
            "TOKEN='quoted value'; EMPTY=; mkdir dir; cd dir; exec /bin/lua 'script one.lua' '' \"$TOKEN\"; echo unreachable",
            73, "", 0, environment);
        correct = correct && exec_calls == 1 && exec_succeeded != 0 &&
            equal(exec_path, "/bin/lua") && equal(exec_cwd, "/dir") && exec_argc == 4U &&
            equal(exec_arguments[0], "/bin/lua") && equal(exec_arguments[1], "script one.lua") &&
            equal(exec_arguments[2], "") && equal(exec_arguments[3], "quoted value") && exec_envc == 3U &&
            captured_environment("INHERITED=parent value") && captured_environment("TOKEN=quoted value") &&
            captured_environment("EMPTY=");
        if (correct == 0) puts("FAIL exec-argv-env-cwd: syscall argument/environment snapshot differs");
        passed += correct;
    }
    ++expected;
    {
        int correct = run_case("exec-redirect-inherits-file", "echo keep > out; exec /bin/lua > out", 73, "", 0);
        int file = find_file("/out");
        correct = correct && exec_calls == 1 && file >= 0 && files[file].size == 0U &&
            exec_stdout_object >= 0 && descriptions[exec_stdout_object].file == file && exec_open_descriptors == 3;
        if (correct == 0) puts("FAIL exec-redirect-inherits-file: wrong target or leaked backup");
        passed += correct;
    }
    ++expected;
    {
        int correct = run_case("exec-redirect-creates-target", "exec /bin/lua > absent", 73, "", 0);
        correct = correct && exec_calls == 1 && find_file("/absent") >= 0 && exec_open_descriptors == 3;
        if (correct == 0) puts("FAIL exec-redirect-creates-target: missing target or leaked backup");
        passed += correct;
    }
    ++expected;
    {
        int correct = run_case("exec-inherited-redirect", "sh -c 'exec /bin/lua' > out; echo $?", 73, "", 0);
        int file = find_file("/out");
        correct = correct && exec_calls == 1 && file >= 0 && exec_stdout_object >= 0 &&
            descriptions[exec_stdout_object].file == file && exec_open_descriptors == 3;
        if (correct == 0) puts("FAIL exec-inherited-redirect: target not inherited or backup leaked");
        passed += correct;
    }
    CASE("stdin-file-cat", "printf '%s' 'input bytes' > input; cat < input; echo after", 0, "input bytesafter\n", 0);
    CASE("stdin-output-copy", "echo data > input; cat < input > output; cat output", 0, "data\n", 0);
    CASE("stdin-output-append", "echo first > out; echo second > in; cat < in >> out; cat out", 0, "first\nsecond\n", 0);
    CASE("failed-exec-restores-output", "echo keep > out; exec /missing > out || echo recovered; echo after; cat out", 0, "recovered\nafter\n", 1);
    CASE("nested-output-remapping", "sh -c 'echo one; echo inner > inner; echo two' > outer; cat outer inner; echo tail", 0, "one\ntwo\ninner\ntail\n", 0);
    CASE("source-output-remapping", "echo 'echo sourced' > script; source script > out; cat out; echo restored", 0, "sourced\nrestored\n", 0);
    CASE("input-first-failure-keeps-output", "echo old > out; cat < missing > out; cat out", 0, "old\n", 1);
    CASE("output-first-failure-truncates-output", "echo old > out; cat > out < missing; cat out; echo after", 0, "after\n", 1);
    CASE("duplicate-input-rejected", "cat < missing < another", 2, "", 1);
    CASE("heredoc-rejected", "cat << EOF", 2, "", 1);
    CASE("here-string-rejected", "cat <<< data", 2, "", 1);
    CASE("readwrite-redirection-rejected", "cat <> file", 2, "", 1);
    CASE("input-fd-redirection-rejected", "cat 0< file", 2, "", 1);
    CASE("input-fd-duplicate-rejected", "cat <&0", 2, "", 1);
    CASE("redirect-skipped-branch", "false && cat < missing > out; echo alive", 0, "alive\n", 0);
    CASE("quoted-redirection-path", "echo quoted > 'in file'; cat<'in file'>'out file'; cat 'out file'", 0, "quoted\n", 0);
    CASE("redirection-only-command", "echo x > in; < in > out; cat out; echo restored", 0, "restored\n", 0);
    CASE("dash-file-explicit-path", "echo file > ./-; cat ./-", 0, "file\n", 0);
    ++expected;
    {
        initial_input = "original\n";
        passed += run_case("cat-default-stdin", "cat", 0, "original\n", 0);
    }
    ++expected;
    {
        initial_input = "original\n";
        passed += run_case("cat-dash-shares-input-offset", "cat -; cat -- -", 0, "original\n", 0);
    }
    ++expected;
    {
        initial_input = "original\n";
        passed += run_case("failed-exec-restores-input", "echo file > in; exec /missing < in || cat", 0, "original\n", 1);
    }
    ++expected;
    {
        initial_input = "original\n";
        passed += run_case("nested-input-restoration-offset", "echo file > in; sh -c 'cat < in; cat'; cat", 0, "file\noriginal\n", 0);
    }
    ++expected;
    {
        initial_closed_mask = 1;
        passed += run_case("restore-originally-closed-stdin", "echo file > in; cat < in; echo restored", 0, "file\nrestored\n", 0);
    }
    ++expected;
    {
        initial_closed_mask = 2;
        int correct = run_case("restore-originally-closed-stdout", "echo stored > out; true", 0, "", 0);
        int file = find_file("/out");
        correct = correct && file >= 0 && equal(files[file].data, "stored\n");
        if (correct == 0) puts("FAIL restore-originally-closed-stdout");
        passed += correct;
    }
    ++expected;
    {
        initial_closed_mask = 3;
        int correct = run_case("redirect-both-originally-closed", "echo stored > in; cat < in > out; true", 0, "", 0);
        int file = find_file("/out");
        correct = correct && file >= 0 && equal(files[file].data, "stored\n");
        if (correct == 0) puts("FAIL redirect-both-originally-closed");
        passed += correct;
    }
    ++expected;
    {
        initial_cloexec_mask = 3;
        passed += run_case("restore-original-cloexec-flags", "echo file > in; cat < in > out; cat out", 0, "file\n", 0);
    }
    ++expected;
    {
        int correct = run_case("exec-both-streams-and-backups", "echo data > in; sh -c 'exec /bin/lua - < in' > out", 73, "", 0);
        int input = find_file("/in"), output = find_file("/out");
        correct = correct && exec_open_descriptors == 3 && exec_stdin_object >= 0 && exec_stdout_object >= 0 &&
            descriptions[exec_stdin_object].file == input && descriptions[exec_stdout_object].file == output;
        if (correct == 0) puts("FAIL exec-both-streams-and-backups: wrong inherited descriptions or leaked backup");
        passed += correct;
    }
    ++expected;
    {
        int correct = run_case("duplicate-output-no-side-effects", "echo keep > out; echo no > out > absent", 2, "", 1);
        int file = find_file("/out");
        correct = correct && file >= 0 && equal(files[file].data, "keep\n") && find_file("/absent") < 0;
        if (correct == 0) puts("FAIL duplicate-output-no-side-effects");
        passed += correct;
    }
    printf("Shell host regressions: %d/%d passed (mock Linux syscalls; no ARM64 execution).\n", passed, expected);
    return passed == expected ? 0 : 1;
}
