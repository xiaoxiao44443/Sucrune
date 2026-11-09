/* Sucrune's bounded, freestanding shell subset. Linux/AArch64 syscall ABI;
 * no libc, Android, host broker, or Sucrune symbol dependencies. */
#include <stddef.h>
#include <stdint.h>

#define SCRIPT_LIMIT 65536U
#define WORD_LIMIT 8192U
#define ARG_LIMIT 64U
#define DEPTH_LIMIT 4U
#define VARIABLE_LIMIT 64U
#define VALUE_LIMIT 1024U
#define NAME_LIMIT 64U
#define PATH_LIMIT 1024U
#if defined(__aarch64__) && !defined(SUCRUNE_SHELL_HOST_TEST)
#include <linux/fcntl.h>
#include <asm/unistd.h>
_Static_assert(O_DIRECTORY == 16384 && O_WRONLY == 1 && O_CREAT == 64 &&
               O_TRUNC == 512 && O_APPEND == 1024 && AT_FDCWD == -100 &&
               F_GETFD == 1 && F_SETFD == 2 && F_DUPFD_CLOEXEC == 1030 && FD_CLOEXEC == 1,
               "Linux ARM64 file ABI");
_Static_assert(__NR_read == 63 && __NR_write == 64 && __NR_openat == 56 &&
               __NR_close == 57 && __NR_getdents64 == 61 && __NR_mkdirat == 34 &&
               __NR_unlinkat == 35 && __NR_renameat == 38 && __NR_chdir == 49 &&
               __NR_getcwd == 17 && __NR_nanosleep == 101 && __NR_exit == 93 &&
               __NR_execve == 221 && __NR_dup3 == 24 && __NR_fcntl == 25,
               "Linux ARM64 syscall ABI");
#else
#define AT_FDCWD (-100L)
#define O_WRONLY 1L
#define O_CREAT 64L
#define O_TRUNC 512L
#define O_APPEND 1024L
#define O_DIRECTORY 16384L
#define F_GETFD 1L
#define F_SETFD 2L
#define F_DUPFD_CLOEXEC 1030L
#define FD_CLOEXEC 1L
#endif

#if !defined(SUCRUNE_SHELL_HOST_TEST)
void *memcpy(void *destination, const void *source, size_t size) {
    unsigned char *out = destination;
    const unsigned char *in = source;
    for (size_t i = 0U; i < size; ++i) out[i] = in[i];
    return destination;
}
void *memset(void *destination, int value, size_t size) {
    unsigned char *out = destination;
    for (size_t i = 0U; i < size; ++i) out[i] = (unsigned char)value;
    return destination;
}
#endif
static size_t length(const char *text) { size_t n = 0U; while (text[n] != 0) ++n; return n; }
static int equal(const char *a, const char *b) {
    size_t n = 0U;
    while (a[n] != 0 && a[n] == b[n]) ++n;
    return a[n] == b[n];
}
static int copy(char *out, size_t capacity, const char *in) {
    size_t n = length(in);
    if (n >= capacity) return 0;
    (void)memcpy(out, in, n + 1U);
    return 1;
}
#if defined(SUCRUNE_SHELL_HOST_TEST)
intptr_t sucrune_shell_test_syscall(intptr_t number, intptr_t a, intptr_t b,
                                  intptr_t c, intptr_t d, intptr_t e, intptr_t f);
#endif
static intptr_t call6(intptr_t number, intptr_t a, intptr_t b, intptr_t c, intptr_t d, intptr_t e, intptr_t f) {
#if defined(SUCRUNE_SHELL_HOST_TEST)
    return sucrune_shell_test_syscall(number, a, b, c, d, e, f);
#else
    register intptr_t x0 __asm__("x0") = a;
    register intptr_t x1 __asm__("x1") = b;
    register intptr_t x2 __asm__("x2") = c;
    register intptr_t x3 __asm__("x3") = d;
    register intptr_t x4 __asm__("x4") = e;
    register intptr_t x5 __asm__("x5") = f;
    register intptr_t x8 __asm__("x8") = number;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3),
                     "r"(x4), "r"(x5), "r"(x8) : "memory", "cc");
    return x0;
#endif
}
static intptr_t open_file(const char *path, intptr_t flags, intptr_t mode) {
    return call6(56, AT_FDCWD, (intptr_t)(uintptr_t)path, flags, mode, 0, 0);
}
static intptr_t close_file(intptr_t fd) { return call6(57, fd, 0, 0, 0, 0, 0); }
static intptr_t read_file(intptr_t fd, void *buffer, size_t size) {
    return call6(63, fd, (intptr_t)(uintptr_t)buffer, (intptr_t)size, 0, 0, 0);
}
static int write_all(intptr_t fd, const void *buffer, size_t size) {
    const unsigned char *bytes = buffer;
    size_t offset = 0U;
    while (offset < size) {
        intptr_t written = call6(64, fd, (intptr_t)(uintptr_t)(bytes + offset), (intptr_t)(size - offset), 0, 0, 0);
        if (written <= 0 || (uintptr_t)written > size - offset) return 0;
        offset += (size_t)written;
    }
    return 1;
}
static int text(intptr_t fd, const char *value) { return write_all(fd, value, length(value)); }
static void number_text(unsigned int value, char *out) {
    char reverse[16]; size_t n = 0U;
    do { reverse[n++] = (char)('0' + value % 10U); value /= 10U; } while (value != 0U);
    for (size_t i = 0U; i < n; ++i) out[i] = reverse[n - i - 1U];
    out[n] = 0;
}
static int error(const char *message) {
    (void)text(2, "sucrune-sh: "); (void)text(2, message); (void)text(2, "\n"); return 2;
}
static int operation_error(const char *command, const char *path, intptr_t code) {
    char digits[16]; number_text((unsigned int)(code < 0 ? -code : code), digits);
    (void)text(2, "sucrune-sh: "); (void)text(2, command);
    (void)text(2, ": "); (void)text(2, path); (void)text(2, " (errno ");
    (void)text(2, digits); (void)text(2, ")\n"); return 1;
}
static int name_start(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'; }
static int name_char(char c) { return name_start(c) || (c >= '0' && c <= '9'); }
struct variable { char name[NAME_LIMIT]; char value[VALUE_LIMIT]; };
struct word { const char *start; size_t size; };
struct frame {
    char script[SCRIPT_LIMIT + 1U];
    char expanded[WORD_LIMIT];
    struct word words[ARG_LIMIT];
    char *argv[ARG_LIMIT + 1U];
    struct variable saved_variables[VARIABLE_LIMIT];
    char saved_cwd[PATH_LIMIT];
};
static struct frame frames[DEPTH_LIMIT];
static struct variable variables[VARIABLE_LIMIT];
/* This shell has no separate export attribute: exec receives every variable.
 * Keep the environment in bounded guest storage, independent of command words. */
static char exec_environment[VARIABLE_LIMIT][NAME_LIMIT + VALUE_LIMIT];
static char *exec_envp[VARIABLE_LIMIT + 1U];
static int last_status;
static int exit_requested;
static volatile unsigned char initialized_data = 1U;

static const char *get_variable(const char *name) {
    for (size_t i = 0U; i < VARIABLE_LIMIT; ++i)
        if (variables[i].name[0] != 0 && equal(variables[i].name, name)) return variables[i].value;
    return "";
}
static int set_variable(const char *name, const char *value) {
    size_t free_slot = VARIABLE_LIMIT;
    if (!name_start(name[0]) || length(name) >= NAME_LIMIT || length(value) >= VALUE_LIMIT)
        return error("invalid or oversized variable");
    for (size_t i = 1U; name[i] != 0; ++i) if (!name_char(name[i])) return error("invalid variable name");
    for (size_t i = 0U; i < VARIABLE_LIMIT; ++i) {
        if (variables[i].name[0] == 0 && free_slot == VARIABLE_LIMIT) free_slot = i;
        if (equal(variables[i].name, name)) { free_slot = i; break; }
    }
    if (free_slot == VARIABLE_LIMIT) return error("variable limit exceeded");
    (void)copy(variables[free_slot].name, NAME_LIMIT, name);
    (void)copy(variables[free_slot].value, VALUE_LIMIT, value);
    return 0;
}
static int append_char(char *out, size_t *used, char c) {
    if (*used + 1U >= WORD_LIMIT) return 0;
    out[(*used)++] = c; return 1;
}
static int append_text(char *out, size_t *used, const char *value) {
    for (size_t i = 0U; value[i] != 0; ++i) if (!append_char(out, used, value[i])) return 0;
    return 1;
}
static int expand(const struct word *word, char *out, size_t *used, char **result) {
    *result = out + *used;
    char quote = 0;
    for (size_t i = 0U; i < word->size; ++i) {
        char c = word->start[i];
        if (c == '\'' && quote != '"') { quote = quote == '\'' ? 0 : '\''; continue; }
        if (c == '"' && quote != '\'') { quote = quote == '"' ? 0 : '"'; continue; }
        if (c == '\\' && quote != '\'') {
            char next = word->start[++i];
            if (next == '\n') continue;
            if (quote == '"' && next != '$' && next != '`' && next != '"' && next != '\\')
                if (!append_char(out, used, '\\')) return error("expanded command is too large");
            c = next;
        } else if (c == '$' && quote != '\'') {
            char name[NAME_LIMIT]; size_t n = 0U;
            if (i + 1U < word->size && word->start[i + 1U] == '?') {
                char digits[16]; number_text((unsigned int)last_status, digits); ++i;
                if (!append_text(out, used, digits)) return error("expanded command is too large");
                continue;
            }
            int braced = i + 1U < word->size && word->start[i + 1U] == '{';
            size_t cursor = i + 1U + (braced != 0 ? 1U : 0U);
            if (cursor >= word->size || !name_start(word->start[cursor])) {
                if (braced != 0 || (cursor < word->size &&
                    (word->start[cursor] == '(' || word->start[cursor] == '@' ||
                     word->start[cursor] == '*' || word->start[cursor] == '#' ||
                     word->start[cursor] == '!' || word->start[cursor] == '-' ||
                     word->start[cursor] == '$' ||
                     (word->start[cursor] >= '0' && word->start[cursor] <= '9'))))
                    return error("unsupported variable or command substitution");
                if (!append_char(out, used, '$')) return error("expanded command is too large");
                continue;
            }
            while (cursor < word->size && name_char(word->start[cursor])) {
                if (n + 1U >= sizeof(name)) return error("variable name is too large");
                name[n++] = word->start[cursor++];
            }
            name[n] = 0;
            if (braced != 0) {
                if (cursor >= word->size || word->start[cursor] != '}') return error("unsupported variable expansion");
                ++cursor;
            }
            i = cursor - 1U;
            if (!append_text(out, used, get_variable(name))) return error("expanded command is too large");
            continue;
        }
        if (!append_char(out, used, c)) return error("expanded command is too large");
    }
    if (!append_char(out, used, 0)) return error("expanded command is too large");
    return 0;
}

/* Lex a complete command before performing its side effects. Expansion is
 * delayed until execution; skipped &&/|| commands are still syntax checked. */
static int scan_word(const char *script, size_t *position, struct word *word) {
    size_t start = *position; char quote = 0;
    while (script[*position] != 0) {
        char c = script[*position];
        if (quote == 0 && (c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
                          c == ';' || c == '&' || c == '|' || c == '>' || c == '<')) break;
        if (c == '\'' && quote != '"') quote = quote == '\'' ? 0 : '\'';
        else if (c == '"' && quote != '\'') quote = quote == '"' ? 0 : '"';
        else if (c == '\\' && quote != '\'') {
            if (script[*position + 1U] == 0) return error("trailing backslash");
            *position += 2U; continue;
        } else if (quote != '\'' && (c == '`' || (c == '$' && script[*position + 1U] == '(')))
            return error("command substitution is unsupported");
        else if (quote == 0 && (c == '(' || c == ')'))
            return error("subshell syntax is unsupported");
        else if (quote == 0 && (c == '*' || c == '[' ||
                 (c == '?' && (*position == start || script[*position - 1U] != '$'))))
            return error("unquoted glob patterns are unsupported");
        else if (quote == 0 && c == '~' && *position == start)
            return error("tilde expansion is unsupported; use an explicit path");
        ++*position;
    }
    if (quote != 0) return error("unterminated quote");
    word->start = script + start; word->size = *position - start;
    return word->size == 0U ? error("expected a word") : 0;
}
struct redirection { struct word path; int target, append; };
struct command { size_t argc, redirect_count; struct redirection redirects[2]; int connector; };
static int parse_command(struct frame *frame, size_t *position, struct command *command) {
    (void)memset(command, 0, sizeof(*command));
    const char *script = frame->script;
    for (;;) {
        while (script[*position] == ' ' || script[*position] == '\t' || script[*position] == '\r') ++*position;
        if (script[*position] == '\\' && script[*position + 1U] == '\n') { *position += 2U; continue; }
        char c = script[*position];
        if (c == '#') { while (script[*position] != 0 && script[*position] != '\n') ++*position; continue; }
        if (c == 0 || c == ';' || c == '\n' || c == '&' || c == '|') {
            if (c == '&' || c == '|') {
                if (script[*position + 1U] != c) return error("pipelines and background commands are unsupported");
                command->connector = c == '&' ? 1 : 2; *position += 2U;
            } else if (c != 0) ++*position;
            if (command->argc == 0U && command->redirect_count == 0U) return error("empty command");
            return 0;
        }
        if (c == '>' || c == '<') {
            int target = c == '<' ? 0 : 1;
            for (size_t i = 0U; i < command->redirect_count; ++i)
                if (command->redirects[i].target == target)
                    return error("at most one input and one output redirection are supported");
            if (command->redirect_count == 2U) return error("redirection limit exceeded");
            struct redirection *redirect = &command->redirects[command->redirect_count++];
            redirect->target = target;
            ++*position;
            if (target == 1 && script[*position] == '>') { redirect->append = 1; ++*position; }
            if (script[*position] == '<' || script[*position] == '>' || script[*position] == '&')
                return error("here-documents and file-descriptor redirection are unsupported");
            while (script[*position] == ' ' || script[*position] == '\t') ++*position;
            if (script[*position] == '#') return error("expected a redirection path before comment");
            if (scan_word(script, position, &redirect->path) != 0) return 2;
            continue;
        }
        if (command->argc >= ARG_LIMIT) return error("argument limit exceeded");
        struct word *word = &frame->words[command->argc++];
        if (scan_word(script, position, word) != 0) return 2;
        if ((script[*position] == '>' || script[*position] == '<') && word->size > 0U) {
            int digits_only = 1;
            for (size_t i = 0U; i < word->size; ++i)
                if (word->start[i] < '0' || word->start[i] > '9') digits_only = 0;
            if (digits_only != 0) return error("file-descriptor redirection is unsupported");
        }
    }
}

static int integer(const char *value, unsigned int maximum, unsigned int *result) {
    if (value[0] == 0) return 0;
    unsigned int n = 0U;
    for (size_t i = 0U; value[i] != 0; ++i) {
        if (value[i] < '0' || value[i] > '9') return 0;
        unsigned int digit = (unsigned int)(value[i] - '0');
        if (n > maximum / 10U || (n == maximum / 10U && digit > maximum % 10U)) return 0;
        n = n * 10U + digit;
    }
    *result = n; return 1;
}
static int canonical_path(const char *path, char *out) {
    if (path[0] == 0) return operation_error("path", "empty path", -2);
    char combined[PATH_LIMIT * 2U]; size_t used = 0U;
    if (path[0] != '/') {
        intptr_t result = call6(17, (intptr_t)(uintptr_t)combined, PATH_LIMIT, 0, 0, 0, 0);
        if (result < 0) return operation_error("getcwd", "", result);
        used = length(combined);
        if (used == 0U || combined[used - 1U] != '/') combined[used++] = '/';
    }
    size_t n = length(path);
    if (used + n >= sizeof(combined)) return error("path is too long");
    (void)memcpy(combined + used, path, n + 1U);
    out[0] = '/'; used = 1U;
    size_t position = 0U;
    while (combined[position] != 0) {
        while (combined[position] == '/') ++position;
        size_t start = position;
        while (combined[position] != 0 && combined[position] != '/') ++position;
        size_t part = position - start;
        if (part == 0U || (part == 1U && combined[start] == '.')) continue;
        if (part == 2U && combined[start] == '.' && combined[start + 1U] == '.') {
            if (used == 1U) return operation_error("path", path, -1);
            while (used > 1U && out[used - 1U] != '/') --used;
            if (used > 1U) --used;
            continue;
        }
        if (used > 1U) { if (used + 1U >= PATH_LIMIT) return error("path is too long"); out[used++] = '/'; }
        if (part >= PATH_LIMIT - used) return error("path is too long");
        (void)memcpy(out + used, combined + start, part); used += part;
    }
    out[used] = 0; return 0;
}
static int make_directory(const char *path, int parents) {
    if (parents == 0) {
        intptr_t result = call6(34, AT_FDCWD, (intptr_t)(uintptr_t)path, 0755, 0, 0, 0);
        return result < 0 ? operation_error("mkdir", path, result) : 0;
    }
    char normalized[PATH_LIMIT];
    int result = canonical_path(path, normalized); if (result != 0) return result;
    for (size_t i = 1U;; ++i) {
        if (normalized[i] != '/' && normalized[i] != 0) continue;
        char separator = normalized[i]; normalized[i] = 0;
        intptr_t made = call6(34, AT_FDCWD, (intptr_t)(uintptr_t)normalized, 0755, 0, 0, 0);
        if (made == -17) {
            intptr_t fd = open_file(normalized, O_DIRECTORY, 0);
            if (fd < 0) return operation_error("mkdir", normalized, fd);
            (void)close_file(fd);
        } else if (made < 0) return operation_error("mkdir", normalized, made);
        normalized[i] = separator;
        if (separator == 0) break;
    }
    return 0;
}
static int cat_descriptor(intptr_t fd, const char *path, intptr_t output) {
    unsigned char buffer[4096]; int result = 0;
    for (;;) {
        intptr_t got = read_file(fd, buffer, sizeof(buffer));
        if (got < 0) { result = operation_error("cat", path, got); break; }
        if (got == 0) break;
        if ((uintptr_t)got > sizeof(buffer) || !write_all(output, buffer, (size_t)got)) { result = 1; break; }
    }
    return result;
}
static int cat_file(const char *path, intptr_t output) {
    if (equal(path, "-")) return cat_descriptor(0, "stdin", output);
    intptr_t fd = open_file(path, 0, 0);
    if (fd < 0) return operation_error("cat", path, fd);
    int result = cat_descriptor(fd, path, output);
    intptr_t closed = close_file(fd);
    return result != 0 ? result : (closed < 0 ? operation_error("close", path, closed) : 0);
}
static int copy_file(const char *source, const char *destination) {
    char from[PATH_LIMIT], to[PATH_LIMIT];
    int result = canonical_path(source, from); if (result != 0) return result;
    result = canonical_path(destination, to); if (result != 0) return result;
    if (equal(from, to)) return operation_error("cp", "source and destination are the same path", -22);
    intptr_t directory = open_file(from, O_DIRECTORY, 0);
    if (directory >= 0) { (void)close_file(directory); return operation_error("cp", source, -21); }
    if (directory != -20) return operation_error("cp", source, directory);
    intptr_t input = open_file(from, 0, 0);
    if (input < 0) return operation_error("cp", source, input);
    intptr_t output = open_file(to, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (output < 0) { (void)close_file(input); return operation_error("cp", destination, output); }
    unsigned char buffer[4096];
    for (;;) {
        intptr_t got = read_file(input, buffer, sizeof(buffer));
        if (got < 0) { result = operation_error("cp", source, got); break; }
        if (got == 0) break;
        if ((uintptr_t)got > sizeof(buffer) || !write_all(output, buffer, (size_t)got)) { result = 1; break; }
    }
    intptr_t closed_input = close_file(input), closed_output = close_file(output);
    return result != 0 ? result : (closed_input < 0 || closed_output < 0 ? 1 : 0);
}
static int list_directory(const char *path, int all, intptr_t output) {
    intptr_t fd = open_file(path, O_DIRECTORY, 0);
    if (fd < 0) return operation_error("ls", path, fd);
    unsigned char buffer[4096]; int result = 0;
    for (;;) {
        intptr_t got = call6(61, fd, (intptr_t)(uintptr_t)buffer, sizeof(buffer), 0, 0, 0);
        if (got < 0) { result = operation_error("ls", path, got); break; }
        if (got == 0) break;
        if ((uintptr_t)got > sizeof(buffer)) { result = 1; break; }
        size_t offset = 0U;
        while (offset < (size_t)got) {
            if ((size_t)got - offset < 20U) { result = 1; break; }
            size_t record = (size_t)buffer[offset + 16U] | ((size_t)buffer[offset + 17U] << 8U);
            if (record < 20U || record > (size_t)got - offset) { result = 1; break; }
            char *name = (char *)(buffer + offset + 19U); size_t n = 0U;
            while (n < record - 19U && name[n] != 0) ++n;
            if (n == record - 19U) { result = 1; break; }
            if ((all != 0 || name[0] != '.') && !equal(name, ".") && !equal(name, ".."))
                if (!write_all(output, name, n) || !text(output, "\n")) { result = 1; break; }
            offset += record;
        }
        if (result != 0) break;
    }
    intptr_t closed = close_file(fd);
    return result != 0 ? result : (closed < 0 ? 1 : 0);
}
static int printf_command(size_t argc, char **argv, intptr_t output) {
    if (argc < 2U) return error("printf requires a format");
    const char *format = argv[1]; int has_substitution = 0;
    for (size_t i = 0U; format[i] != 0; ++i) {
        if (format[i] == '%') {
            ++i; if (format[i] != '%' && format[i] != 's') return error("printf supports only %s and %%");
            if (format[i] == 's') has_substitution = 1;
        } else if (format[i] == '\\') {
            ++i; if (format[i] != 'n' && format[i] != 'r' && format[i] != 't' && format[i] != '\\')
                return error("printf supports only backslash n, r, t and backslash");
        }
    }
    size_t argument = 2U;
    do {
        for (size_t i = 0U; format[i] != 0; ++i) {
            char c = format[i];
            if (c == '%') {
                c = format[++i];
                if (c == 's') { if (argument < argc && !text(output, argv[argument++])) return 1; continue; }
            } else if (c == '\\') {
                c = format[++i];
                if (c == 'n') c = '\n'; else if (c == 'r') c = '\r'; else if (c == 't') c = '\t';
            }
            if (!write_all(output, &c, 1U)) return 1;
        }
    } while (has_substitution != 0 && argument < argc);
    return 0;
}

static int run_script(unsigned int depth);
static int replace_program(size_t argc, char **argv) {
    if (argc < 2U || argv[1][0] != '/')
        return error("exec requires an absolute bundled program path; PATH search is unsupported");
    size_t count = 0U;
    for (size_t i = 0U; i < VARIABLE_LIMIT; ++i) {
        if (variables[i].name[0] == 0) continue;
        size_t name_size = length(variables[i].name);
        size_t value_size = length(variables[i].value);
        (void)memcpy(exec_environment[count], variables[i].name, name_size);
        exec_environment[count][name_size] = '=';
        (void)memcpy(exec_environment[count] + name_size + 1U,
                     variables[i].value, value_size + 1U);
        exec_envp[count] = exec_environment[count];
        ++count;
    }
    exec_envp[count] = NULL;
    intptr_t result = call6(221, (intptr_t)(uintptr_t)argv[1],
                           (intptr_t)(uintptr_t)&argv[1],
                           (intptr_t)(uintptr_t)exec_envp, 0, 0, 0);
    /* A successful execve never returns, even from a nested sh/source frame.
     * Failed exec leaves the current script alive, including its cwd/variables. */
    (void)operation_error("exec", argv[1], result);
    return result == -2 ? 127 : 126;
}
static int run_nested(unsigned int depth, size_t argc, char **argv, int source) {
    if (depth + 1U >= DEPTH_LIMIT) return error("script recursion limit exceeded");
    struct frame *child = &frames[depth + 1U];
    const char *path = NULL;
    if (source == 0 && argc == 3U && equal(argv[1], "-c")) {
        if (!copy(child->script, sizeof(child->script), argv[2])) return error("script exceeds 64 KiB");
    } else if (argc == 2U) {
        path = argv[1];
        if (path[0] == '-') return error("unsupported sh/source option; prefix dash-named files with ./");
    }
    else return error("use sh -c SCRIPT, sh FILE, or source FILE; positional parameters are unsupported");
    if (path != NULL) {
        intptr_t fd = open_file(path, 0, 0);
        if (fd < 0) return operation_error(source != 0 ? "source" : "sh", path, fd);
        size_t used = 0U;
        for (;;) {
            size_t capacity = sizeof(child->script) - used;
            intptr_t got = read_file(fd, child->script + used, capacity);
            if (got < 0) { (void)close_file(fd); return operation_error("read script", path, got); }
            if (got == 0) break;
            if ((uintptr_t)got > capacity || (size_t)got > SCRIPT_LIMIT - used) {
                (void)close_file(fd); return error("script exceeds 64 KiB");
            }
            for (size_t i = 0U; i < (size_t)got; ++i)
                if (child->script[used + i] == 0) { (void)close_file(fd); return error("NUL bytes in scripts are unsupported"); }
            used += (size_t)got;
        }
        child->script[used] = 0;
        intptr_t closed = close_file(fd); if (closed < 0) return operation_error("close script", path, closed);
    }
    if (source != 0) return run_script(depth + 1U);
    (void)memcpy(child->saved_variables, variables, sizeof(variables));
    intptr_t cwd = call6(17, (intptr_t)(uintptr_t)child->saved_cwd, sizeof(child->saved_cwd), 0, 0, 0, 0);
    if (cwd < 0) return operation_error("getcwd", "", cwd);
    int saved_exit = exit_requested;
    exit_requested = 0;
    int result = run_script(depth + 1U);
    exit_requested = saved_exit;
    (void)memcpy(variables, child->saved_variables, sizeof(variables));
    intptr_t restored = call6(49, (intptr_t)(uintptr_t)child->saved_cwd, 0, 0, 0, 0, 0);
    return restored < 0 ? operation_error("restore cwd", child->saved_cwd, restored) : result;
}
static int builtin(unsigned int depth, size_t argc, char **argv) {
    const intptr_t output = 1;
    const char *command = argv[0];
    if (equal(command, "echo")) {
        size_t first = 1U; int newline = 1;
        if (first < argc && equal(argv[first], "-n")) { newline = 0; ++first; }
        if (first < argc && (equal(argv[first], "-e") || equal(argv[first], "-E"))) return error("echo supports only -n; use printf for escapes");
        for (size_t i = first; i < argc; ++i) {
            if (i > first && !text(output, " ")) return 1;
            if (!text(output, argv[i])) return 1;
        }
        return newline != 0 && !text(output, "\n") ? 1 : 0;
    }
    if (equal(command, "printf")) return printf_command(argc, argv, output);
    if (equal(command, "exec")) return replace_program(argc, argv);
    if (equal(command, "true")) return 0;
    if (equal(command, "false")) return 1;
    if (equal(command, "exit")) {
        unsigned int value = (unsigned int)last_status;
        if (argc > 2U || (argc == 2U && !integer(argv[1], 255U, &value))) return error("exit expects a code from 0 to 255");
        exit_requested = 1; return (int)value;
    }
    if (equal(command, "pwd")) {
        if (argc != 1U) return error("pwd takes no options");
        char path[PATH_LIMIT]; intptr_t result = call6(17, (intptr_t)(uintptr_t)path, sizeof(path), 0, 0, 0, 0);
        return result < 0 ? operation_error("pwd", "", result) : (!text(output, path) || !text(output, "\n") ? 1 : 0);
    }
    if (equal(command, "cd")) {
        if (argc != 2U) return error("cd requires one explicit path");
        intptr_t result = call6(49, (intptr_t)(uintptr_t)argv[1], 0, 0, 0, 0, 0);
        return result < 0 ? operation_error("cd", argv[1], result) : 0;
    }
    if (equal(command, "cat")) {
        size_t first = 1U; int literal = first < argc && equal(argv[first], "--");
        if (literal != 0) ++first;
        if (first == argc) return cat_descriptor(0, "stdin", output);
        for (size_t i = first; i < argc; ++i)
            if (literal == 0 && argv[i][0] == '-' && !equal(argv[i], "-")) return error("cat options are unsupported");
        int result = 0;
        for (size_t i = first; i < argc; ++i) { int one = cat_file(argv[i], output); if (one != 0) result = one; }
        return result;
    }
    if (equal(command, "ls")) {
        size_t first = 1U; int all = 0;
        if (first < argc && equal(argv[first], "-a")) { all = 1; ++first; }
        if (argc - first > 1U || (first < argc && argv[first][0] == '-')) return error("ls supports only -a and one directory");
        return list_directory(first < argc ? argv[first] : ".", all, output);
    }
    if (equal(command, "mkdir")) {
        size_t first = 1U; int parents = 0;
        if (first < argc && equal(argv[first], "-p")) { parents = 1; ++first; }
        int literal = first < argc && equal(argv[first], "--"); if (literal != 0) ++first;
        if (first == argc) return error("mkdir requires paths");
        for (size_t i = first; i < argc; ++i)
            if (literal == 0 && argv[i][0] == '-') return error("mkdir supports only -p");
        int result = 0;
        for (size_t i = first; i < argc; ++i) { int one = make_directory(argv[i], parents); if (one != 0) result = one; }
        return result;
    }
    if (equal(command, "touch")) {
        size_t first = 1U; int literal = first < argc && equal(argv[first], "--"); if (literal != 0) ++first;
        if (first == argc) return error("touch requires paths");
        for (size_t i = first; i < argc; ++i)
            if (literal == 0 && argv[i][0] == '-') return error("touch options are unsupported");
        int result = 0;
        for (size_t i = first; i < argc; ++i) {
            intptr_t fd = open_file(argv[i], O_WRONLY | O_CREAT, 0644);
            if (fd < 0) result = operation_error("touch", argv[i], fd);
            else { intptr_t closed = close_file(fd); if (closed < 0) result = operation_error("touch", argv[i], closed); }
        }
        return result;
    }
    if (equal(command, "rm")) {
        size_t first = 1U; int force = 0;
        if (first < argc && equal(argv[first], "-f")) { force = 1; ++first; }
        int literal = first < argc && equal(argv[first], "--"); if (literal != 0) ++first;
        if (first == argc) return force != 0 ? 0 : error("rm requires file paths");
        for (size_t i = first; i < argc; ++i)
            if (literal == 0 && argv[i][0] == '-') return error("rm supports only -f; recursive removal is unsupported");
        int result = 0;
        for (size_t i = first; i < argc; ++i) {
            intptr_t removed = call6(35, AT_FDCWD, (intptr_t)(uintptr_t)argv[i], 0, 0, 0, 0);
            if (removed < 0 && !(force != 0 && removed == -2)) result = operation_error("rm", argv[i], removed);
        }
        return result;
    }
    if (equal(command, "cp")) {
        if (argc != 3U) return error("cp requires source and destination file paths");
        return copy_file(argv[1], argv[2]);
    }
    if (equal(command, "mv")) {
        if (argc != 3U) return error("mv requires source and destination paths");
        intptr_t result = call6(38, AT_FDCWD, (intptr_t)(uintptr_t)argv[1], AT_FDCWD, (intptr_t)(uintptr_t)argv[2], 0, 0);
        return result < 0 ? operation_error("mv", argv[1], result) : 0;
    }
    if (equal(command, "sleep")) {
        unsigned int seconds;
        if (argc != 2U || !integer(argv[1], 60U, &seconds)) return error("sleep requires integer seconds from 0 to 60");
        struct { intptr_t seconds; intptr_t nanoseconds; } duration = {(intptr_t)seconds, 0};
        intptr_t result = call6(101, (intptr_t)(uintptr_t)&duration, 0, 0, 0, 0, 0);
        return result < 0 ? operation_error("sleep", argv[1], result) : 0;
    }
    if (equal(command, "sh")) return run_nested(depth, argc, argv, 0);
    if (equal(command, "source") || equal(command, ".")) return run_nested(depth, argc, argv, 1);
    if (equal(command, "help")) {
        return text(output, "Sucrune sh: bounded shell subset, not POSIX sh/bash.\n"
                    "Commands: echo [-n], printf (%s/%% and \\n/\\r/\\t/\\\\), pwd, cd, cat [files|-], ls [-a],\n"
                    "mkdir [-p], touch (ensure file exists), rm [-f] (files only), cp, mv,\n"
                    "true, false, exit, sleep (0..60 seconds), sh -c SCRIPT, sh FILE, source FILE,\n"
                    "exec /bin/lua|/bin/musl-smoke|/bin/sucrune-sh [args...] (replaces this shell).\n"
                    "Syntax: quotes, escapes, NAME=value, $NAME/${NAME}/$?, ;, newline, &&, ||, <, >, >>.\n"
                    "No pipelines, background jobs, command substitution, loops, globbing,\n"
                    "field splitting, PATH search, fork, positional args, here-docs or fd redirection.\n"
                    "exec exports all variables and inherits stdin/stdout redirection.\n") ? 0 : 1;
    }
    if (equal(command, "for") || equal(command, "while") || equal(command, "until") ||
        equal(command, "if") || equal(command, "then") || equal(command, "else") ||
        equal(command, "fi") || equal(command, "do") || equal(command, "done") ||
        equal(command, "case") || equal(command, "esac") || equal(command, "function"))
        return error("compound commands and functions are unsupported");
    (void)text(2, "sucrune-sh: command not found: "); (void)text(2, command); (void)text(2, "\n");
    return 127;
}
static size_t assignment_prefix(const struct word *word) {
    if (word->size == 0U || !name_start(word->start[0])) return 0U;
    size_t i = 1U;
    while (i < word->size && name_char(word->start[i])) ++i;
    return i < word->size && word->start[i] == '=' ? i : 0U;
}
static int compound_word(const char *word) {
    return equal(word, "for") || equal(word, "while") || equal(word, "until") ||
           equal(word, "if") || equal(word, "then") || equal(word, "else") ||
           equal(word, "fi") || equal(word, "do") || equal(word, "done") ||
           equal(word, "case") || equal(word, "esac") || equal(word, "function");
}
struct saved_descriptor { intptr_t target, backup, flags; };
static intptr_t restore_descriptors(struct saved_descriptor *saved, size_t count) {
    intptr_t first_error = 0;
    while (count > 0U) {
        struct saved_descriptor *item = &saved[--count];
        intptr_t result;
        if (item->backup >= 0) {
            result = call6(24, item->backup, item->target, 0, 0, 0, 0);
            if (result >= 0) result = call6(25, item->target, F_SETFD, item->flags, 0, 0, 0);
            intptr_t closed = close_file(item->backup);
            if (result >= 0 && closed < 0) result = closed;
        } else {
            result = close_file(item->target);
            if (result == -9) result = 0; /* It was closed before this command. */
        }
        if (result < 0 && first_error == 0) first_error = result;
    }
    return first_error;
}
static int execute(unsigned int depth, const struct command *command, int *fatal) {
    struct frame *frame = &frames[depth]; size_t used = 0U;
    size_t assignments = 0U;
    while (assignments < command->argc && assignment_prefix(&frame->words[assignments]) != 0U) ++assignments;
    *fatal = 1;
    if (assignments != 0U && assignments != command->argc)
        return error("temporary command-prefix assignments are unsupported; use NAME=value; command");
    for (size_t i = 0U; i < command->argc; ++i) {
        int result = expand(&frame->words[i], frame->expanded, &used, &frame->argv[i]);
        if (result != 0) return result;
        if (assignments != 0U) {
            size_t prefix = assignment_prefix(&frame->words[i]);
            if (prefix >= NAME_LIMIT) return error("variable name is too large");
            char name[NAME_LIMIT]; (void)memcpy(name, frame->argv[i], prefix); name[prefix] = 0;
            result = set_variable(name, frame->argv[i] + prefix + 1U);
            if (result != 0) return result;
        }
    }
    frame->argv[command->argc] = NULL;
    if (command->argc != 0U && assignments == 0U && compound_word(frame->argv[0]))
        return error("compound commands and functions are unsupported");
    char *paths[2];
    for (size_t i = 0U; i < command->redirect_count; ++i) {
        int expanded = expand(&command->redirects[i].path, frame->expanded, &used, &paths[i]);
        if (expanded != 0) return expanded;
    }
    *fatal = 0;
    struct saved_descriptor saved[2];
    /* Save every affected standard descriptor before the first open. Backups
     * share offsets but close on successful exec, including nested-frame saves. */
    for (size_t i = 0U; i < command->redirect_count; ++i) {
        saved[i].target = command->redirects[i].target;
        saved[i].backup = -1;
        saved[i].flags = call6(25, saved[i].target, F_GETFD, 0, 0, 0, 0);
        intptr_t result = saved[i].flags;
        if (result >= 0) result = saved[i].backup = call6(25, saved[i].target, F_DUPFD_CLOEXEC, 3, 0, 0, 0);
        if (result < 0 && saved[i].flags != -9) {
            for (size_t n = 0U; n < i; ++n) if (saved[n].backup >= 0) (void)close_file(saved[n].backup);
            return operation_error("save descriptor", "", result);
        }
    }
    int result = 0;
    for (size_t i = 0U; i < command->redirect_count; ++i) {
        const struct redirection *redirect = &command->redirects[i];
        intptr_t flags = redirect->target == 0 ? 0 : O_WRONLY | O_CREAT | (redirect->append != 0 ? O_APPEND : O_TRUNC);
        intptr_t opened = open_file(paths[i], flags, 0644);
        if (opened < 0) { result = operation_error("redirect", paths[i], opened); break; }
        if (opened != redirect->target) {
            intptr_t mapped = call6(24, opened, redirect->target, 0, 0, 0, 0);
            intptr_t closed = close_file(opened);
            if (mapped < 0 || closed < 0) { result = operation_error("redirect descriptor", paths[i], mapped < 0 ? mapped : closed); break; }
        }
    }
    if (result == 0 && command->argc != 0U && assignments == 0U) result = builtin(depth, command->argc, frame->argv);
    intptr_t restored = restore_descriptors(saved, command->redirect_count);
    if (restored < 0) {
        *fatal = 1; /* Never continue a script with uncertain standard streams. */
        return operation_error("restore descriptor", "", restored);
    }
    return result;
}
static int run_script(unsigned int depth) {
    struct frame *frame = &frames[depth]; size_t position = 0U;
    int connector = 0; int any = 0;
    while (exit_requested == 0) {
        for (;;) {
            while (frame->script[position] == ' ' || frame->script[position] == '\t' ||
                   frame->script[position] == '\r' || frame->script[position] == '\n') ++position;
            if (frame->script[position] == '\\' && frame->script[position + 1U] == '\n') { position += 2U; continue; }
            if (frame->script[position] != '#') break;
            while (frame->script[position] != 0 && frame->script[position] != '\n') ++position;
        }
        if (frame->script[position] == 0) return connector != 0 ? error("missing command after && or ||") : (any != 0 ? last_status : 0);
        struct command command;
        int result = parse_command(frame, &position, &command);
        if (result != 0) return result;
        if (connector == 0 || (connector == 1 && last_status == 0) || (connector == 2 && last_status != 0)) {
            int fatal = 0;
            last_status = execute(depth, &command, &fatal);
            if (fatal != 0) return last_status;
        }
        any = 1; connector = command.connector;
    }
    return last_status;
}

int shell_main(intptr_t argc, char **argv, char **environment) {
    if (initialized_data != 1U) return 126;
    for (size_t i = 0U; environment != NULL && environment[i] != NULL && i < VARIABLE_LIMIT; ++i) {
        const char *value = environment[i]; size_t n = 0U;
        while (value[n] != 0 && value[n] != '=' && n + 1U < NAME_LIMIT) ++n;
        if (value[n] != '=' || n == 0U || length(value + n + 1U) >= VALUE_LIMIT) continue;
        char name[NAME_LIMIT]; (void)memcpy(name, value, n); name[n] = 0;
        if (name_start(name[0])) (void)set_variable(name, value + n + 1U);
    }
    if (argc == 3 && equal(argv[1], "-c")) {
        if (!copy(frames[0].script, sizeof(frames[0].script), argv[2])) return error("script exceeds 64 KiB");
        return run_script(0U);
    }
    if (argc == 2 && equal(argv[1], "--help")) {
        char help[] = "help"; char *arguments[1] = {help};
        return builtin(0U, 1U, arguments);
    }
    if (argc == 2) {
        /* Top-level FILE uses the same bounded reader as nested sh. */
        return run_nested(0U, (size_t)argc, argv, 1);
    }
    return error("usage: sh -c SCRIPT | sh FILE | sh --help");
}
