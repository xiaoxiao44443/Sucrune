#ifndef SUCRUNE_GUEST_SHEBANG_H
#define SUCRUNE_GUEST_SHEBANG_H
#include <stddef.h>
#include <errno.h>
#include <string.h>

/* Linux binfmt_script examines BINPRM_BUF_SIZE bytes. A space or tab
 * separates the interpreter from one opaque argument. CR is ordinary data. */
#define SUCRUNE_SHEBANG_HEADER 256U
#define SUCRUNE_SHEBANG_DEPTH 5U
struct sucrune_script_line {
    char text[SUCRUNE_SHEBANG_HEADER]; /* interpreter, then optional argument */
    size_t argument;
};
struct sucrune_script_chain {
    struct sucrune_script_line lines[SUCRUNE_SHEBANG_DEPTH];
    size_t count;
};
static inline int sucrune_script_blank(unsigned char c) { return c == ' ' || c == '\t'; }
/* Return 0 for another executable format, 1 for a script, or negative errno. */
static inline int sucrune_script_parse(const unsigned char *buf, size_t size,
                                       struct sucrune_script_line *line) {
    if (size < 2U || buf[0] != '#' || buf[1] != '!') return 0;
    if (size > SUCRUNE_SHEBANG_HEADER) size = SUCRUNE_SHEBANG_HEADER;
    size_t end = 2U;
    while (end < size && buf[end] != '\n' && buf[end] != 0) end++;
    size_t first = 2U;
    while (first < end && sucrune_script_blank(buf[first])) first++;
    size_t sep = first;
    while (sep < end && !sucrune_script_blank(buf[sep])) sep++;
    if (sep == first || (end == SUCRUNE_SHEBANG_HEADER && sep == end)) return -ENOEXEC;
    if (end == SUCRUNE_SHEBANG_HEADER) end--;
    while (end > sep && sucrune_script_blank(buf[end - 1U])) end--;
    size_t arg = sep;
    while (arg < end && sucrune_script_blank(buf[arg])) arg++;
    size_t name = sep - first;
    memcpy(line->text, buf + first, name);
    line->text[name] = 0;
    line->argument = 0;
    if (arg < end) {
        line->argument = name + 1U;
        memcpy(line->text + line->argument, buf + arg, end - arg);
        line->text[line->argument + end - arg] = 0;
    }
    return 1;
}
/* binfmt_script replaces argv[0] on every interpretation. In a chain the
 * innermost interpreter and its optional argument therefore appear first. */
static inline size_t sucrune_script_prefix(const struct sucrune_script_chain *chain,
                                           const char *filename, const char **prefix) {
    size_t used = 0;
    for (size_t depth = chain->count; depth > 0; depth--) {
        const struct sucrune_script_line *line = &chain->lines[depth - 1U];
        prefix[used++] = line->text;
        if (line->argument != 0U) prefix[used++] = line->text + line->argument;
    }
    prefix[used++] = filename;
    return used;
}
#endif
