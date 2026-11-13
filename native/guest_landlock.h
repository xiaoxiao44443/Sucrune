#ifndef SUCRUNE_GUEST_LANDLOCK_H
#define SUCRUNE_GUEST_LANDLOCK_H
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

/* Linux filesystem UAPI through ABI 3. */
enum sucrune_landlock_access {
    LL_EXECUTE = 1U, LL_WRITE_FILE = 1U << 1, LL_READ_FILE = 1U << 2, LL_READ_DIR = 1U << 3,
    LL_REMOVE_DIR = 1U << 4, LL_REMOVE_FILE = 1U << 5, LL_MAKE_CHAR = 1U << 6,
    LL_MAKE_DIR = 1U << 7, LL_MAKE_REG = 1U << 8, LL_MAKE_SOCK = 1U << 9,
    LL_MAKE_FIFO = 1U << 10, LL_MAKE_BLOCK = 1U << 11, LL_MAKE_SYM = 1U << 12,
    LL_REFER = 1U << 13, LL_TRUNCATE = 1U << 14, LL_ALL = (1U << 15) - 1U,
    LL_FILE = LL_EXECUTE | LL_READ_FILE | LL_WRITE_FILE | LL_TRUNCATE
};
/* Negative synthetic identities have no manager-owned inode. All synthetic
 * files inherit grants on guest /. Other devices fail closed for named rules. */
#define LL_DEV_NULL (-1000)
#define LL_OTHER_SPECIAL (-1001)
#define LL_NO_TARGET (-1)
#define LL_MAX_LAYERS 16U
struct ll_ruleset;
struct ll_layer;
struct ll_domain {
    struct ll_layer *layers[LL_MAX_LAYERS];
    unsigned int count;
    bool no_new_privs;
    /* Borrowed from the broker family. Splice a trusted POSIX export into
     * its virtual guest hierarchy while computing PATH_BENEATH rights. */
    int bind_root_plus_one, bind_parent_plus_one;
};
int ll_create(uint64_t handled, struct ll_ruleset **out);
void ll_hold(struct ll_ruleset *set);
void ll_put(struct ll_ruleset *set);
int ll_add(struct ll_ruleset *set, uint64_t rights, int fd);
int ll_restrict(struct ll_domain *domain, struct ll_ruleset *set);
void ll_inherit(struct ll_domain *child, const struct ll_domain *parent);
void ll_release(struct ll_domain *domain);
/* parent is the final resolved guest directory. target is an optional inode
 * within it (including Sucrune's backing inode for emulated hard links). */
int ll_check(const struct ll_domain *domain, int root, int parent, int target, unsigned int rights);
int ll_allowed(const struct ll_domain *domain, int root, int parent, int target, unsigned int *rights);
int ll_reparent(const struct ll_domain *domain, int root, int old_parent, int child, int new_parent, mode_t mode);
unsigned int ll_make_right(mode_t mode);
#endif
