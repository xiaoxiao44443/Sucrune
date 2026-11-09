#ifndef SUCRUNE_LINUX_ELF_H
#define SUCRUNE_LINUX_ELF_H
#include "elf_loader.h"
#include "guest_space.h"

#define SUCRUNE_LINUX_MAX_FILE (256U * 1024U * 1024U)
#define SUCRUNE_LINUX_MAX_IMAGE (1024U * 1024U * 1024U)
#define SUCRUNE_LINUX_INTERPRETER 1024U

/* Linux execution profile. The ELF interpreter, not this mapper, performs
 * dynamic relocations/TLS setup. Section tables are not execution metadata.
 * Accepting an image is not a hostile-code security validation. */
struct sucrune_linux_plan {
    struct sucrune_elf_plan load;
    char interpreter[SUCRUNE_LINUX_INTERPRETER];
    int has_dynamic;
};
enum sucrune_elf_error sucrune_linux_validate(const void *bytes, size_t length,
    size_t page_size, struct sucrune_linux_plan *plan);
/* space owns every mapping. image is a view; do not call elf_unload on it. */
enum sucrune_elf_error sucrune_linux_map(const void *bytes, size_t length,
    const struct sucrune_linux_plan *plan, struct sucrune_guest_space *space,
    struct sucrune_elf_image *image);
#endif
