#include "linux_elf.h"
#include <elf.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>

static int bounds(uint64_t offset, uint64_t count, size_t length) {
    return offset <= length && count <= length - offset;
}
static int power(uint64_t value) { return value != 0U && (value & (value - 1U)) == 0U; }
static void phdr_at(const unsigned char *bytes, const Elf64_Ehdr *header, size_t index, Elf64_Phdr *phdr) {
    memcpy(phdr, bytes + (size_t)header->e_phoff + index * sizeof(*phdr), sizeof(*phdr));
}
static int metadata_mapped(const struct sucrune_elf_plan *plan, const Elf64_Phdr *p, int tls) {
    if (p->p_vaddr < plan->virtual_base || p->p_vaddr - plan->virtual_base > plan->image_size) return 0;
    if (tls && p->p_filesz == 0U) return 1;
    size_t relative = (size_t)(p->p_vaddr - plan->virtual_base);
    for (size_t i = 0; i < plan->segment_count; i++) {
        const struct sucrune_elf_segment *s = &plan->segments[i];
        if (relative < s->vaddr || relative - s->vaddr > s->memsz) continue;
        size_t delta = relative - s->vaddr;
        if (!tls && p->p_memsz > s->memsz - delta) {
            /* lld can round RELRO to the end of the mapped page, beyond
             * the last declared RW byte. No file data may use this padding. */
            if (p->p_type != PT_GNU_RELRO || delta == s->memsz ||
                p->p_memsz > s->page_offset + s->page_length - relative) continue;
        }
        if (p->p_filesz != 0U && (delta > s->filesz || p->p_filesz > s->filesz - delta ||
                p->p_offset != s->offset + delta)) continue;
        return 1;
    }
    return 0;
}
enum sucrune_elf_error sucrune_linux_validate(const void *input, size_t length,
        size_t page_size, struct sucrune_linux_plan *result) {
    if (input == NULL || result == NULL || (page_size != 4096U && page_size != 16384U)) return SUCRUNE_ELF_INVALID_ARGUMENT;
    memset(result, 0, sizeof(*result));
    if (length < sizeof(Elf64_Ehdr) || length > SUCRUNE_LINUX_MAX_FILE) return SUCRUNE_ELF_BAD_BOUNDS;
    const unsigned char *bytes = input;
    Elf64_Ehdr h;
    memcpy(&h, bytes, sizeof(h));
    if (memcmp(h.e_ident, ELFMAG, SELFMAG) != 0 || h.e_ident[EI_CLASS] != ELFCLASS64 ||
        h.e_ident[EI_DATA] != ELFDATA2LSB || h.e_ident[EI_VERSION] != EV_CURRENT ||
        h.e_version != EV_CURRENT || h.e_ehsize != sizeof(h) || h.e_phentsize != sizeof(Elf64_Phdr) ||
        h.e_phnum == 0U || h.e_phnum > SUCRUNE_ELF_MAX_PHDRS) return SUCRUNE_ELF_BAD_HEADER;
    if (h.e_machine != EM_AARCH64 || (h.e_type != ET_EXEC && h.e_type != ET_DYN) || h.e_flags != 0U ||
        h.e_ident[EI_ABIVERSION] != 0U || (h.e_ident[EI_OSABI] != ELFOSABI_NONE && h.e_ident[EI_OSABI] != ELFOSABI_LINUX))
        return SUCRUNE_ELF_UNSUPPORTED;
    size_t phsize = (size_t)h.e_phnum * sizeof(Elf64_Phdr);
    if (h.e_phoff < sizeof(h) || !bounds(h.e_phoff, phsize, length)) return SUCRUNE_ELF_BAD_BOUNDS;
    struct sucrune_elf_plan *plan = &result->load;
    plan->page_size = page_size; plan->alignment = page_size;
    plan->phnum = h.e_phnum; plan->phentsize = h.e_phentsize;
    plan->fixed_address = h.e_type == ET_EXEC;
    int first = 1, entry = 0, tls = 0, interp = 0, dynamic = 0, explicit_phdr = 0;
    size_t previous_end = 0;
    for (size_t i = 0; i < h.e_phnum; i++) {
        Elf64_Phdr p; phdr_at(bytes, &h, i, &p);
        if (p.p_type == PT_NULL) continue;
        if (!(p.p_type == PT_TLS && p.p_filesz == 0U) && !bounds(p.p_offset, p.p_filesz, length)) return SUCRUNE_ELF_BAD_BOUNDS;
        if (p.p_type == PT_INTERP) {
            if (interp++ || p.p_filesz < 2U || p.p_filesz > sizeof(result->interpreter)) return SUCRUNE_ELF_BAD_HEADER;
            const char *name = (const char *)bytes + (size_t)p.p_offset;
            if (name[0] != '/' || name[p.p_filesz - 1U] != '\0' || memchr(name, 0, (size_t)p.p_filesz - 1U) != NULL)
                return SUCRUNE_ELF_BAD_HEADER;
            memcpy(result->interpreter, name, (size_t)p.p_filesz);
            continue;
        }
        if (p.p_type == PT_GNU_STACK) {
            if ((p.p_flags & PF_X) != 0U) return SUCRUNE_ELF_BAD_PERMISSIONS;
            continue;
        }
        if (p.p_type == PT_DYNAMIC || p.p_type == PT_TLS || p.p_type == PT_PHDR ||
            p.p_type == PT_GNU_RELRO || p.p_type == PT_GNU_EH_FRAME || p.p_type == 0x6474e553U) {
            if (p.p_filesz > p.p_memsz || p.p_memsz > SUCRUNE_LINUX_MAX_IMAGE ||
                (p.p_align > 1U && !power(p.p_align))) return SUCRUNE_ELF_BAD_BOUNDS;
            if ((p.p_type == PT_TLS && tls++) || (p.p_type == PT_DYNAMIC && dynamic++) || (p.p_type == PT_PHDR && explicit_phdr++))
                return SUCRUNE_ELF_BAD_HEADER;
            if (p.p_type == PT_DYNAMIC) result->has_dynamic = 1;
            continue;
        }
        if (p.p_type == PT_NOTE) continue;
        if (p.p_type != PT_LOAD) return SUCRUNE_ELF_UNSUPPORTED;
        if (p.p_memsz == 0U) { if (p.p_filesz != 0U) return SUCRUNE_ELF_BAD_BOUNDS; continue; }
        if (first) {
            plan->virtual_base = (uintptr_t)(p.p_vaddr & ~((uint64_t)page_size - 1U)); first = 0;
            if (plan->fixed_address && plan->virtual_base < 65536U) return SUCRUNE_ELF_BAD_BOUNDS;
        }
        if (p.p_filesz > p.p_memsz || p.p_vaddr < plan->virtual_base ||
            p.p_vaddr - plan->virtual_base > SUCRUNE_LINUX_MAX_IMAGE ||
            p.p_memsz > SUCRUNE_LINUX_MAX_IMAGE - (p.p_vaddr - plan->virtual_base) ||
            p.p_vaddr > UINTPTR_MAX - p.p_memsz || plan->segment_count == SUCRUNE_ELF_MAX_LOADS) return SUCRUNE_ELF_BAD_BOUNDS;
        if ((p.p_flags & ~(unsigned int)(PF_R | PF_W | PF_X)) != 0U || !(p.p_flags & PF_R) ||
            (p.p_flags & (PF_W | PF_X)) == (PF_W | PF_X)) return SUCRUNE_ELF_BAD_PERMISSIONS;
        if (p.p_align > SUCRUNE_LINUX_MAX_IMAGE || (p.p_align > 1U && (!power(p.p_align) ||
            p.p_vaddr % p.p_align != p.p_offset % p.p_align)) || p.p_vaddr % page_size != p.p_offset % page_size)
            return SUCRUNE_ELF_BAD_ALIGNMENT;
        size_t relative = (size_t)(p.p_vaddr - plan->virtual_base);
        size_t begin = relative & ~(page_size - 1U);
        size_t end = (relative + (size_t)p.p_memsz + page_size - 1U) & ~(page_size - 1U);
        if (begin < previous_end) return SUCRUNE_ELF_OVERLAP;
        previous_end = end;
        struct sucrune_elf_segment *s = &plan->segments[plan->segment_count++];
        s->offset = (size_t)p.p_offset; s->vaddr = relative; s->filesz = (size_t)p.p_filesz; s->memsz = (size_t)p.p_memsz;
        s->page_offset = begin; s->page_length = end - begin; s->flags = p.p_flags;
        if (p.p_align > plan->alignment) plan->alignment = (size_t)p.p_align;
        plan->image_size = end;
        if ((p.p_flags & PF_X) && h.e_entry >= p.p_vaddr && h.e_entry - p.p_vaddr < p.p_filesz &&
            p.p_filesz - (h.e_entry - p.p_vaddr) >= 4U && h.e_entry % 4U == 0U) entry = 1;
        if (h.e_phoff >= p.p_offset && h.e_phoff - p.p_offset <= p.p_filesz && phsize <= p.p_filesz - (h.e_phoff - p.p_offset)) {
            plan->phdr_offset = relative + (size_t)(h.e_phoff - p.p_offset); plan->phdr_mapped = 1;
        }
    }
    if (first || !entry) return SUCRUNE_ELF_BAD_ENTRY;
    if (!plan->phdr_mapped) return SUCRUNE_ELF_BAD_HEADER;
    for (size_t i = 0; i < h.e_phnum; i++) {
        Elf64_Phdr p; phdr_at(bytes, &h, i, &p);
        if (p.p_type == PT_DYNAMIC || p.p_type == PT_TLS || p.p_type == PT_GNU_RELRO || p.p_type == PT_GNU_EH_FRAME || p.p_type == 0x6474e553U) {
            if (!metadata_mapped(plan, &p, p.p_type == PT_TLS)) return SUCRUNE_ELF_BAD_BOUNDS;
        }
        if (p.p_type == PT_PHDR && (p.p_offset != h.e_phoff || p.p_vaddr != plan->virtual_base + plan->phdr_offset ||
                p.p_filesz != phsize || p.p_memsz != phsize)) return SUCRUNE_ELF_BAD_HEADER;
    }
    plan->entry_offset = (size_t)(h.e_entry - plan->virtual_base);
    return SUCRUNE_ELF_OK;
}

enum sucrune_elf_error sucrune_linux_map(const void *bytes, size_t length,
        const struct sucrune_linux_plan *parsed, struct sucrune_guest_space *space,
        struct sucrune_elf_image *image) {
    if (bytes == NULL || parsed == NULL || space == NULL || image == NULL) return SUCRUNE_ELF_INVALID_ARGUMENT;
    struct sucrune_linux_plan verified;
    enum sucrune_elf_error valid = sucrune_linux_validate(bytes, length, space->page_size, &verified);
    if (valid != SUCRUNE_ELF_OK) return valid;
    if (memcmp(&verified, parsed, sizeof(verified)) != 0) return SUCRUNE_ELF_INVALID_ARGUMENT;
    const struct sucrune_elf_plan *p = &parsed->load;
    unsigned int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    if (p->fixed_address) flags |= MAP_FIXED_NOREPLACE;
    int64_t mapped = sucrune_space_map(space, p->fixed_address ? p->virtual_base : 0U, p->image_size, p->alignment, PROT_NONE, flags);
    if (mapped < 0) { errno = (int)-mapped; return SUCRUNE_ELF_MAP_FAILED; }
    uintptr_t base = (uintptr_t)mapped;
    memset(image, 0, sizeof(*image));
    image->base = (void *)base; image->size = p->image_size; image->load_bias = base - p->virtual_base;
    image->entry = base + p->entry_offset; image->phdr = base + p->phdr_offset;
    image->phnum = p->phnum; image->phentsize = p->phentsize; image->segment_count = p->segment_count;
    for (size_t i = 0; i < p->segment_count; i++) {
        const struct sucrune_elf_segment *s = &p->segments[i];
        uintptr_t page = base + s->page_offset;
        int error = sucrune_space_protect(space, page, s->page_length, PROT_READ | PROT_WRITE);
        if (error == 0) {
            size_t prefix = s->vaddr - s->page_offset;
            memcpy((void *)page, (const unsigned char *)bytes + s->offset - prefix, s->filesz + prefix);
            int protection = PROT_READ | ((s->flags & PF_W) ? PROT_WRITE : 0) | ((s->flags & PF_X) ? PROT_EXEC : 0);
            error = sucrune_space_protect(space, page, s->page_length, protection);
            if (error == 0) error = sucrune_space_mark_file(space, page, s->page_length);
        }
        if (error != 0) { (void)sucrune_space_unmap(space, base, p->image_size); memset(image, 0, sizeof(*image)); errno = -error; return SUCRUNE_ELF_PROTECT_FAILED; }
        image->segments[i].start = page; image->segments[i].length = s->page_length; image->segments[i].flags = s->flags;
    }
    return SUCRUNE_ELF_OK;
}
