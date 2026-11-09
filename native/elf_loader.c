#include "elf_loader.h"

#include <elf.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#ifndef SUCRUNE_ELF_VALIDATE_ONLY
#include <sys/mman.h>
#include <unistd.h>
#endif

static int bounded(uint64_t offset, uint64_t count, size_t length) {
    return offset <= (uint64_t)length && count <= (uint64_t)length - offset;
}

static int power_of_two(size_t value) {
    return value != 0U && (value & (value - 1U)) == 0U;
}

static size_t page_up(size_t value, size_t page_size) {
    return (value + page_size - 1U) & ~(page_size - 1U);
}

static enum sucrune_elf_error validate_sections(const unsigned char *bytes,
                                               size_t length,
                                               const Elf64_Ehdr *header) {
    if (header->e_shoff == 0U) {
        return header->e_shnum == 0U && header->e_shstrndx == SHN_UNDEF
                   ? SUCRUNE_ELF_OK : SUCRUNE_ELF_BAD_HEADER;
    }
    /* Extended section numbering is deliberately outside this first format. */
    if (header->e_shnum == 0U || header->e_shentsize != sizeof(Elf64_Shdr) ||
        (header->e_shstrndx != SHN_UNDEF && header->e_shstrndx >= header->e_shnum)) {
        return SUCRUNE_ELF_BAD_HEADER;
    }
    if (!bounded(header->e_shoff,
                 (uint64_t)header->e_shnum * sizeof(Elf64_Shdr), length)) {
        return SUCRUNE_ELF_BAD_BOUNDS;
    }
    for (size_t index = 0U; index < header->e_shnum; ++index) {
        Elf64_Shdr section;
        memcpy(&section, bytes + (size_t)header->e_shoff + index * sizeof(section),
               sizeof(section));
        if (section.sh_type != SHT_NOBITS && section.sh_type != SHT_NULL &&
            !bounded(section.sh_offset, section.sh_size, length)) {
            return SUCRUNE_ELF_BAD_BOUNDS;
        }
        if ((section.sh_type == SHT_REL || section.sh_type == SHT_RELA ||
             section.sh_type == SHT_DYNAMIC || section.sh_type == 19U) &&
            section.sh_size != 0U) { /* 19 is SHT_RELR. */
            return SUCRUNE_ELF_UNSUPPORTED;
        }
    }
    return SUCRUNE_ELF_OK;
}

static enum sucrune_elf_error validate(const void *input, size_t length,
                                      size_t page_size,
                                      struct sucrune_elf_plan *plan,
                                      int program) {
    if (input == NULL || plan == NULL ||
        (page_size != 4096U && page_size != 16384U)) {
        return SUCRUNE_ELF_INVALID_ARGUMENT;
    }
    memset(plan, 0, sizeof(*plan));
    if (length < sizeof(Elf64_Ehdr) || length > SUCRUNE_ELF_MAX_IMAGE) {
        return SUCRUNE_ELF_BAD_BOUNDS;
    }
    const unsigned char *bytes = input;
    Elf64_Ehdr header;
    memcpy(&header, bytes, sizeof(header));
    if (memcmp(header.e_ident, ELFMAG, SELFMAG) != 0 ||
        header.e_ident[EI_CLASS] != ELFCLASS64 ||
        header.e_ident[EI_DATA] != ELFDATA2LSB ||
        header.e_ident[EI_VERSION] != EV_CURRENT ||
        header.e_version != EV_CURRENT || header.e_ehsize != sizeof(header) ||
        header.e_phentsize != sizeof(Elf64_Phdr) || header.e_phnum == 0U ||
        header.e_phnum > SUCRUNE_ELF_MAX_PHDRS) {
        return SUCRUNE_ELF_BAD_HEADER;
    }
    if (header.e_machine != EM_AARCH64 || header.e_type != (program != 0 ? ET_EXEC : ET_DYN) ||
        header.e_flags != 0U || header.e_ident[EI_ABIVERSION] != 0U ||
        (header.e_ident[EI_OSABI] != ELFOSABI_NONE &&
         header.e_ident[EI_OSABI] != ELFOSABI_LINUX)) {
        return SUCRUNE_ELF_UNSUPPORTED;
    }
    const size_t phdr_bytes = (size_t)header.e_phnum * sizeof(Elf64_Phdr);
    if (header.e_phoff < sizeof(header) ||
        !bounded(header.e_phoff, phdr_bytes, length)) {
        return SUCRUNE_ELF_BAD_BOUNDS;
    }
    enum sucrune_elf_error section_error = validate_sections(bytes, length, &header);
    if (section_error != SUCRUNE_ELF_OK) { return section_error; }

    if (program != 0) {
        int found = 0;
        for (size_t index = 0U; index < header.e_phnum; ++index) {
            Elf64_Phdr phdr;
            memcpy(&phdr, bytes + (size_t)header.e_phoff + index * sizeof(phdr), sizeof(phdr));
            if (phdr.p_type != PT_LOAD) { continue; }
            uint64_t base = phdr.p_vaddr & ~((uint64_t)page_size - 1U);
            if (base < 65536U || base > UINTPTR_MAX - SUCRUNE_ELF_MAX_IMAGE) {
                return SUCRUNE_ELF_BAD_BOUNDS;
            }
            plan->virtual_base = (uintptr_t)base;
            plan->fixed_address = 1;
            found = 1;
            break;
        }
        if (found == 0) { return SUCRUNE_ELF_BAD_ENTRY; }
    }

    plan->page_size = page_size;
    plan->alignment = page_size;
    plan->phnum = header.e_phnum;
    plan->phentsize = header.e_phentsize;
    size_t previous_end = 0U;
    int entry_found = 0;
    int phdr_seen = 0;
    int tls_seen = 0;
    int relro_seen = 0;
    Elf64_Phdr explicit_phdr = {0};
    for (size_t index = 0U; index < header.e_phnum; ++index) {
        Elf64_Phdr phdr;
        memcpy(&phdr, bytes + (size_t)header.e_phoff + index * sizeof(phdr),
               sizeof(phdr));
        if (phdr.p_type == PT_NULL) { continue; }
        /* Pure TBSS has no file template; its file offset is not dereferenced. */
        if (!(program != 0 && phdr.p_type == PT_TLS && phdr.p_filesz == 0U) &&
            !bounded(phdr.p_offset, phdr.p_filesz, length)) {
            return SUCRUNE_ELF_BAD_BOUNDS;
        }
        if (phdr.p_type == PT_DYNAMIC || phdr.p_type == PT_INTERP ||
            (program == 0 && phdr.p_type == PT_TLS)) { return SUCRUNE_ELF_UNSUPPORTED; }
        if (program != 0 && (phdr.p_type == PT_TLS || phdr.p_type == PT_GNU_RELRO ||
                            phdr.p_type == PT_GNU_EH_FRAME || phdr.p_type == 0x6474e553U)) {
            if ((phdr.p_type == PT_TLS && tls_seen++ != 0) ||
                (phdr.p_type == PT_GNU_RELRO && relro_seen++ != 0)) {
                return SUCRUNE_ELF_BAD_HEADER;
            }
            if (phdr.p_filesz > phdr.p_memsz || phdr.p_vaddr < plan->virtual_base ||
                phdr.p_vaddr - plan->virtual_base > SUCRUNE_ELF_MAX_IMAGE ||
                phdr.p_memsz > SUCRUNE_ELF_MAX_IMAGE ||
                (phdr.p_type != PT_TLS && phdr.p_memsz >
                 SUCRUNE_ELF_MAX_IMAGE - (phdr.p_vaddr - plan->virtual_base))) {
                return SUCRUNE_ELF_BAD_BOUNDS;
            }
            if (phdr.p_align > SUCRUNE_ELF_MAX_IMAGE ||
                (phdr.p_type == PT_TLS && phdr.p_align == 0U) ||
                (phdr.p_align > 1U && (!power_of_two((size_t)phdr.p_align) ||
                 ((phdr.p_type != PT_TLS || phdr.p_filesz != 0U) &&
                  phdr.p_vaddr % phdr.p_align != phdr.p_offset % phdr.p_align)))) {
                return SUCRUNE_ELF_BAD_ALIGNMENT;
            }
            if ((phdr.p_flags & PF_X) != 0U || (phdr.p_flags & ~(unsigned int)(PF_R | PF_W)) != 0U) {
                return SUCRUNE_ELF_BAD_PERMISSIONS;
            }
            continue;
        }
        if (phdr.p_type == PT_GNU_STACK) {
            if ((phdr.p_flags & PF_X) != 0U) { return SUCRUNE_ELF_BAD_PERMISSIONS; }
            continue;
        }
        if (phdr.p_type == PT_PHDR) {
            if (phdr_seen != 0) { return SUCRUNE_ELF_BAD_HEADER; }
            phdr_seen = 1;
            explicit_phdr = phdr;
            continue;
        }
        if (phdr.p_type == PT_NOTE) { continue; }
        if (phdr.p_type != PT_LOAD) { return SUCRUNE_ELF_UNSUPPORTED; }
        if (phdr.p_filesz > phdr.p_memsz || phdr.p_memsz == 0U ||
            phdr.p_vaddr < plan->virtual_base ||
            phdr.p_vaddr - plan->virtual_base > SUCRUNE_ELF_MAX_IMAGE ||
            phdr.p_memsz > SUCRUNE_ELF_MAX_IMAGE - (phdr.p_vaddr - plan->virtual_base) ||
            plan->segment_count >= SUCRUNE_ELF_MAX_LOADS) {
            return SUCRUNE_ELF_BAD_BOUNDS;
        }
        if ((phdr.p_flags & ~(unsigned int)(PF_R | PF_W | PF_X)) != 0U ||
            (phdr.p_flags & PF_R) == 0U ||
            (phdr.p_flags & (PF_W | PF_X)) == (PF_W | PF_X)) {
            return SUCRUNE_ELF_BAD_PERMISSIONS;
        }
        if (phdr.p_align > SUCRUNE_ELF_MAX_IMAGE ||
            (phdr.p_align > 1U && !power_of_two((size_t)phdr.p_align)) ||
            (phdr.p_align > 1U &&
             phdr.p_vaddr % phdr.p_align != phdr.p_offset % phdr.p_align) ||
            phdr.p_vaddr % page_size != phdr.p_offset % page_size) {
            return SUCRUNE_ELF_BAD_ALIGNMENT;
        }
        size_t relative = (size_t)(phdr.p_vaddr - plan->virtual_base);
        size_t page_start = relative & ~(page_size - 1U);
        size_t page_end = page_up(relative + (size_t)phdr.p_memsz, page_size);
        if (plan->segment_count == 0U && page_start != 0U) {
            return SUCRUNE_ELF_UNSUPPORTED;
        }
        if (page_start < previous_end) { return SUCRUNE_ELF_OVERLAP; }
        previous_end = page_end;
        struct sucrune_elf_segment *segment = &plan->segments[plan->segment_count++];
        segment->offset = (size_t)phdr.p_offset;
        segment->vaddr = relative;
        segment->filesz = (size_t)phdr.p_filesz;
        segment->memsz = (size_t)phdr.p_memsz;
        segment->page_offset = page_start;
        segment->page_length = page_end - page_start;
        segment->flags = phdr.p_flags;
        if (phdr.p_align > plan->alignment) { plan->alignment = (size_t)phdr.p_align; }
        plan->image_size = page_end;
        if ((phdr.p_flags & PF_X) != 0U && header.e_entry >= phdr.p_vaddr &&
            header.e_entry - phdr.p_vaddr < phdr.p_filesz &&
            phdr.p_filesz - (header.e_entry - phdr.p_vaddr) >= 4U &&
            header.e_entry % 4U == 0U) {
            entry_found = 1;
        }
        if (header.e_phoff >= phdr.p_offset &&
            header.e_phoff - phdr.p_offset <= phdr.p_filesz &&
            phdr_bytes <= phdr.p_filesz - (header.e_phoff - phdr.p_offset)) {
            plan->phdr_offset = segment->vaddr + (size_t)(header.e_phoff - phdr.p_offset);
            plan->phdr_mapped = 1;
        }
    }
    if (plan->segment_count == 0U || entry_found == 0) { return SUCRUNE_ELF_BAD_ENTRY; }
    if (phdr_seen != 0 && (plan->phdr_mapped == 0 ||
        explicit_phdr.p_offset != header.e_phoff ||
        explicit_phdr.p_vaddr != plan->virtual_base + plan->phdr_offset ||
        explicit_phdr.p_filesz != phdr_bytes || explicit_phdr.p_memsz != phdr_bytes)) {
        return SUCRUNE_ELF_BAD_HEADER;
    }
    if (program != 0) {
        /* Only initialized TLS bytes live in the image: libc copies that
         * template into a separately allocated TLS block and zeroes TBSS.
         * Other metadata still requires its entire memory range in PT_LOAD. */
        for (size_t index = 0U; index < header.e_phnum; ++index) {
            Elf64_Phdr phdr;
            memcpy(&phdr, bytes + (size_t)header.e_phoff + index * sizeof(phdr), sizeof(phdr));
            if (phdr.p_type != PT_TLS && phdr.p_type != PT_GNU_RELRO &&
                phdr.p_type != PT_GNU_EH_FRAME && phdr.p_type != 0x6474e553U) { continue; }
            size_t relative = (size_t)(phdr.p_vaddr - plan->virtual_base);
            if (phdr.p_type == PT_TLS && phdr.p_filesz == 0U) {
                /* A zero-byte template may point into a gap or one past the
                 * reserved image; no bytes are read at that address. */
                if (relative > plan->image_size) { return SUCRUNE_ELF_BAD_BOUNDS; }
                continue;
            }
            int contained = 0;
            for (size_t i = 0U; i < plan->segment_count; ++i) {
                const struct sucrune_elf_segment *segment = &plan->segments[i];
                if (relative < segment->vaddr || relative - segment->vaddr > segment->memsz) { continue; }
                size_t delta = relative - segment->vaddr;
                if (phdr.p_type != PT_TLS && phdr.p_memsz > segment->memsz - delta) { continue; }
                if (phdr.p_filesz != 0U && (delta > segment->filesz ||
                    phdr.p_filesz > segment->filesz - delta ||
                    phdr.p_offset != segment->offset + delta)) { continue; }
                contained = 1;
                break;
            }
            if (contained == 0) { return SUCRUNE_ELF_BAD_BOUNDS; }
        }
        if (plan->phdr_mapped == 0) { return SUCRUNE_ELF_BAD_HEADER; }
    }
    plan->entry_offset = (size_t)(header.e_entry - plan->virtual_base);
    return SUCRUNE_ELF_OK;
}

enum sucrune_elf_error sucrune_elf_validate(const void *input, size_t length,
                                          size_t page_size,
                                          struct sucrune_elf_plan *plan) {
    return validate(input, length, page_size, plan, 0);
}

enum sucrune_elf_error sucrune_elf_validate_program(const void *input, size_t length,
                                                  size_t page_size,
                                                  struct sucrune_elf_plan *plan) {
    return validate(input, length, page_size, plan, 1);
}

#ifndef SUCRUNE_ELF_VALIDATE_ONLY
static enum sucrune_elf_error load(const void *bytes, size_t length,
                                 struct sucrune_elf_image *image, int program) {
    if (image == NULL) { return SUCRUNE_ELF_INVALID_ARGUMENT; }
    memset(image, 0, sizeof(*image));
    long page = sysconf(_SC_PAGESIZE);
    if (page != 4096L && page != 16384L) { return SUCRUNE_ELF_UNSUPPORTED; }
    struct sucrune_elf_plan plan;
    enum sucrune_elf_error result = validate(bytes, length, (size_t)page, &plan, program);
    if (result != SUCRUNE_ELF_OK) { return result; }
    const size_t reservation_size = plan.image_size + (plan.fixed_address != 0 ? 0U : plan.alignment);
    void *reservation = mmap(plan.fixed_address != 0 ? (void *)plan.virtual_base : NULL, reservation_size, PROT_NONE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reservation == MAP_FAILED) { return SUCRUNE_ELF_MAP_FAILED; }
    if (plan.fixed_address != 0 && (uintptr_t)reservation != plan.virtual_base) {
        (void)munmap(reservation, reservation_size);
        errno = EADDRINUSE;
        return SUCRUNE_ELF_MAP_FAILED;
    }
    uintptr_t address = (uintptr_t)reservation;
    uintptr_t aligned = plan.fixed_address != 0 ? address :
        (address + plan.alignment - 1U) & ~(uintptr_t)(plan.alignment - 1U);
    image->reservation = reservation;
    image->reservation_size = reservation_size;
    image->base = (void *)aligned;
    image->size = plan.image_size;
    image->load_bias = aligned - plan.virtual_base;
    image->entry = aligned + plan.entry_offset;
    image->phdr = plan.phdr_mapped != 0 ? aligned + plan.phdr_offset : 0U;
    image->phnum = plan.phnum;
    image->phentsize = plan.phentsize;
    image->segment_count = plan.segment_count;
    for (size_t index = 0U; index < plan.segment_count; ++index) {
        const struct sucrune_elf_segment *segment = &plan.segments[index];
        void *mapped_page = (void *)(aligned + segment->page_offset);
        if (mprotect(mapped_page, segment->page_length, PROT_READ | PROT_WRITE) != 0) {
            int saved_errno = errno;
            sucrune_elf_unload(image);
            errno = saved_errno;
            return SUCRUNE_ELF_PROTECT_FAILED;
        }
        unsigned char *destination = (unsigned char *)(aligned + segment->vaddr);
        memcpy(destination, (const unsigned char *)bytes + segment->offset, segment->filesz);
        /* Anonymous pages already contain zeroes, including BSS and padding. */
        int protection = PROT_READ;
        if ((segment->flags & PF_W) != 0U) { protection |= PROT_WRITE; }
        if ((segment->flags & PF_X) != 0U) {
            __builtin___clear_cache((char *)mapped_page,
                                    (char *)mapped_page + segment->page_length);
            protection |= PROT_EXEC;
        }
        if (mprotect(mapped_page, segment->page_length, protection) != 0) {
            int saved_errno = errno;
            sucrune_elf_unload(image);
            errno = saved_errno;
            return SUCRUNE_ELF_PROTECT_FAILED;
        }
        image->segments[index].start = aligned + segment->vaddr;
        image->segments[index].length = segment->memsz;
        image->segments[index].flags = segment->flags;
    }
    return SUCRUNE_ELF_OK;
}

enum sucrune_elf_error sucrune_elf_load(const void *bytes, size_t length,
                                      struct sucrune_elf_image *image) {
    return load(bytes, length, image, 0);
}

enum sucrune_elf_error sucrune_elf_load_program(const void *bytes, size_t length,
                                              struct sucrune_elf_image *image) {
    return load(bytes, length, image, 1);
}

void sucrune_elf_unload(struct sucrune_elf_image *image) {
    if (image == NULL) { return; }
    if (image->reservation != NULL && image->reservation_size != 0U) {
        (void)munmap(image->reservation, image->reservation_size);
    }
    memset(image, 0, sizeof(*image));
}
#endif

int sucrune_elf_readable(const struct sucrune_elf_image *image,
                        uintptr_t address, size_t length) {
    if (image == NULL) { return 0; }
    for (size_t index = 0U; index < image->segment_count; ++index) {
        const struct sucrune_elf_range *range = &image->segments[index];
        if ((range->flags & PF_R) != 0U && address >= range->start &&
            address - range->start <= range->length &&
            length <= range->length - (address - range->start)) { return 1; }
    }
    return 0;
}

const char *sucrune_elf_error_message(enum sucrune_elf_error error) {
    switch (error) {
        case SUCRUNE_ELF_OK: return "ELF accepted";
        case SUCRUNE_ELF_INVALID_ARGUMENT: return "Invalid parser argument or page size";
        case SUCRUNE_ELF_BAD_HEADER: return "Invalid ELF header or program-header metadata";
        case SUCRUNE_ELF_UNSUPPORTED: return "ELF feature is outside the static ARM64 fixture format";
        case SUCRUNE_ELF_BAD_BOUNDS: return "ELF offset, size or segment count exceeds bounds";
        case SUCRUNE_ELF_BAD_ALIGNMENT: return "ELF segment alignment is invalid";
        case SUCRUNE_ELF_BAD_PERMISSIONS: return "ELF requires unsupported memory permissions";
        case SUCRUNE_ELF_OVERLAP: return "ELF load pages overlap or are unordered";
        case SUCRUNE_ELF_BAD_ENTRY: return "ELF entry is not a file-backed ARM64 instruction in executable memory";
        case SUCRUNE_ELF_MAP_FAILED: return "Anonymous image reservation failed";
        case SUCRUNE_ELF_PROTECT_FAILED: return "ELF segment protection change failed";
    }
    return "Unknown ELF loader error";
}
