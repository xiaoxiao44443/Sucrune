#include "elf_loader.h"

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { NEGATIVE_CASES = 26 };

enum { PROGRAM_NEGATIVE_CASES = 28, PROGRAM_TLS_POSITIVE_CASES = 5 };

static unsigned char *make_program_fixture(size_t *length) {
    *length = 16384U + 64U;
    unsigned char *bytes = calloc(*length, 1U);
    if (bytes == NULL) { return NULL; }
    const uint64_t base = 0x10000000U;
    Elf64_Ehdr header = {0};
    memcpy(header.e_ident, ELFMAG, SELFMAG);
    header.e_ident[EI_CLASS] = ELFCLASS64;
    header.e_ident[EI_DATA] = ELFDATA2LSB;
    header.e_ident[EI_VERSION] = EV_CURRENT;
    header.e_machine = EM_AARCH64;
    header.e_type = ET_EXEC;
    header.e_version = EV_CURRENT;
    header.e_entry = base + 512U;
    header.e_phoff = sizeof(header);
    header.e_ehsize = sizeof(header);
    header.e_phentsize = sizeof(Elf64_Phdr);
    header.e_phnum = 6U;
    memcpy(bytes, &header, sizeof(header));
    Elf64_Phdr headers[6] = {0};
    headers[0] = (Elf64_Phdr){ .p_type=PT_LOAD, .p_flags=PF_R|PF_X,
        .p_vaddr=base, .p_filesz=1024U, .p_memsz=1024U, .p_align=16384U };
    headers[1] = (Elf64_Phdr){ .p_type=PT_LOAD, .p_flags=PF_R|PF_W,
        .p_offset=16384U, .p_vaddr=base+16384U, .p_filesz=64U,
        .p_memsz=128U, .p_align=16384U };
    headers[2] = (Elf64_Phdr){ .p_type=PT_TLS, .p_flags=PF_R,
        .p_offset=16400U, .p_vaddr=base+16400U, .p_filesz=8U,
        .p_memsz=24U, .p_align=8U };
    headers[3] = (Elf64_Phdr){ .p_type=PT_GNU_RELRO, .p_flags=PF_R,
        .p_offset=16384U, .p_vaddr=base+16384U, .p_filesz=64U,
        .p_memsz=64U, .p_align=1U };
    headers[4] = (Elf64_Phdr){ .p_type=PT_GNU_STACK, .p_flags=PF_R|PF_W, .p_align=16U };
    headers[5] = (Elf64_Phdr){ .p_type=PT_PHDR, .p_flags=PF_R,
        .p_offset=sizeof(header), .p_vaddr=base+sizeof(header),
        .p_filesz=sizeof(headers), .p_memsz=sizeof(headers), .p_align=8U };
    memcpy(bytes + sizeof(header), headers, sizeof(headers));
    const unsigned char instruction[4] = {0xc0U, 0x03U, 0x5fU, 0xd6U};
    memcpy(bytes + 512U, instruction, sizeof(instruction));
    return bytes;
}

int sucrune_elf_program_selftest(void) {
    size_t length;
    unsigned char *original = make_program_fixture(&length);
    unsigned char *bytes = malloc(length);
    if (original == NULL || bytes == NULL) { free(original); free(bytes); return 0; }
    struct sucrune_elf_plan plan;
    if (sucrune_elf_validate_program(original, length, 4096U, &plan) != SUCRUNE_ELF_OK ||
        sucrune_elf_validate_program(original, length, 16384U, &plan) != SUCRUNE_ELF_OK ||
        plan.virtual_base != 0x10000000U || plan.fixed_address != 1 ||
        plan.entry_offset != 512U || plan.image_size != 32768U ||
        sucrune_elf_validate(original, length, 4096U, &plan) != SUCRUNE_ELF_UNSUPPORTED) {
        free(original); free(bytes); return 0;
    }
    for (size_t page_size = 4096U; page_size <= 16384U; page_size *= 4U) {
        if (sucrune_elf_validate_program(original, length, page_size, &plan) != SUCRUNE_ELF_OK) {
            free(original); free(bytes); return 0;
        }
        const size_t image_size = plan.image_size;
        for (int i = 0; i < PROGRAM_TLS_POSITIVE_CASES; ++i) {
            memcpy(bytes, original, length);
            Elf64_Phdr tls;
            const size_t tls_offset = sizeof(Elf64_Ehdr) + 2U * sizeof(tls);
            memcpy(&tls, bytes + tls_offset, sizeof(tls));
            switch (i) {
                case 0:
                    /* Initialized template stays in LOAD; TBSS extends beyond it. */
                    tls.p_memsz = SUCRUNE_ELF_MAX_IMAGE;
                    break;
                case 1: /* Real linkers may place pure TBSS at the end of RX. */
                    tls.p_vaddr = 0x10000000U + 1024U;
                    tls.p_filesz = 0U;
                    tls.p_offset = UINT64_MAX;
                    break;
                case 2: /* A pure TBSS template needs no readable mapping. */
                    tls.p_vaddr = 0x10000000U + 8192U;
                    tls.p_filesz = 0U;
                    tls.p_offset = UINT64_MAX;
                    break;
                case 3: /* Zero bytes also permit the one-past-image address. */
                    tls.p_vaddr = 0x10000000U + image_size;
                    tls.p_filesz = 0U;
                    tls.p_offset = UINT64_MAX;
                    break;
                case 4: tls.p_type = PT_NULL; break;
                default: free(original); free(bytes); return 0;
            }
            memcpy(bytes + tls_offset, &tls, sizeof(tls));
            if (sucrune_elf_validate_program(bytes, length, page_size, &plan) != SUCRUNE_ELF_OK) {
                free(original); free(bytes); return 0;
            }
        }
    }
    for (int i = 0; i < PROGRAM_NEGATIVE_CASES; ++i) {
        memcpy(bytes, original, length);
        Elf64_Ehdr header;
        Elf64_Phdr phdr[6];
        memcpy(&header, bytes, sizeof(header));
        memcpy(phdr, bytes + sizeof(header), sizeof(phdr));
        enum sucrune_elf_error expected = SUCRUNE_ELF_BAD_BOUNDS;
        switch (i) {
            case 0: header.e_type = ET_DYN; expected = SUCRUNE_ELF_UNSUPPORTED; break;
            case 1: phdr[2].p_type = PT_INTERP; expected = SUCRUNE_ELF_UNSUPPORTED; break;
            case 2: phdr[2].p_type = PT_DYNAMIC; expected = SUCRUNE_ELF_UNSUPPORTED; break;
            case 3: phdr[2].p_filesz = 25U; break;
            case 4: phdr[2].p_vaddr += 16384U; break;
            case 5: phdr[2].p_offset += 8U; break;
            case 6: phdr[3] = phdr[2]; expected = SUCRUNE_ELF_BAD_HEADER; break;
            case 7: phdr[3].p_memsz = 129U; break;
            case 8: phdr[0].p_vaddr = 0U; break;
            case 9: phdr[1].p_vaddr = UINT64_MAX; break;
            case 10: phdr[1].p_vaddr = phdr[0].p_vaddr; expected = SUCRUNE_ELF_OVERLAP; break;
            case 11: phdr[1].p_flags |= PF_X; expected = SUCRUNE_ELF_BAD_PERMISSIONS; break;
            case 12: phdr[2].p_align = 3U; expected = SUCRUNE_ELF_BAD_ALIGNMENT; break;
            case 13: header.e_entry = phdr[1].p_vaddr; expected = SUCRUNE_ELF_BAD_ENTRY; break;
            case 14: phdr[5].p_vaddr += 8U; expected = SUCRUNE_ELF_BAD_HEADER; break;
            case 15: phdr[2].p_vaddr -= 1U; expected = SUCRUNE_ELF_BAD_ALIGNMENT; break;
            case 16: phdr[4].p_flags |= PF_X; expected = SUCRUNE_ELF_BAD_PERMISSIONS; break;
            case 17: phdr[3].p_flags |= PF_X; expected = SUCRUNE_ELF_BAD_PERMISSIONS; break;
            case 18: phdr[2].p_offset = UINT64_MAX; break;
            case 19: header.e_entry = UINT64_MAX; expected = SUCRUNE_ELF_BAD_ENTRY; break;
            case 20: phdr[2].p_memsz = (uint64_t)SUCRUNE_ELF_MAX_IMAGE + 1U; break;
            case 21: phdr[2].p_align = 0U; expected = SUCRUNE_ELF_BAD_ALIGNMENT; break;
            case 22:
                phdr[2].p_align = (uint64_t)SUCRUNE_ELF_MAX_IMAGE * 2U;
                expected = SUCRUNE_ELF_BAD_ALIGNMENT;
                break;
            case 23: /* Template is file-bounded but crosses the LOAD template end. */
                phdr[2].p_vaddr = phdr[0].p_vaddr + 1016U;
                phdr[2].p_offset = 1016U;
                phdr[2].p_filesz = 16U;
                break;
            case 24: /* Readable LOAD BSS is not an initialized file template. */
                phdr[0].p_memsz = 2048U;
                phdr[2].p_vaddr = phdr[0].p_vaddr + 1024U;
                phdr[2].p_offset = 1024U;
                break;
            case 25:
                phdr[2].p_filesz = 0U;
                phdr[2].p_vaddr = phdr[0].p_vaddr + 32776U;
                break;
            case 26:
                phdr[2].p_filesz = 0U;
                phdr[2].p_vaddr = phdr[0].p_vaddr - 8U;
                break;
            case 27:
                phdr[2].p_filesz = 0U;
                phdr[2].p_memsz = (uint64_t)SUCRUNE_ELF_MAX_IMAGE + 1U;
                break;
            default: free(original); free(bytes); return 0;
        }
        memcpy(bytes, &header, sizeof(header));
        memcpy(bytes + sizeof(header), phdr, sizeof(phdr));
        if (sucrune_elf_validate_program(bytes, length, 4096U, &plan) != expected ||
            sucrune_elf_validate_program(bytes, length, 16384U, &plan) != expected) {
            free(original); free(bytes); return 0;
        }
    }
    free(original); free(bytes);
    return PROGRAM_NEGATIVE_CASES;
}

int sucrune_elf_selftest(const void *input, size_t length) {
    struct sucrune_elf_plan plan;
    /* Both supported page layouts must accept the unmodified fixture. */
    if (sucrune_elf_validate(input, length, 4096U, &plan) != SUCRUNE_ELF_OK ||
        sucrune_elf_validate(input, length, 16384U, &plan) != SUCRUNE_ELF_OK) {
        return 0;
    }
    const unsigned char *bytes = input;
    Elf64_Ehdr original;
    memcpy(&original, bytes, sizeof(original));
    size_t first_load = SIZE_MAX;
    size_t second_load = SIZE_MAX;
    size_t stack_header = SIZE_MAX;
    for (size_t index = 0U; index < original.e_phnum; ++index) {
        Elf64_Phdr phdr;
        memcpy(&phdr, bytes + (size_t)original.e_phoff + index * sizeof(phdr), sizeof(phdr));
        if (phdr.p_type == PT_LOAD) {
            if (first_load == SIZE_MAX) { first_load = index; }
            else if (second_load == SIZE_MAX) { second_load = index; }
        }
        if (phdr.p_type == PT_GNU_STACK) { stack_header = index; }
    }
    if (first_load == SIZE_MAX || second_load == SIZE_MAX || stack_header == SIZE_MAX) {
        return 0;
    }
    unsigned char *mutated = malloc(length);
    if (mutated == NULL) { return 0; }
    for (int test = 0; test < NEGATIVE_CASES; ++test) {
        memcpy(mutated, bytes, length);
        Elf64_Ehdr header = original;
        Elf64_Phdr phdr;
        size_t target = first_load;
        size_t test_length = length;
        size_t test_page_size = 4096U;
        enum sucrune_elf_error expected = SUCRUNE_ELF_BAD_HEADER;
        memcpy(&phdr, mutated + (size_t)original.e_phoff + target * sizeof(phdr), sizeof(phdr));
        switch (test) {
            case 0:
                test_length = sizeof(Elf64_Ehdr) - 1U;
                expected = SUCRUNE_ELF_BAD_BOUNDS;
                break;
            case 1: header.e_ident[EI_MAG0] = 0U; break;
            case 2: header.e_ident[EI_CLASS] = ELFCLASS32; break;
            case 3: header.e_ident[EI_DATA] = ELFDATA2MSB; break;
            case 4:
                header.e_machine = EM_X86_64;
                expected = SUCRUNE_ELF_UNSUPPORTED;
                break;
            case 5:
                header.e_type = ET_EXEC;
                expected = SUCRUNE_ELF_UNSUPPORTED;
                break;
            case 6:
                header.e_phoff = UINT64_MAX;
                expected = SUCRUNE_ELF_BAD_BOUNDS;
                break;
            case 7: header.e_phnum = 0U; break;
            case 8: header.e_phentsize = 1U; break;
            case 9:
                phdr.p_memsz = phdr.p_filesz - 1U;
                expected = SUCRUNE_ELF_BAD_BOUNDS;
                break;
            case 10:
                phdr.p_offset = UINT64_MAX;
                expected = SUCRUNE_ELF_BAD_BOUNDS;
                break;
            case 11:
                phdr.p_vaddr = UINT64_MAX;
                expected = SUCRUNE_ELF_BAD_BOUNDS;
                break;
            case 12:
                phdr.p_memsz = (uint64_t)SUCRUNE_ELF_MAX_IMAGE + 1U;
                expected = SUCRUNE_ELF_BAD_BOUNDS;
                break;
            case 13:
                phdr.p_align = 3U;
                expected = SUCRUNE_ELF_BAD_ALIGNMENT;
                break;
            case 14:
                phdr.p_flags = PF_R | PF_W | PF_X;
                expected = SUCRUNE_ELF_BAD_PERMISSIONS;
                break;
            case 15: {
                Elf64_Phdr data;
                memcpy(&data, mutated + (size_t)original.e_phoff + second_load * sizeof(data), sizeof(data));
                header.e_entry = data.p_vaddr;
                expected = SUCRUNE_ELF_BAD_ENTRY;
                break;
            }
            case 16:
                header.e_entry = original.e_entry + 1U;
                expected = SUCRUNE_ELF_BAD_ENTRY;
                break;
            case 17:
                header.e_entry = UINT64_MAX;
                expected = SUCRUNE_ELF_BAD_ENTRY;
                break;
            case 18:
                phdr.p_type = PT_INTERP;
                expected = SUCRUNE_ELF_UNSUPPORTED;
                break;
            case 19:
                phdr.p_type = PT_DYNAMIC;
                expected = SUCRUNE_ELF_UNSUPPORTED;
                break;
            case 20:
                phdr.p_type = PT_TLS;
                expected = SUCRUNE_ELF_UNSUPPORTED;
                break;
            case 21:
                target = stack_header;
                memcpy(&phdr, mutated + (size_t)original.e_phoff + target * sizeof(phdr), sizeof(phdr));
                phdr.p_flags |= PF_X;
                expected = SUCRUNE_ELF_BAD_PERMISSIONS;
                break;
            case 22:
                target = second_load;
                memcpy(&phdr, mutated + (size_t)original.e_phoff + target * sizeof(phdr), sizeof(phdr));
                phdr.p_vaddr = 0U;
                expected = SUCRUNE_ELF_OVERLAP;
                break;
            case 23:
                phdr.p_vaddr += 1U;
                expected = SUCRUNE_ELF_BAD_ALIGNMENT;
                break;
            case 24:
                header.e_shoff = UINT64_MAX;
                header.e_shnum = 1U;
                header.e_shentsize = sizeof(Elf64_Shdr);
                header.e_shstrndx = SHN_UNDEF;
                expected = SUCRUNE_ELF_BAD_BOUNDS;
                break;
            case 25:
                test_page_size = 8192U;
                expected = SUCRUNE_ELF_INVALID_ARGUMENT;
                break;
            default: free(mutated); return 0;
        }
        memcpy(mutated, &header, sizeof(header));
        /* Use original metadata to write the mutation, even for bad e_phoff. */
        memcpy(mutated + (size_t)original.e_phoff + target * sizeof(phdr), &phdr, sizeof(phdr));
        if (sucrune_elf_validate(mutated, test_length, test_page_size, &plan) != expected) {
            free(mutated);
            return 0;
        }
    }
    free(mutated);
    return NEGATIVE_CASES;
}

#ifdef SUCRUNE_ELF_TEST_MAIN
static unsigned char *make_test_fixture(size_t *length) {
    *length = 16384U + 8U;
    unsigned char *bytes = calloc(*length, 1U);
    if (bytes == NULL) { return NULL; }
    Elf64_Ehdr header = {0};
    memcpy(header.e_ident, ELFMAG, SELFMAG);
    header.e_ident[EI_CLASS] = ELFCLASS64;
    header.e_ident[EI_DATA] = ELFDATA2LSB;
    header.e_ident[EI_VERSION] = EV_CURRENT;
    header.e_machine = EM_AARCH64;
    header.e_type = ET_DYN;
    header.e_version = EV_CURRENT;
    header.e_entry = 256U;
    header.e_phoff = sizeof(header);
    header.e_ehsize = sizeof(header);
    header.e_phentsize = sizeof(Elf64_Phdr);
    header.e_phnum = 3U;
    memcpy(bytes, &header, sizeof(header));
    Elf64_Phdr headers[3] = {0};
    headers[0].p_type = PT_LOAD;
    headers[0].p_flags = PF_R | PF_X;
    headers[0].p_filesz = 260U;
    headers[0].p_memsz = 260U;
    headers[0].p_align = 16384U;
    headers[1].p_type = PT_LOAD;
    headers[1].p_flags = PF_R | PF_W;
    headers[1].p_offset = 16384U;
    headers[1].p_vaddr = 16384U;
    headers[1].p_filesz = 8U;
    headers[1].p_memsz = 24U;
    headers[1].p_align = 16384U;
    headers[2].p_type = PT_GNU_STACK;
    headers[2].p_flags = PF_R | PF_W;
    headers[2].p_align = 16U;
    memcpy(bytes + sizeof(header), headers, sizeof(headers));
    /* ARM64 ret, never executed by these parser tests. */
    const unsigned char instruction[4] = {0xc0U, 0x03U, 0x5fU, 0xd6U};
    memcpy(bytes + 256U, instruction, sizeof(instruction));
    return bytes;
}

int main(int argc, char **argv) {
    int program = argc == 3 && strcmp(argv[1], "--program") == 0;
    if (argc != 1 && argc != 2 && program == 0) {
        fputs("usage: elf_loader_tests [ELF_FIXTURE | --program STATIC_ELF]\n", stderr);
        return 1;
    }
    size_t length = 0U;
    unsigned char *bytes;
    if (argc == 1) {
        bytes = make_test_fixture(&length);
    } else {
        FILE *file = fopen(argv[program != 0 ? 2 : 1], "rb");
        if (file == NULL) { return 1; }
        if (fseek(file, 0L, SEEK_END) != 0) { (void)fclose(file); return 1; }
        long file_size = ftell(file);
        if (file_size <= 0L || (unsigned long)file_size > SUCRUNE_ELF_MAX_IMAGE ||
            fseek(file, 0L, SEEK_SET) != 0) { (void)fclose(file); return 1; }
        length = (size_t)file_size;
        bytes = malloc(length);
        if (bytes == NULL) { (void)fclose(file); return 1; }
        size_t read_size = fread(bytes, 1U, length, file);
        (void)fclose(file);
        if (read_size != length) { free(bytes); return 1; }
    }
    if (bytes == NULL) { return 1; }
    if (program != 0) {
        struct sucrune_elf_plan plan;
        enum sucrune_elf_error error4 = sucrune_elf_validate_program(bytes, length, 4096U, &plan);
        enum sucrune_elf_error error16 = sucrune_elf_validate_program(bytes, length, 16384U, &plan);
        free(bytes);
        int passed = sucrune_elf_program_selftest();
        if (error4 != SUCRUNE_ELF_OK || error16 != SUCRUNE_ELF_OK || passed != PROGRAM_NEGATIVE_CASES) {
            fprintf(stderr, "Static-program check failed: 4K=%s, 16K=%s, mutations=%d\n",
                    sucrune_elf_error_message(error4), sucrune_elf_error_message(error16), passed);
            return 1;
        }
        printf("Static ELF: 4/16 KiB accepted, base=%llx, span=%zu, %d mutations rejected\n",
               (unsigned long long)plan.virtual_base, plan.image_size, passed);
        return 0;
    }
    int passed = sucrune_elf_selftest(bytes, length);
    free(bytes);
    if (passed != NEGATIVE_CASES) { fputs("ELF parser regression failed\n", stderr); return 1; }
    if (sucrune_elf_program_selftest() != PROGRAM_NEGATIVE_CASES) {
        fputs("Static-program ELF parser regression failed\n", stderr); return 1;
    }
    printf("ELF parser: valid 4/16 KiB layouts and %d rejection cases passed\n", passed);
    printf("Static-program ELF parser: valid 4/16 KiB layouts and %d rejection cases passed\n", PROGRAM_NEGATIVE_CASES);
    return 0;
}
#endif
