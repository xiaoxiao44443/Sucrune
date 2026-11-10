/* Pure Linux-profile ELF parser tests. They never map/execute guest images.
 * Usage: linux-loader-tests <hello> <ld.so> <libc.so.6> <node>
 * Actual Android execution and dynamic linker behavior need separate tests. */
#include "linux_elf.h"
#include "guest_shebang.h"
#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define FIXTURE_SIZE 0x5000U
#define HEADERS 8U
#define CHECK(value) do { if (!(value)) { \
    (void)fprintf(stderr, "linux_loader_tests.c:%d: %s\n", __LINE__, #value); exit(1); \
} } while (0)

static unsigned int real_cases, positive_cases, negative_cases;

static void header_get(const unsigned char *bytes, Elf64_Ehdr *header) {
    memcpy(header, bytes, sizeof(*header));
}
static void header_set(unsigned char *bytes, const Elf64_Ehdr *header) {
    memcpy(bytes, header, sizeof(*header));
}
static void segment_get(const unsigned char *bytes, size_t index, Elf64_Phdr *header) {
    memcpy(header, bytes + sizeof(Elf64_Ehdr) + index * sizeof(*header), sizeof(*header));
}
static void segment_set(unsigned char *bytes, size_t index, const Elf64_Phdr *header) {
    memcpy(bytes + sizeof(Elf64_Ehdr) + index * sizeof(*header), header, sizeof(*header));
}
static void fixture(unsigned char *bytes) {
    memset(bytes, 0, FIXTURE_SIZE);
    Elf64_Ehdr h = {0};
    memcpy(h.e_ident, ELFMAG, SELFMAG);
    h.e_ident[EI_CLASS] = ELFCLASS64; h.e_ident[EI_DATA] = ELFDATA2LSB;
    h.e_ident[EI_VERSION] = EV_CURRENT; h.e_type = ET_DYN; h.e_machine = EM_AARCH64;
    h.e_version = EV_CURRENT; h.e_entry = 0x800U; h.e_ehsize = sizeof(h);
    h.e_phoff = sizeof(h); h.e_phentsize = sizeof(Elf64_Phdr); h.e_phnum = HEADERS;
    header_set(bytes, &h);
    Elf64_Phdr p = {.p_type=PT_LOAD, .p_flags=PF_R|PF_X, .p_filesz=0x1000U, .p_memsz=0x1000U, .p_align=0x4000U};
    segment_set(bytes, 0U, &p);
    p = (Elf64_Phdr){.p_type=PT_LOAD, .p_flags=PF_R|PF_W, .p_offset=0x4000U, .p_vaddr=0x4000U,
                    .p_filesz=0x1000U, .p_memsz=0x2000U, .p_align=0x4000U};
    segment_set(bytes, 1U, &p);
    const char interpreter[] = "/lib/test-ld.so";
    memcpy(bytes + 0x400U, interpreter, sizeof(interpreter));
    p = (Elf64_Phdr){.p_type=PT_INTERP, .p_flags=PF_R, .p_offset=0x400U, .p_vaddr=0x400U,
                    .p_filesz=sizeof(interpreter), .p_memsz=sizeof(interpreter), .p_align=1U};
    segment_set(bytes, 2U, &p);
    p = (Elf64_Phdr){.p_type=PT_DYNAMIC, .p_flags=PF_R|PF_W, .p_offset=0x4100U, .p_vaddr=0x4100U,
                    .p_filesz=2U*sizeof(Elf64_Dyn), .p_memsz=2U*sizeof(Elf64_Dyn), .p_align=8U};
    segment_set(bytes, 3U, &p);
    p = (Elf64_Phdr){.p_type=PT_TLS, .p_flags=PF_R, .p_offset=0x4200U, .p_vaddr=0x4200U,
                    .p_filesz=8U, .p_memsz=32U, .p_align=16U};
    segment_set(bytes, 4U, &p);
    p = (Elf64_Phdr){.p_type=PT_PHDR, .p_flags=PF_R, .p_offset=sizeof(h), .p_vaddr=sizeof(h),
                    .p_filesz=HEADERS*sizeof(Elf64_Phdr), .p_memsz=HEADERS*sizeof(Elf64_Phdr), .p_align=8U};
    segment_set(bytes, 5U, &p);
    p = (Elf64_Phdr){.p_type=PT_GNU_STACK, .p_flags=PF_R|PF_W, .p_align=16U};
    segment_set(bytes, 6U, &p);
    p = (Elf64_Phdr){.p_type=PT_NOTE, .p_flags=PF_R, .p_offset=0x600U, .p_vaddr=0x600U,
                    .p_filesz=16U, .p_memsz=16U, .p_align=4U};
    segment_set(bytes, 7U, &p);
}

static void valid(const unsigned char *bytes, size_t size, size_t page, int fixed, int interpreter) {
    struct sucrune_linux_plan plan;
    enum sucrune_elf_error error = sucrune_linux_validate(bytes, size, page, &plan);
    if (error != SUCRUNE_ELF_OK) (void)fprintf(stderr, "Unexpected valid-image rejection %d (page=%zu)\n", (int)error, page);
    CHECK(error == SUCRUNE_ELF_OK);
    CHECK(plan.load.page_size == page && plan.load.fixed_address == fixed);
    CHECK(plan.load.phdr_mapped && plan.load.phdr_offset < plan.load.image_size);
    CHECK(plan.load.entry_offset < plan.load.image_size && plan.load.segment_count > 0U);
    CHECK(plan.load.image_size % page == 0U && plan.load.alignment >= page);
    CHECK((plan.interpreter[0] != '\0') == interpreter);
    for (size_t i = 0; i < plan.load.segment_count; i++) {
        const struct sucrune_elf_segment *s = &plan.load.segments[i];
        CHECK(s->page_offset % page == 0U && s->page_length % page == 0U);
        CHECK(s->page_offset <= s->vaddr && s->vaddr - s->page_offset <= s->offset);
        CHECK(s->filesz <= s->memsz && s->offset <= size && s->filesz <= size - s->offset);
        CHECK(s->page_offset <= plan.load.image_size && s->page_length <= plan.load.image_size - s->page_offset);
    }
}

static void real_file(const char *path, const char *name, int fixed, int interpreter) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0);
    struct stat info;
    CHECK(fstat(fd, &info) == 0 && info.st_size > 0 && info.st_size <= SUCRUNE_LINUX_MAX_FILE);
    size_t length = (size_t)info.st_size;
    void *bytes = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, 0);
    CHECK(bytes != MAP_FAILED);
    valid(bytes, length, 4096U, fixed, interpreter); real_cases++;
    valid(bytes, length, 16384U, fixed, interpreter); real_cases++;
    struct sucrune_linux_plan plan;
    CHECK(sucrune_linux_validate(bytes, length, 4096U, &plan) == SUCRUNE_ELF_OK);
    CHECK(plan.has_dynamic);
    if (strcmp(name, "node") == 0) CHECK(length > 100U*1024U*1024U && plan.load.image_size > 16U*1024U*1024U);
    (void)printf("real=%s pages=4096,16384 bytes=%zu image=%zu loads=%zu base=0x%llx dynamic=%d interpreter=%s\n",
        name, length, plan.load.image_size, plan.load.segment_count,
        (unsigned long long)plan.load.virtual_base, plan.has_dynamic, plan.interpreter);
    CHECK(munmap(bytes, length) == 0 && close(fd) == 0);
}

enum mutation {
    BAD_MAGIC, BAD_CLASS, BAD_ENDIAN, BAD_IDENT_VERSION, BAD_VERSION, BAD_EHSIZE,
    BAD_PHENTSIZE, NO_PHDRS, TOO_MANY_PHDRS, EARLY_PHDRS, OVERFLOW_PHDRS, TRUNCATED_PHDRS,
    BAD_MACHINE, BAD_TYPE, BAD_FLAGS, BAD_ABIVERSION, BAD_OSABI, RELATIVE_INTERP,
    UNTERMINATED_INTERP, EMBEDDED_INTERP_NUL, SHORT_INTERP, LONG_INTERP, INTERP_BOUNDS,
    DUP_INTERP, DUP_DYNAMIC, DUP_TLS, DUP_PHDR, DYNAMIC_FILES_GT_MEM, DYNAMIC_OUTSIDE,
    DYNAMIC_OFFSET, DYNAMIC_ALIGNMENT, TLS_OUTSIDE, TLS_FILES_GT_MEM, TLS_OFFSET,
    PHDR_OFFSET, PHDR_ADDRESS, PHDR_SIZE, PHDR_UNMAPPED, EXEC_STACK, UNKNOWN_SEGMENT,
    LOAD_FILES_GT_MEM, LOAD_BOUNDS, LOAD_ADDRESS_HIGH, LOAD_SIZE_HIGH, LOAD_ADDRESS_OVERFLOW,
    LOAD_WX, LOAD_NO_READ, LOAD_UNKNOWN_FLAGS, LOAD_ALIGNMENT_ODD, LOAD_ALIGNMENT_HIGH,
    LOAD_ALIGNMENT_MISMATCH, LOAD_PAGE_OVERLAP, LOAD_REVERSED, NO_LOADS, EMPTY_LOADS,
    ENTRY_DATA, ENTRY_UNALIGNED, ENTRY_OUTSIDE, ENTRY_AT_FILE_END, FIXED_LOW_ADDRESS,
    MUTATION_COUNT
};

static void mutate(unsigned char *bytes, enum mutation change) {
    Elf64_Ehdr h; Elf64_Phdr p, other;
    header_get(bytes, &h);
    switch (change) {
        case BAD_MAGIC: h.e_ident[0]=0; break;
        case BAD_CLASS: h.e_ident[EI_CLASS]=ELFCLASS32; break;
        case BAD_ENDIAN: h.e_ident[EI_DATA]=ELFDATA2MSB; break;
        case BAD_IDENT_VERSION: h.e_ident[EI_VERSION]=0; break;
        case BAD_VERSION: h.e_version=0; break;
        case BAD_EHSIZE: h.e_ehsize=0; break;
        case BAD_PHENTSIZE: h.e_phentsize=1; break;
        case NO_PHDRS: h.e_phnum=0; break;
        case TOO_MANY_PHDRS: h.e_phnum=SUCRUNE_ELF_MAX_PHDRS+1U; break;
        case EARLY_PHDRS: h.e_phoff=0; break;
        case OVERFLOW_PHDRS: h.e_phoff=UINT64_MAX-2U; break;
        case TRUNCATED_PHDRS: h.e_phoff=FIXTURE_SIZE-1U; break;
        case BAD_MACHINE: h.e_machine=EM_X86_64; break;
        case BAD_TYPE: h.e_type=ET_REL; break;
        case BAD_FLAGS: h.e_flags=1U; break;
        case BAD_ABIVERSION: h.e_ident[EI_ABIVERSION]=1U; break;
        case BAD_OSABI: h.e_ident[EI_OSABI]=255U; break;
        case RELATIVE_INTERP: bytes[0x400U]='r'; break;
        case UNTERMINATED_INTERP: segment_get(bytes,2U,&p); bytes[0x400U+p.p_filesz-1U]='x'; break;
        case EMBEDDED_INTERP_NUL: bytes[0x402U]=0; break;
        case SHORT_INTERP: segment_get(bytes,2U,&p); p.p_filesz=1U; segment_set(bytes,2U,&p); break;
        case LONG_INTERP: segment_get(bytes,2U,&p); p.p_filesz=SUCRUNE_LINUX_INTERPRETER+1U; segment_set(bytes,2U,&p); break;
        case INTERP_BOUNDS: segment_get(bytes,2U,&p); p.p_offset=UINT64_MAX; segment_set(bytes,2U,&p); break;
        case DUP_INTERP: segment_get(bytes,2U,&p); segment_set(bytes,7U,&p); break;
        case DUP_DYNAMIC: segment_get(bytes,3U,&p); segment_set(bytes,7U,&p); break;
        case DUP_TLS: segment_get(bytes,4U,&p); segment_set(bytes,7U,&p); break;
        case DUP_PHDR: segment_get(bytes,5U,&p); segment_set(bytes,7U,&p); break;
        case DYNAMIC_FILES_GT_MEM: segment_get(bytes,3U,&p); p.p_memsz=1U; segment_set(bytes,3U,&p); break;
        case DYNAMIC_OUTSIDE: segment_get(bytes,3U,&p); p.p_vaddr=0x9000U; segment_set(bytes,3U,&p); break;
        case DYNAMIC_OFFSET: segment_get(bytes,3U,&p); p.p_offset++; segment_set(bytes,3U,&p); break;
        case DYNAMIC_ALIGNMENT: segment_get(bytes,3U,&p); p.p_align=3U; segment_set(bytes,3U,&p); break;
        case TLS_OUTSIDE: segment_get(bytes,4U,&p); p.p_vaddr=UINT64_MAX; segment_set(bytes,4U,&p); break;
        case TLS_FILES_GT_MEM: segment_get(bytes,4U,&p); p.p_memsz=1U; segment_set(bytes,4U,&p); break;
        case TLS_OFFSET: segment_get(bytes,4U,&p); p.p_offset++; segment_set(bytes,4U,&p); break;
        case PHDR_OFFSET: segment_get(bytes,5U,&p); p.p_offset++; segment_set(bytes,5U,&p); break;
        case PHDR_ADDRESS: segment_get(bytes,5U,&p); p.p_vaddr++; segment_set(bytes,5U,&p); break;
        case PHDR_SIZE: segment_get(bytes,5U,&p); p.p_filesz--; segment_set(bytes,5U,&p); break;
        case PHDR_UNMAPPED:
            memcpy(bytes+0x1000U,bytes+sizeof(h),HEADERS*sizeof(Elf64_Phdr)); h.e_phoff=0x1000U; break;
        case EXEC_STACK: segment_get(bytes,6U,&p); p.p_flags|=PF_X; segment_set(bytes,6U,&p); break;
        case UNKNOWN_SEGMENT: segment_get(bytes,7U,&p); p.p_type=0x12345678U; segment_set(bytes,7U,&p); break;
        case LOAD_FILES_GT_MEM: segment_get(bytes,1U,&p); p.p_memsz=1U; segment_set(bytes,1U,&p); break;
        case LOAD_BOUNDS: segment_get(bytes,1U,&p); p.p_offset=UINT64_MAX; segment_set(bytes,1U,&p); break;
        case LOAD_ADDRESS_HIGH: segment_get(bytes,1U,&p); p.p_vaddr=SUCRUNE_LINUX_MAX_IMAGE+0x4000ULL; segment_set(bytes,1U,&p); break;
        case LOAD_SIZE_HIGH: segment_get(bytes,1U,&p); p.p_memsz=SUCRUNE_LINUX_MAX_IMAGE+1ULL; segment_set(bytes,1U,&p); break;
        case LOAD_ADDRESS_OVERFLOW: segment_get(bytes,0U,&p); p.p_vaddr=UINT64_MAX-0xfffU; p.p_memsz=0x2000U; segment_set(bytes,0U,&p); break;
        case LOAD_WX: segment_get(bytes,0U,&p); p.p_flags|=PF_W; segment_set(bytes,0U,&p); break;
        case LOAD_NO_READ: segment_get(bytes,0U,&p); p.p_flags=PF_X; segment_set(bytes,0U,&p); break;
        case LOAD_UNKNOWN_FLAGS: segment_get(bytes,0U,&p); p.p_flags|=0x80U; segment_set(bytes,0U,&p); break;
        case LOAD_ALIGNMENT_ODD: segment_get(bytes,0U,&p); p.p_align=3U; segment_set(bytes,0U,&p); break;
        case LOAD_ALIGNMENT_HIGH: segment_get(bytes,0U,&p); p.p_align=2ULL*SUCRUNE_LINUX_MAX_IMAGE; segment_set(bytes,0U,&p); break;
        case LOAD_ALIGNMENT_MISMATCH: segment_get(bytes,1U,&p); p.p_offset++; segment_set(bytes,1U,&p); break;
        case LOAD_PAGE_OVERLAP: segment_get(bytes,1U,&p); p.p_vaddr=0x800U; p.p_offset=0x800U; segment_set(bytes,1U,&p); break;
        case LOAD_REVERSED: segment_get(bytes,0U,&p); segment_get(bytes,1U,&other); segment_set(bytes,0U,&other); segment_set(bytes,1U,&p); break;
        case NO_LOADS: for(size_t i=0;i<2U;i++){segment_get(bytes,i,&p);p.p_type=PT_NULL;segment_set(bytes,i,&p);} break;
        case EMPTY_LOADS: for(size_t i=0;i<2U;i++){segment_get(bytes,i,&p);p.p_memsz=0;p.p_filesz=0;segment_set(bytes,i,&p);} break;
        case ENTRY_DATA: h.e_entry=0x4000U; break;
        case ENTRY_UNALIGNED: h.e_entry++; break;
        case ENTRY_OUTSIDE: h.e_entry=UINT64_MAX; break;
        case ENTRY_AT_FILE_END: h.e_entry=0x1000U; break;
        case FIXED_LOW_ADDRESS: h.e_type=ET_EXEC; break;
        case MUTATION_COUNT: CHECK(0); break;
    }
    header_set(bytes,&h);
}

static void synthetic_tests(void) {
    unsigned char *bytes = malloc(FIXTURE_SIZE);
    CHECK(bytes != NULL);
    const size_t pages[] = {4096U,16384U};
    for(size_t page_index=0;page_index<2U;page_index++) {
        size_t page=pages[page_index];
        fixture(bytes); valid(bytes,FIXTURE_SIZE,page,0,1); positive_cases++;
        Elf64_Phdr p; segment_get(bytes,4U,&p); p.p_filesz=0; p.p_offset=UINT64_MAX;
        segment_set(bytes,4U,&p); valid(bytes,FIXTURE_SIZE,page,0,1); positive_cases++;
        fixture(bytes); segment_get(bytes,5U,&p); p.p_type=PT_NULL; segment_set(bytes,5U,&p);
        valid(bytes,FIXTURE_SIZE,page,0,1); positive_cases++;
        fixture(bytes); Elf64_Ehdr h; header_get(bytes,&h); h.e_shoff=UINT64_MAX; h.e_shnum=65535U;
        header_set(bytes,&h); valid(bytes,FIXTURE_SIZE,page,0,1); positive_cases++;
        fixture(bytes); header_get(bytes,&h); h.e_type=ET_EXEC; h.e_entry+=0x20000000U;
        header_set(bytes,&h);
        for(size_t i=0;i<HEADERS;i++){segment_get(bytes,i,&p); if(p.p_type!=PT_GNU_STACK){p.p_vaddr+=0x20000000U;}segment_set(bytes,i,&p);}
        valid(bytes,FIXTURE_SIZE,page,1,1); positive_cases++;
        fixture(bytes); segment_get(bytes,2U,&p); p.p_type=PT_NULL; segment_set(bytes,2U,&p);
        valid(bytes,FIXTURE_SIZE,page,0,0); positive_cases++;
        /* lld's padded PT_GNU_RELRO in the ARM64 ripgrep release. */
        fixture(bytes); segment_get(bytes,1U,&p); p.p_memsz=0x1100U; segment_set(bytes,1U,&p);
        size_t end=(0x5100U+page-1U)&~(page-1U);
        p=(Elf64_Phdr){.p_type=PT_GNU_RELRO,.p_flags=PF_R,.p_offset=0x4800U,.p_vaddr=0x4800U,
                      .p_filesz=0x800U,.p_memsz=end-0x4800U,.p_align=1U};
        segment_set(bytes,7U,&p); valid(bytes,FIXTURE_SIZE,page,0,1); positive_cases++;
        struct sucrune_linux_plan relro;
        p.p_memsz++; segment_set(bytes,7U,&p);
        CHECK(sucrune_linux_validate(bytes,FIXTURE_SIZE,page,&relro)==SUCRUNE_ELF_BAD_BOUNDS); negative_cases++;
        p.p_memsz--; p.p_filesz++; segment_set(bytes,7U,&p);
        CHECK(sucrune_linux_validate(bytes,FIXTURE_SIZE,page,&relro)==SUCRUNE_ELF_BAD_BOUNDS); negative_cases++;
        p.p_filesz--; p.p_offset++; segment_set(bytes,7U,&p);
        CHECK(sucrune_linux_validate(bytes,FIXTURE_SIZE,page,&relro)==SUCRUNE_ELF_BAD_BOUNDS); negative_cases++;
        /* The allowed load/header maxima must work, not only reject overflow. */
        fixture(bytes); header_get(bytes,&h); h.e_phnum=SUCRUNE_ELF_MAX_PHDRS;
        header_set(bytes,&h);
        memset(bytes+sizeof(h),0,SUCRUNE_ELF_MAX_PHDRS*sizeof(Elf64_Phdr));
        for(size_t i=0;i<SUCRUNE_ELF_MAX_LOADS;i++) {
            p=(Elf64_Phdr){.p_type=PT_LOAD,.p_flags=i==0U ? PF_R|PF_X : PF_R,
                .p_vaddr=i*0x4000U,.p_filesz=i==0U ? 0x1000U : 0U,.p_memsz=0x1000U,.p_align=0x4000U};
            segment_set(bytes,i,&p);
        }
        valid(bytes,FIXTURE_SIZE,page,0,0); positive_cases++;
        p=(Elf64_Phdr){.p_type=PT_LOAD,.p_flags=PF_R,.p_vaddr=SUCRUNE_ELF_MAX_LOADS*0x4000U,
            .p_memsz=0x1000U,.p_align=0x4000U};
        segment_set(bytes,SUCRUNE_ELF_MAX_LOADS,&p);
        struct sucrune_linux_plan limit_plan;
        CHECK(sucrune_linux_validate(bytes,FIXTURE_SIZE,page,&limit_plan)==SUCRUNE_ELF_BAD_BOUNDS); negative_cases++;
        /* A sparse plan may span exactly 1 GiB without allocating that space. */
        fixture(bytes); header_get(bytes,&h); h.e_phnum=2U; header_set(bytes,&h);
        segment_get(bytes,1U,&p); p.p_vaddr=SUCRUNE_LINUX_MAX_IMAGE-0x4000U;
        p.p_offset=0U; p.p_filesz=0U; p.p_memsz=0x4000U; segment_set(bytes,1U,&p);
        valid(bytes,FIXTURE_SIZE,page,0,0); positive_cases++;
        CHECK(sucrune_linux_validate(bytes,FIXTURE_SIZE,page,&limit_plan)==SUCRUNE_ELF_OK);
        CHECK(limit_plan.load.image_size==SUCRUNE_LINUX_MAX_IMAGE);
        for(int change=0;change<MUTATION_COUNT;change++) {
            fixture(bytes); mutate(bytes,(enum mutation)change);
            struct sucrune_linux_plan plan;
            enum sucrune_elf_error error=sucrune_linux_validate(bytes,FIXTURE_SIZE,page,&plan);
            if(error==SUCRUNE_ELF_OK) (void)fprintf(stderr,"Unexpected mutation acceptance: %d page=%zu\n",change,page);
            CHECK(error!=SUCRUNE_ELF_OK); negative_cases++;
        }
        fixture(bytes); struct sucrune_linux_plan plan;
        CHECK(sucrune_linux_validate(bytes,sizeof(Elf64_Ehdr)-1U,page,&plan)==SUCRUNE_ELF_BAD_BOUNDS); negative_cases++;
        CHECK(sucrune_linux_validate(bytes,(size_t)SUCRUNE_LINUX_MAX_FILE+1U,page,&plan)==SUCRUNE_ELF_BAD_BOUNDS); negative_cases++;
        CHECK(sucrune_linux_validate(NULL,FIXTURE_SIZE,page,&plan)==SUCRUNE_ELF_INVALID_ARGUMENT); negative_cases++;
        CHECK(sucrune_linux_validate(bytes,FIXTURE_SIZE,page,NULL)==SUCRUNE_ELF_INVALID_ARGUMENT); negative_cases++;
    }
    struct sucrune_linux_plan plan; fixture(bytes);
    CHECK(sucrune_linux_validate(bytes,FIXTURE_SIZE,8192U,&plan)==SUCRUNE_ELF_INVALID_ARGUMENT); negative_cases++;
    free(bytes);
}

static void script_headers(void) {
    struct sucrune_script_chain chain = {0};
    struct sucrune_script_line *line = &chain.lines[0];
    const unsigned char outer[] = "#! \t./helper\t -S name  with\tspaces   \nignored";
    CHECK(sucrune_script_parse(outer, sizeof(outer)-1U, line) == 1);
    CHECK(strcmp(line->text, "./helper") == 0 && strcmp(line->text + line->argument, "-S name  with\tspaces") == 0);
    CHECK(sucrune_script_parse((const unsigned char *)"#!/bin/sh\r\n", 11, &chain.lines[1]) == 1);
    CHECK(strcmp(chain.lines[1].text, "/bin/sh\r") == 0 && chain.lines[1].argument == 0U);
    chain.count = 2;
    const char *prefix[2U * SUCRUNE_SHEBANG_DEPTH + 1U];
    CHECK(sucrune_script_prefix(&chain, "./outer", prefix) == 4U);
    CHECK(strcmp(prefix[0], "/bin/sh\r") == 0 && strcmp(prefix[1], "./helper") == 0 &&
          strcmp(prefix[2], "-S name  with\tspaces") == 0 && strcmp(prefix[3], "./outer") == 0);
    CHECK(sucrune_script_parse((const unsigned char *)"#", 1, line) == 0);
    CHECK(sucrune_script_parse((const unsigned char *)"#! \t\n", 5, line) == -ENOEXEC);
    CHECK(sucrune_script_parse((const unsigned char *)"#!/x", 4, line) == 1);
    unsigned char full[SUCRUNE_SHEBANG_HEADER];
    memset(full, 'x', sizeof(full)); full[0] = '#'; full[1] = '!';
    CHECK(sucrune_script_parse(full, sizeof(full), line) == -ENOEXEC);
    full[4] = ' ';
    CHECK(sucrune_script_parse(full, sizeof(full), line) == 1);
    CHECK(strcmp(line->text, "xx") == 0 && strlen(line->text + line->argument) == sizeof(full)-6U);
}

int main(int argc,char **argv) {
    CHECK(argc==5);
    real_file(argv[1],"hello",0,1);
    real_file(argv[2],"ld.so",0,0);
    real_file(argv[3],"libc.so.6",0,1);
    real_file(argv[4],"node",1,1);
    synthetic_tests();
    script_headers();
    (void)printf("Linux ELF parser: real=%u synthetic_positive=%u rejected=%u; no guest mapping or execution\n",
        real_cases,positive_cases,negative_cases);
    return 0;
}
