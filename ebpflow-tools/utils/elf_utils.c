#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <inttypes.h>
#include <elf.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <asm/byteorder.h>
#include <linux/bpf.h>

#include "ebpf.h"
#include "elf_utils.h"

#ifndef EM_BPF
#define EM_BPF 247
#endif

char *
eu_error(const char *fmt, ...)
{
    char *msg;
    va_list ap;
    va_start(ap, fmt);
    if (vasprintf(&msg, fmt, ap) < 0) {
        msg = NULL;
    }
    va_end(ap);
    return msg;
}

const void *
eu_parse_elf_header(const void *elf, size_t elf_size, char **errmsg)
{
    struct eu_bounds b;
    b.base = elf;
    b.size = elf_size;

    if(elf == NULL || elf_size <= 0){
        // Erro message filled by readfile()
        return NULL;
    }

    const Elf64_Ehdr *ehdr = eu_bounds_check(&b, 0, sizeof(*ehdr));
    if (!ehdr) {
        *errmsg = eu_error("not enough data for ELF header");
        return NULL;
    }

    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG)) {
        *errmsg = eu_error("wrong magic");
        return NULL;
    }

    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        *errmsg = eu_error("wrong class");
        return NULL;
    }

    #if __BYTE_ORDER == __BIG_ENDIAN
    if (ehdr->e_ident[EI_DATA] != ELFDATA2MSB) {
        *errmsg = eu_error("expected big-endian ELF file, but got little-endian\n"
                              "please compile your BPF code with '-target bpfbe'");
        return NULL;
    }
    #elif __BYTE_ORDER == __LITTLE_ENDIAN
    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        *errmsg = eu_error("expected little-endian ELF file, but got big-endian\n"
                              "please compile your BPF code with '-target bpfle'");
        return NULL;
    }
    #else
       *errmsg = eu_error("unable to detect host's endiannes. Please fix asm/byteorder.h");
       return NULL;
    #endif

    if (ehdr->e_ident[EI_VERSION] != 1) {
        *errmsg = eu_error("wrong version");
        return NULL;
    }

    if (ehdr->e_ident[EI_OSABI] != ELFOSABI_NONE) {
        *errmsg = eu_error("wrong OS ABI");
        return NULL;
    }

    if (ehdr->e_type != ET_REL) {
        *errmsg = eu_error("wrong type, expected relocatable");
        return NULL;
    }

    if (ehdr->e_machine != EM_NONE && ehdr->e_machine != EM_BPF) {
        *errmsg = eu_error("wrong machine, expected none or EM_BPF (%d)", EM_BPF);
        return NULL;
    }

    if (ehdr->e_shnum > MAX_ELF_SECTIONS) {
        *errmsg = eu_error("too many sections");
        return NULL;
    }

    return ehdr;
}

const void *
eu_bounds_check(struct eu_bounds *bounds, uint64_t offset, uint64_t size)
{
    if (offset + size > bounds->size || offset + size < offset) {
        return NULL;
    }
    return bounds->base + offset;
}


void *eu_read_elf(const char *path, size_t maxlen, size_t *len, char **errmsg)
{
    FILE *file;
    if (!strcmp(path, "-")) {
        file = fdopen(STDIN_FILENO, "r");
    } else {
        file = fopen(path, "r");
    }

    if (file == NULL) {
        *errmsg = eu_error("Failed to open %s: %s", path, strerror(errno));
        return NULL;
    }

    void *data = calloc(maxlen, 1);
    size_t offset = 0;
    size_t rv;
    while ((rv = fread(data+offset, 1, maxlen-offset, file)) > 0) {
        offset += rv;
    }

    if (ferror(file)) {
        *errmsg = eu_error("Failed to read %s: %s", path, strerror(errno));
        fclose(file);
        free(data);
        return NULL;
    }

    if (!feof(file)) {
        *errmsg = eu_error("Failed to read %s because it is too large (max %u bytes)",
                path, (unsigned)maxlen);
        fclose(file);
        free(data);
        return NULL;
    }

    fclose(file);
    if (len) {
        *len = offset;
    }

    return data;
}