#include <stdlib.h>
#include <stdint.h>

#define MAX_ELF_SECTIONS 32

struct eu_bounds {
    const void *base;
    uint64_t size;
};

const void *eu_parse_elf_header(const void *elf, size_t elf_size, char **errmsg);

const void *eu_bounds_check(struct eu_bounds *bounds, uint64_t offset, uint64_t size);

void *eu_read_elf(const char *path, size_t maxlen, size_t *len, char **errmsg);