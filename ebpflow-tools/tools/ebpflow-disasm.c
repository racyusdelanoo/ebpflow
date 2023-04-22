#include <stdio.h>
#include <stdlib.h>
// #include <ebpflow.h>
#include <elf.h>
#include <unistd.h>
#include <getopt.h>

#include "ebpf.h"
#include "elf_utils.h"

void try_message(){
    printf("Try 'ebpflow-disasm -h' for more information.\n");
}

void usage(){
    printf(
        "Usage: ebpflow-disasm [FLAGS] <ebpf-file.o>\n"
        "Disassembles eBPF code into human-readable format.\n"
        "\n"
        "Options:\n"
        "   -o [outfile]    Output to file\n"
        "   -h              Print this help message\n"
    );
}

static const void *
bounds_check(const void *base, uint64_t t_size, uint64_t offset, uint64_t s_size)
{
    if (offset + s_size > t_size || offset + s_size < offset) {
        return NULL;
    }

    return base + offset;
}

int main(int argc, char** argv){
    int opt;
    char *filepath = NULL;
    char* errmsg;
    const struct ebpf_inst *code = NULL;
    uint32_t num_insts;
    FILE* outfile = NULL;
    char* outfile_path = NULL;
    size_t elf_size;
    struct eu_bounds bounds;

    // Flags
    int tofile = 0;

    while( (opt = getopt(argc,argv,"o:h")) != -1){
        switch(opt){
            case 'o':
                tofile = 1;
                outfile_path = optarg;
                break;
            case 'h':
                usage();
                return 0;
                break;
            default:
                try_message();
                exit(1);
                break;
        }
    }

    if(argc == optind){
        printf("Expected .o file to load\n");
        try_message();
        return 1;
    }

    // Filename should always be the last argument
    filepath = argv[optind];

    if(tofile){
        outfile = freopen(outfile_path,"w+",stdout); 
    }

    const void* elf = eu_read_elf(filepath,1024*1024,&elf_size, &errmsg);
    if(elf == NULL){
        fprintf(stderr,"%s\n",errmsg);
        return 1;
    }

    bounds.base = elf;
    bounds.size = elf_size;

    const Elf64_Ehdr *ehdr = eu_parse_elf_header(elf,elf_size, &errmsg);
    if(ehdr == NULL){
        fprintf(stderr,"%s\n",errmsg);
        return 1;
    }

    /* Find .text section */
    for (int i = 0; i < ehdr->e_shnum; i++) {
        const Elf64_Shdr *shdr = eu_bounds_check(&bounds, ehdr->e_shoff + i*ehdr->e_shentsize, sizeof(*shdr));
        if (shdr == NULL) {
            fprintf(stderr,"bad section header offset or size\n");
            return 1;
        }

        const void *data = eu_bounds_check(&bounds, shdr->sh_offset, shdr->sh_size);
        if (data == NULL) {
            fprintf(stderr,"bad section offset or size\n");
            return 1;
        }

        if (shdr->sh_type == SHT_PROGBITS &&
                shdr->sh_flags == (SHF_ALLOC|SHF_EXECINSTR)) {

            if(shdr->sh_size % sizeof(uint64_t)){
                fprintf(stderr,"bad number of bytes on .text section\n");
                return 1;
            }

            num_insts = shdr->sh_size/sizeof(uint64_t);
            code = data;

            break;
        }
    }

    if (code == NULL) {
        fprintf(stderr,"text section not found\n");
        return 1;
    }

    ebpf_disassemble_many(code,num_insts);


    if(tofile)
        fclose(outfile);

    return 0;
}