/*
 * Copyright 2015 Big Switch Networks, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
// #include <linux/bpf.h>

#include <ght_hash_table.h>

#include "ebpflow_int.h"
#include "../utils/ebpf.h"
#include "elf_utils.h"


struct section {
    const Elf64_Shdr *shdr;
    const void *data;
    uint64_t size;
};

#ifndef BPF_PSEUDO_MAP_FD
#define BPF_PSEUDO_MAP_FD 1
#endif

#define MAX_ELF_SIZE 1048576 //1024*1024

/* Instructions to be placed at the beginning of every code
   loaded. These instructions are necessary to bootstrap the
   code to run on the processor. The description of each is
   commented below.
*/
const struct ebpf_inst bootstrap_insts[] = {
    { // mov r1, 0  <~ Load pointer to packet
        .opcode = EBPF_OP_MOV64_IMM,
        .dst    = 1,
        .src    = 0,
        .offset = 0,
        .imm	= 0,
    },
    { // mov r10, 2560 <~ Load pointer to stack
        .opcode = EBPF_OP_MOV64_IMM,
        .dst    = 10,
        .src    = 0,
        .offset = 0,
        .imm	= 0xa00,
    }
};

/* Translate the code to Little Endian byte order */
int
code_to_le (struct ebpf_inst* code, int n_insts){
#if __BYTE_ORDER == __BIG_ENDIAN
    int i;
    struct ebpf_inst* inst;
    for(i = 0 ; i < n_insts ; i++){
        inst = &code[i];
        uint8_t aux  = inst->dst;
        inst->dst    = inst->src;
        inst->src    = aux;
        inst->offset = __cpu_to_le16(inst->offset);
        inst->imm	 = __cpu_to_le32(inst->imm);
    }
#endif
    /* If this is run on a Little Endian machine, there's nothing to do */

    return 0;
}

uint32_t
ebpflow_parse_elf(struct ebpflow_fw *fw, char *filepath, void **code, char **errmsg)
{
    struct eu_bounds b;
    void *text_copy = NULL;
    void *text_buffer = NULL;
    int i;
    size_t elf_size;
    void* elf = NULL;

    ght_hash_table_t *maps = ght_create(MAX_MAPS);
    if (maps == NULL) {
        *errmsg = ebpflow_error("unable to create internal hash table");
        goto error;
    }

    elf = eu_read_elf(filepath, MAX_ELF_SIZE, &elf_size, errmsg);
    b.base = elf;
    b.size = elf_size;

    const Elf64_Ehdr *ehdr = eu_parse_elf_header(elf,elf_size,errmsg);

    if(ehdr == NULL){
        return 0;
    }

    // ref to string table, TODO: probably a better way to reference to the strings_table
    const char* strings_table = NULL;

    /* Parse section headers into an array */
    struct section sections[MAX_ELF_SECTIONS];
    for (i = 0; i < ehdr->e_shnum; i++) {
        const Elf64_Shdr *shdr = eu_bounds_check(&b, ehdr->e_shoff + i*ehdr->e_shentsize, sizeof(*shdr));
        if (!shdr) {
            *errmsg = ebpflow_error("bad section header offset or size");
            goto error;
        }

        const void *data = eu_bounds_check(&b, shdr->sh_offset, shdr->sh_size);
        if (!data) {
            *errmsg = ebpflow_error("bad section offset or size");
            goto error;
        }

        sections[i].shdr = shdr;
        sections[i].data = data;
        sections[i].size = shdr->sh_size;

        // Store the reference to the strings table
        if (shdr->sh_type == SHT_STRTAB) {
            strings_table = data;
        }
    }

    // Find the reference to the symtab and maps sections, NOTE: quite hacky way of doing things ...
    int symtab_idx = 0;
    int maps_idx = 0;

    for (i = 0; i < ehdr->e_shnum; i++) {
        struct section *sec = &sections[i];

        if (sec->shdr->sh_type == SHT_SYMTAB) {
            symtab_idx = i;
        }

        else if (strcmp("maps", strings_table + sec->shdr->sh_name) == 0) {
            maps_idx = i;
        }
    }

    /*
        We need to get the reference for the two allowed maps (LPM_TRIE [TCAM]
        and ARRAY [CAM]), to make sure at most one of each type exists. Otherwise,
        we need to reject the program as the processor cannot handle it
    */

    // TODO: Change map tracking as more map types are added.
    // A better approach would be to have an array indexed by bpf_map_type (which is an enum)
    // with each position holding the corresponding indexes and counters for each type
    int lpm_map_idx = -1;
    int lpm_map_cnt = 0;
    int array_map_idx = -1;
    int array_map_cnt = 0;

    if (symtab_idx != 0 && maps_idx != 0) {
        // Iterate over symbol definition to find the maps
        struct section *symtab = &sections[symtab_idx];
        const Elf64_Sym *syms = symtab->data;
        uint32_t num_syms = symtab->size/sizeof(Elf64_Sym);
        for (i = 0; i < num_syms; i++) {
            // Get the related section using st_shndx entry
            const Elf64_Sym *sym = &syms[i];
            struct section *rel = &sections[sym->st_shndx];

            // If the related section is the maps definition, then we have a table definition symbol
            if (sym->st_shndx == maps_idx) {
                int bpf_map_def_idx = sym->st_value / sizeof(struct bpf_map_def);
                const struct bpf_map_def *maps_defs = rel->data;
                const struct bpf_map_def map_def = maps_defs[bpf_map_def_idx];

                // TODO do we have to copy the name as it will be copied again ...
                char map_name[TABLE_NAME_MAX_LENGTH] = {0};
                strncpy(map_name, strings_table + sym->st_name, TABLE_NAME_MAX_LENGTH-1);

                struct table_entry *tab_entry = ght_get(maps, sizeof(char)*(strlen(map_name)), map_name);

                // If the entry for this map doesn't exist create it
                if (tab_entry == NULL) {
                    tab_entry = calloc(1, sizeof(struct table_entry));
                    switch(map_def.type){
                        case BPF_MAP_TYPE_LPM_TRIE:
                            if(lpm_map_cnt == 0){
                                lpm_map_cnt++;
                                lpm_map_idx = bpf_map_def_idx;
                                tab_entry->id = bpf_map_def_idx;
                                tab_entry->type = BPFPROC_MAP_TCAM;
                            }else{
                                *errmsg = ebpflow_error("The processor currently only supports 1 map of type LPM_TRIE");
                                goto error;
                            }
                            break;
                    case BPF_MAP_TYPE_HASH:
                        if (array_map_cnt == 0){
                                array_map_cnt++;
                                array_map_idx = bpf_map_def_idx;
                                tab_entry->id = bpf_map_def_idx;
                                tab_entry->type = BPFPROC_MAP_CAM;
                            }else{
                                *errmsg = ebpflow_error("The processor currently only supports 1 map of type ARRAY");
                                goto error;
                            }
                            break;
                        default:
                            *errmsg = ebpflow_error("Map %s has an unsupported map type: type=%u", map_name, map_def.type);
                            goto error;
                    }

                    tab_entry->key_size = map_def.key_size;
                    tab_entry->value_size = map_def.value_size;
                    tab_entry->max_entries = map_def.max_entries;

                    int ret = ght_insert(maps,tab_entry,sizeof(char)*(strlen(map_name)),map_name);
                    if(ret == -1){
                        *errmsg = ebpflow_error("A map with the name %s already exists!",map_name);
                        goto error;
                    }

                    // Can I free this??
                    // free(tab_entry);
                }
            }
        }
    }

    /* Find first text section */
    int text_shndx = 0;
    for (i = 0; i < ehdr->e_shnum; i++) {
        const Elf64_Shdr *shdr = sections[i].shdr;
        if (shdr->sh_type == SHT_PROGBITS &&
                shdr->sh_flags == (SHF_ALLOC|SHF_EXECINSTR)) {
            text_shndx = i;
            break;
        }
    }

    if (!text_shndx) {
        *errmsg = ebpflow_error("text section not found");
        goto error;
    }

    struct section *text = &sections[text_shndx];



    /* May need to modify text for relocations, so make a copy.
     * Also add extra space for the instructions necessary to
     * initialize the code on the processor.
     */
    text_buffer = malloc(text->size+sizeof(bootstrap_insts));
    if (!text_buffer) {
        *errmsg = ebpflow_error("failed to allocate memory");
        goto error;
    }

    // Copy bootstrap instructions
    memcpy(text_buffer, bootstrap_insts, sizeof(bootstrap_insts));

    // text_copy will point to the beginning of the original code
    text_copy = text_buffer+sizeof(bootstrap_insts);

    // Copy original code
    memcpy(text_copy, text->data, text->size);


    /* Process code */
    struct ebpf_inst *insns = text_copy;
    unsigned int n_insns = text->size/sizeof(struct ebpf_inst);
    for (i = 0; i < n_insns ; i++) {

        /* Modify second part of LDDW instruction */
        if (insns[i].opcode == EBPF_OP_LDDW) {
            if(i+1 >= n_insns){
                *errmsg = ebpflow_error("code ended too soon");
                goto error;
            }

            if(insns[i+1].opcode != 0x00){
                *errmsg = ebpflow_error("bad instruction after LDDW");
                goto error;
            }

            /* LDDW is divided into 2 instructions. The second one
               has all fields 0 except for IMM. The processor expects
               EBPF_OP_LDDW2 as the opcode, instead of 0, and the dst
               register, which is the same as the LDDW operation.
            */
            insns[i+1].opcode = EBPF_OP_LDDW2;
            insns[i+1].dst    = insns[i].dst;

            /* Skip LDDW2, since it's been treated already */
            i++;
        }
        
        /* Fix negative offset of stack access with complement. 
           Negative offset is calculated on hardware but instruction 
           generated is positive.
        */ 
        if ((insns[i].src == 0xA) | (insns[i].dst == 0xA)){  

           uint8_t class = insns[i].opcode & 0x7;

           if (class == EBPF_CLS_LD | class == EBPF_CLS_LDX)  
              //Complement's 2 
              insns[i].offset = (~insns[i].offset)+1;  
           
           if (class == EBPF_CLS_ST | class == EBPF_CLS_STX)  
              //Complement's 2 
              insns[i].offset = (~insns[i].offset)+1; 
        }
    }

    /* Process each relocation section */
    for (i = 0; i < ehdr->e_shnum; i++) {
        struct section *rel = &sections[i];

        if (rel->shdr->sh_type != SHT_REL) {
            continue;
        } else if (rel->shdr->sh_info != text_shndx) {
            continue;
        }

        const Elf64_Rel *rs = rel->data;

        if (rel->shdr->sh_link >= ehdr->e_shnum) {
            *errmsg = ebpflow_error("bad symbol table section index");
            goto error;
        }

        struct section *symtab = &sections[rel->shdr->sh_link];
        const Elf64_Sym *syms = symtab->data;
        uint32_t num_syms = symtab->size/sizeof(syms[0]);

        if (symtab->shdr->sh_link >= ehdr->e_shnum) {
            *errmsg = ebpflow_error("bad string table section index");
            goto error;
        }

        struct section *strtab = &sections[symtab->shdr->sh_link];
        const char *strings = strtab->data;

        int j;
        for (j = 0; j < rel->size/sizeof(Elf64_Rel); j++) {
            const Elf64_Rel *r = &rs[j];


            uint32_t sym_idx = ELF64_R_SYM(r->r_info);
            if (sym_idx >= num_syms) {
                *errmsg = ebpflow_error("bad symbol index");
                goto error;
            }

            const Elf64_Sym *sym = &syms[sym_idx];

            if (sym->st_name >= strtab->size) {
                *errmsg = ebpflow_error("bad symbol name");
                goto error;
            }

            const char *sym_name = strings + sym->st_name;
            // printf("symbol name %s sym_idx %d  ndx: %d\n", sym_name, sym_idx, sym->st_shndx);

            if (r->r_offset + 8 > text->size) {
                *errmsg = ebpflow_error("bad relocation offset");
                goto error;
            }

            // Custom map relocation
            if (ELF64_R_TYPE(r->r_info) == 1 && sym->st_shndx == maps_idx) { // map relocation
                // struct ebpf_inst *insns = text_copy;
                unsigned int insn_idx;

                insn_idx = r->r_offset / sizeof(struct ebpf_inst);

                if (insns[insn_idx].opcode != (EBPF_CLS_LD | EBPF_SRC_IMM | EBPF_SIZE_DW)) {
                    *errmsg = ebpflow_error("bad relocation for instruction 0x%x at index %d\n", insns[insn_idx].opcode, insn_idx);
                    goto error;
                }

                char map_name[32] = {0};
                strncpy(map_name, sym_name, 31);
                struct table_entry *tab_entry = ght_get(maps, sizeof(char)*(strlen(map_name)), map_name);

                if (tab_entry == NULL) {
                    *errmsg = ebpflow_error("cannot find map %s",map_name);
                    goto error;
                }

                // insns[insn_idx].src = BPF_PSEUDO_MAP_FD; // do we need this?
                insns[insn_idx].imm = tab_entry->id;
            }

            // Perform string relocation
            else if (ELF64_R_TYPE(r->r_info) == 1) {
                struct section *rodata = &sections[sym->st_shndx];
                // printf("value %lu s %s\n", sym->st_value, rodata_value);

                struct ebpf_inst *insns = text_copy;
                unsigned int insn_idx;

                insn_idx = r->r_offset / sizeof(struct ebpf_inst);

                if (insns[insn_idx].opcode != (EBPF_CLS_LD | EBPF_SRC_IMM | EBPF_SIZE_DW)) {
                    *errmsg = ebpflow_error("bad relocation for instruction 0x%x at index %d\n", insns[insn_idx].opcode, insn_idx);
                    goto error;
                }

                uint64_t address = (uintptr_t)rodata->data + sym->st_value;
                insns[insn_idx].imm = address;
                insns[insn_idx+1].imm = address >> 32;
            }

            else if (ELF64_R_TYPE(r->r_info) == 2) {
                // If firmware is NULL, skip function translation
                if(fw != NULL){
                    unsigned int imm = ebpflow_lookup_registered_function(fw, sym_name);
                    if (imm == -1) {
                        *errmsg = ebpflow_error("function '%s' not found", sym_name);
                        goto error;
                    }

                    *(uint32_t *)(text_copy + r->r_offset + 4) = imm;
                }
            }


            else {
                *errmsg = ebpflow_error("bad relocation type %u", ELF64_R_TYPE(r->r_info));
                goto error;
            }
        }
    }

    if(fw != NULL){
       fw->maps = maps;
    }

    /* The processor expects code in Little Endian byte order, so translate it */
    uint32_t code_len = text->size+sizeof(bootstrap_insts);
    n_insns = code_len/sizeof(struct ebpf_inst);
    code_to_le((struct ebpf_inst*) text_buffer, n_insns);
    *code = text_buffer;

    // printf("Saving contents to file!\n");
    // FILE *out = fopen("dump.bpf","wb");
    // fwrite(text_buffer,text->size+sizeof(bootstrap_insts),1,out);
    // fclose(out);

    // free(text_buffer);
    // return rv;

    return code_len;

error:
    free(text_buffer);
    return 0;
}
