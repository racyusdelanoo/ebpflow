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
#include <stdint.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <endian.h>
#include <sys/socket.h>

#include <ght_hash_table.h>

#include "ebpflow_int.h"
#include "ebpflow_consts.h"
#include "ebpf.h"
#include "bpfmap.h"
#include "bitops.h"

#include "sume_util.h"
#include "reg_defines.h"

// #include "bpfmap.h"

// static bool validate(const struct ebpflow_fw *fw, const struct ebpf_inst *insts, uint32_t num_insts, char **errmsg);

struct ebpflow_fw *
ebpflow_create(void)
{
    struct ebpflow_fw *fw = calloc(1, sizeof(*fw));
    if (fw == NULL) {
        return NULL;
    }

    // Try IPv6 connection
    fw->conn = socket(AF_INET6, SOCK_DGRAM, 0);
    if(fw->conn == -1){
        // If failed, try IPv4
        fw->conn = socket(AF_INET, SOCK_DGRAM, 0);
    }

    /* If socket creation failed, terminate */
    if (fw->conn == -1){
        printf("ERROR socket failed for AF_INET6 and AF_INET");
        ebpflow_destroy(fw);
        return NULL;
    }

    fw->ext_funcs = calloc(MAX_EXT_FUNCS, sizeof(*fw->ext_funcs));
    if (fw->ext_funcs == NULL) {
        ebpflow_destroy(fw);
        return NULL;
    }

    fw->ext_func_names = calloc(MAX_EXT_FUNCS, sizeof(*fw->ext_func_names));
    if (fw->ext_func_names == NULL) {
        ebpflow_destroy(fw);
        return NULL;
    }

    // Register external funcs for validation and simulation
    ebpflow_register(fw, 1, "bpf_map_lookup_elem", bpf_lookup_elem);
    ebpflow_register(fw, 2, "bpf_map_update_elem", bpf_update_elem);
    ebpflow_register(fw, 3, "bpf_map_delete_elem", bpf_delete_elem);

    /* This will be filled when loading a program */
    fw->maps = NULL;

    return fw;
}

void
ebpflow_destroy(struct ebpflow_fw *fw)
{
    // if (fw->jitted) {
    //     munmap(fw->jitted, fw->jitted_size);
    // }
    free(fw->insts);
    free(fw->ext_funcs);
    free(fw->ext_func_names);
    free(fw);
}

int
ebpflow_register(struct ebpflow_fw *fw, unsigned int idx, const char *name, void *fn)
{
    if (idx >= MAX_EXT_FUNCS) {
        return -1;
    }

    fw->ext_funcs[idx] = (ext_func)fn;
    fw->ext_func_names[idx] = name;
    return 0;
}

unsigned int
ebpflow_lookup_registered_function(struct ebpflow_fw *fw, const char *name)
{
    int i;
    for (i = 0; i < MAX_EXT_FUNCS; i++) {
        const char *other = fw->ext_func_names[i];
        if (other && !strcmp(other, name)) {
            return i;
        }
    }
    return -1;
}

int
ebpflow_write_register(const struct ebpflow_fw *fw, uint32_t regaddr, uint32_t regval, char** errmsg){
    int ret;

    if(fw == NULL)
        return -1;

    ret = writeReg(fw->conn,regaddr,regval);
    if(ret && errmsg != NULL){
        *errmsg = ebpflow_error("failed to load value to switch (reg_addr = 0x%lx)",regaddr);
        return -1;
    }

    return 0;
}

int
ebpflow_read_register(const struct ebpflow_fw *fw, uint32_t regaddr, uint32_t *regval, char** errmsg){
    int ret;

    if(fw == NULL)
        return -1;

    ret = readReg(fw->conn,regaddr,regval);
    if(ret && errmsg != NULL){
        *errmsg = ebpflow_error("failed to read value from switch (reg_addr = 0x%lx)",regaddr);
        return -1;
    }

    return 0;
}

int
ebpflow_map_insert(const struct ebpflow_fw *fw, char* map_name, uint64_t key, uint64_t mask, uint64_t val){
    struct table_entry *map;
    unsigned int cam_full; 
    unsigned int tcam_full; 
    unsigned int ack_operation;
    int ret;

    if(map_name == NULL || fw == NULL || fw->maps == NULL)
        return -1;

    map = ght_get(fw->maps, sizeof(char)*(strlen(map_name)), map_name);
    if(map == NULL){
        printf("Failed to insert rule. Could not find map.\n");
        return -1;
    }

    // printf("Inserting on map: %s (id = %d)\n",map_name,map->type);
      
    //CAM or TCAM are full   
    ret = ebpflow_read_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_CAMFULL, &cam_full, NULL);
    if(ret) return -1;

    ret = ebpflow_read_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_TCAMFULL, &tcam_full, NULL);
    if(ret) return -1;

    if (cam_full) { 
      printf("\nCAM is full! You need run clean or delete operation!\n"); 
      return -1; 
    }  

    if (tcam_full){ 
      printf("\nTCAM is full! You need run clean or delete operation!\n\n"); 
      return -1; 
    }    
         
    // This indicates in which type of memory the rule should be installed.
    // However, to be more generic, this should indicate just the map ID, and
    // the rest should be derived based on the global maps table and MMU
    ret = ebpflow_write_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_SELECTMEMORY, map->type, NULL);
    if(ret) return -1;

    ret = ebpflow_write_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_OPERATION, BPFPROC_MAP_INSERT_OP, NULL);
    if(ret) return -1;

    ret = ebpflow_write_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_HIKEY, (uint32_t)(HI32(key)), NULL);
    if(ret) return -1;

    ret = ebpflow_write_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_LOKEY, (uint32_t)(LO32(key)), NULL);
    if(ret) return -1;

    ret = ebpflow_write_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_HIMASK,  (uint32_t)(HI32(mask)), NULL);
    if(ret) return -1;

    ret = ebpflow_write_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_LOMASK,  (uint32_t)(LO32(mask)), NULL);
    if(ret) return -1;

    ret = ebpflow_write_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_HIDIN,  (uint32_t)(HI32(val)), NULL);
    if(ret) return -1;

    ret = ebpflow_write_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_LODIN,  (uint32_t)(LO32(val)), NULL);
    if(ret) return -1;

    //Wait until operation finish
    ret = ebpflow_read_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_ACK, &ack_operation, NULL);
    if(ret) return -1;
    
    if(!ack_operation)
      printf("Running insertion operation!\n");  

    while(!ack_operation)
       ebpflow_read_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_ACK, &ack_operation, NULL);

    return 0;
}


int
ebpflow_soft_map_insert(const struct ebpflow_fw *fw, char* map_name, uint64_t key, uint64_t val){
    struct table_entry *map;

    if(map_name == NULL || fw == NULL || fw->maps == NULL)
        return -1;

    map = ght_get(fw->maps, sizeof(char)*(strlen(map_name)), map_name);
    if(map == NULL){
        printf("Could not find map.\n");
        return -1;
    }

    return bpf_update_elem(map->id,key,val,0);
}

int
ebpflow_install_rules(struct ebpflow_fw *fw, char **inrules)
{
    FILE *fin;
    char buf[1024];
    char map_name[64];
    uint64_t key = 0, val = 0, mask = 0;
    int ret;

    fin = fopen(*inrules,"r");
    if(fin == NULL){
        printf("Failed to open file\n");
        return -1;
    }

    int c = 0;
    while(fgets(buf,sizeof(buf),fin)){
        if(buf[0] == '#' || buf[0] == '\n') // Skip comments and empty lines
            continue;

        sscanf(buf,"%s 0x%lx 0x%lx 0x%lx",map_name,&key,&mask,&val);

        // printf("%s 0x%lx 0x%lx 0x%lx\n",map_name,key,mask,val);

        ret = ebpflow_map_insert(fw,map_name,key,mask,val);
        if(ret) return -1;

        //Insert Error message ********
    }

    fclose(fin);

    return 0;
}

int
ebpflow_load_code(struct ebpflow_fw *fw, const void *code, uint32_t code_len, int mode, int payload, char **errmsg)
{
    unsigned num_inst;
    unsigned hi_inst;
    unsigned lo_inst;
    unsigned int i;
    int ret;
    *errmsg = NULL;

    if (fw == NULL){
        *errmsg = ebpflow_error("firmware not initialized");
        return -1;
    }

    if (fw->insts) {
        free(fw->insts); // Allow loading multi BPF programs
        // *errmsg = ubpf_error("code has already been loaded into this firmware");
        // return -1;
    }

    if (code_len == 0 || code_len % 8 != 0) {
        *errmsg = ebpflow_error("code_len must be a multiple of 8 and != 0");
        return -1;
    }

    if (payload != 0 && payload != 1) {
        *errmsg = ebpflow_error("payload flag must be either 0 (false) or 1 (true)");
        return -1;
    }

    // TODO: Modify and add validate func
    // if (!validate(fw, code, code_len/8, errmsg)) {
    //     return -1;
    // }

    fw->insts = malloc(code_len);
    if (fw->insts == NULL) {
        *errmsg = ebpflow_error("out of memory");
        return -1;
    }

    // Keep a local copy of the code loaded
    memcpy(fw->insts, code, code_len);
    fw->num_insts = code_len/sizeof(fw->insts[0]);

    // Do not load code to NetFPGA, only create the local copy
    if(mode == -1)
        return 0;

    if (fw->maps == NULL){
        *errmsg = ebpflow_error("maps table not initialized");
        return -1;
    }

    // Load maps
    unsigned int num_maps = ght_size(fw->maps);

    if(num_maps){
        ght_iterator_t iterator;
        void *key;
        void *elem;
        struct table_entry *map;
        uint32_t regval;
        uint64_t keymask;
        uint64_t valmask;


        ret = writeReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_NUMMAP,num_maps);
        // printf("num maps: 0x%08x\n",num_maps);
        if(ret){
            *errmsg = ebpflow_error("failed to load NUMMAP value to switch");
            return -1;
        }

        for(elem = ght_first(fw->maps, &iterator, &key); elem; elem = ght_next(fw->maps, &iterator, &key)){
            map = (struct table_entry *) elem;
            keymask = 0xFFFFFFFFFFFFFFFFULL >> (MAP_MAX_KEY_SZ_BITS-map->key_size*8);
            valmask = 0xFFFFFFFFFFFFFFFFULL >> (MAP_MAX_VALUE_SZ_BITS-map->value_size*8);

            // TODO: Do all these writeRegs more elegantly. Use function
            // ebpflow_write_register

            regval = (uint32_t) map->type;
            // printf("map type: 0x%08x\n",regval);
            ret = writeReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_TYPEMAP,regval);
            if(ret){
                *errmsg = ebpflow_error("failed to load TYPEMAP value to switch");
                return -1;
            }

            regval = (uint32_t) (keymask>>32); // Higher half
            // printf("keymask HI: 0x%08x\n",regval);
            ret = writeReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_HIKEYMASKMAP,regval);
            if(ret){
                *errmsg = ebpflow_error("failed to load HIKEYMASKMAP value to switch");
                return -1;
            }

            regval = (uint32_t) keymask; // Lower half
            // printf("keymask LO: 0x%08x\n",regval);
            ret = writeReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_LOKEYMASKMAP,regval);
            if(ret){
                *errmsg = ebpflow_error("failed to load LOKEYMASKMAP value to switch");
                return -1;
            }

            regval = (uint32_t) (valmask>>32); // Higher half
            // printf("valmask HI: 0x%08x\n",regval);
            ret = writeReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_HIVALUEMASKMAP,regval);
            if(ret){
                *errmsg = ebpflow_error("failed to load HIVALUEMASKMAP value to switch");
                return -1;
            }

            regval = (uint32_t) valmask; // Lower half
            // printf("valmask LO: 0x%08x\n",regval);
            ret = writeReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_LOVALUEMASKMAP,regval);
            if(ret){
                *errmsg = ebpflow_error("failed to load LOVALUEMASKMAP value to switch");
                return -1;
            }

            regval = (uint32_t) map->max_entries;
            // printf("max entries: 0x%08x\n",regval);
            ret = writeReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_MAXELEMSMAP,map->max_entries);
            if(ret){
                *errmsg = ebpflow_error("failed to load MAXELEMSMAP value to switch");
                return -1;
            }
        }
    }

    // Load instructions
    uint64_t *insts = (uint64_t*) code;

    //ret = writeReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_PAYLOADENABLED,payload);
    //if(ret){
    //    *errmsg = ebpflow_error("failed to load PAYLOADENABLED value to switch");
    //    return -1;
    //}

    ret = writeReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_CLEANDEBUG, 1);
    ret = writeReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_CLEANDEBUG, 0);
    if(ret){
        *errmsg = ebpflow_error("failed to load CLEANDEBUG value to switch");
        return -1;
    }

    ret = writeReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_ROUTERMODE,mode);
    if(ret){
        *errmsg = ebpflow_error("failed to load ROUTERMODE value to switch");
        return -1;
    }

    ret = writeReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_WRINST,0);
    if(ret){
        *errmsg = ebpflow_error("failed to load WRINST value to switch");
        return -1;
    }

    ret = writeReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_NUMINST, fw->num_insts);
    if(ret){
        *errmsg = ebpflow_error("failed to load NUMINST value to switch");
        return -1;
    }

    for (int i = 0 ; i < fw->num_insts ; i++){
        lo_inst = insts[i] & 0xFFFFFFFF;
        hi_inst = (insts[i]>>32) & 0xFFFFFFFF;
        ret = writeReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_HIINST, hi_inst);
        if(ret){
            *errmsg = ebpflow_error("failed to load HI_INST to switch");
            return -1;
        }

        ret = writeReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_LOINST, lo_inst);
        if(ret){
            *errmsg = ebpflow_error("failed to load LOW_INST value to switch");
            return -1;
        }
    }

    return 0;
}

/* Function to load raw hex instructions from a file. Does not support maps. */
int
ebpflow_load_txt(struct ebpflow_fw *fw, char* filepath, int mode, int payload, char **errmsg)
{
    unsigned num_insts = 0;
    unsigned hi_inst;
    unsigned lo_inst;
    unsigned int i;
    uint64_t insts[256]; // 256 is the max # instructions the processor can handle
    FILE* insts_file;
    int ret;
    *errmsg = NULL;

    if (fw == NULL){
        *errmsg = ebpflow_error("firmware not initialized");
        return -1;
    }

    if (fw->insts) {
        free(fw->insts); // Allow loading multi BPF programs
        // *errmsg = ubpf_error("code has already been loaded into this firmware");
        // return -1;
    }


    /*if (payload != 0 && payload != 1) {
        *errmsg = ebpflow_error("payload flag must be either 0 (false) or 1 (true)");
        return -1;
    }
    */

    // TODO: Keep a local copy of the code loaded

    // Do not load code to NetFPGA, only create the local copy
    if(mode == -1)
        return 0;

    // Load instructions
    insts_file = fopen(filepath,"r");
    if(insts_file == NULL){
        *errmsg = ebpflow_error("failed to open raw instruction file");
        return -1;
    }

    while(fscanf(insts_file,"%x %x",&hi_inst, &lo_inst) != EOF){
        insts[num_insts] = (((uint64_t)hi_inst)<<32) | ((uint64_t)lo_inst);

        if(++num_insts > 256){
            *errmsg = ebpflow_error("too many instructions (>256)");
            return -1;
        }
    }

    //printf("Num insts: %d\n",num_insts);

    //ret = writeReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_PAYLOADENABLED,payload);
    //if(ret){
    //    *errmsg = ebpflow_error("failed to load PAYLOADENABLED value to switch");
    //    return -1;
    //}

    ret = writeReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_ROUTERMODE,mode);
    if(ret){
        *errmsg = ebpflow_error("failed to load ROUTERMODE value to switch");
        return -1;
    }

    ret = writeReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_WRINST,0);
    if(ret){
        *errmsg = ebpflow_error("failed to load WRINST value to switch");
        return -1;
    }

    ret = writeReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_NUMINST, num_insts);
    if(ret){
        *errmsg = ebpflow_error("failed to load NUMINST value to switch");
        return -1;
    }

    for (int i = 0 ; i < num_insts ; i++){
        lo_inst = insts[i] & 0xFFFFFFFF;
        hi_inst = (insts[i]>>32) & 0xFFFFFFFF;
        // printf("0x%08x 0x%08x\n", hi_inst, lo_inst);

        ret = writeReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_HIINST, hi_inst);
        if(ret){
            *errmsg = ebpflow_error("failed to load HI_INST to switch");
            return -1;
        }

        ret = writeReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_LOINST, lo_inst);
        if(ret){
            *errmsg = ebpflow_error("failed to load LOW_INST value to switch");
            return -1;
        }
    }

    fclose(insts_file);
    return 0;
}
static uint32_t
u32(uint64_t x)
{
    return x;
}

// static bool
// validate(const struct bpf_proc *proc, const struct ebpf_inst *insts, uint32_t num_insts, char **errmsg)
// {
//     if (num_insts >= MAX_INSTS) {
//         *errmsg = ubpf_error("too many instructions (max %u)", MAX_INSTS);
//         return false;
//     }

// /*    if (num_insts == 0 || insts[num_insts-1].opcode != EBPF_OP_EXIT) {
//         *errmsg = ubpf_error("no exit at end of instructions");
//         return false;
//     }*/

//     int i;
//     for (i = 0; i < num_insts; i++) {
//         struct ebpf_inst inst = insts[i];
//         bool store = false;

//         switch (inst.opcode) {
//         case EBPF_OP_ADD_IMM:
//         case EBPF_OP_ADD_REG:
//         case EBPF_OP_SUB_IMM:
//         case EBPF_OP_SUB_REG:
//         case EBPF_OP_MUL_IMM:
//         case EBPF_OP_MUL_REG:
//         case EBPF_OP_DIV_REG:
//         case EBPF_OP_OR_IMM:
//         case EBPF_OP_OR_REG:
//         case EBPF_OP_AND_IMM:
//         case EBPF_OP_AND_REG:
//         case EBPF_OP_LSH_IMM:
//         case EBPF_OP_LSH_REG:
//         case EBPF_OP_RSH_IMM:
//         case EBPF_OP_RSH_REG:
//         case EBPF_OP_NEG:
//         case EBPF_OP_MOD_REG:
//         case EBPF_OP_XOR_IMM:
//         case EBPF_OP_XOR_REG:
//         case EBPF_OP_MOV_IMM:
//         case EBPF_OP_MOV_REG:
//         case EBPF_OP_ARSH_IMM:
//         case EBPF_OP_ARSH_REG:
//             break;

//         case EBPF_OP_LE:
//         case EBPF_OP_BE:
//             if (inst.imm != 16 && inst.imm != 32 && inst.imm != 64) {
//                 *errmsg = ubpf_error("invalid endian immediate at PC %d", i);
//                 return false;
//             }
//             break;

//         case EBPF_OP_ADD64_IMM:
//         case EBPF_OP_ADD64_REG:
//         case EBPF_OP_SUB64_IMM:
//         case EBPF_OP_SUB64_REG:
//         case EBPF_OP_MUL64_IMM:
//         case EBPF_OP_MUL64_REG:
//         case EBPF_OP_DIV64_REG:
//         case EBPF_OP_OR64_IMM:
//         case EBPF_OP_OR64_REG:
//         case EBPF_OP_AND64_IMM:
//         case EBPF_OP_AND64_REG:
//         case EBPF_OP_LSH64_IMM:
//         case EBPF_OP_LSH64_REG:
//         case EBPF_OP_RSH64_IMM:
//         case EBPF_OP_RSH64_REG:
//         case EBPF_OP_NEG64:
//         case EBPF_OP_MOD64_REG:
//         case EBPF_OP_XOR64_IMM:
//         case EBPF_OP_XOR64_REG:
//         case EBPF_OP_MOV64_IMM:
//         case EBPF_OP_MOV64_REG:
//         case EBPF_OP_ARSH64_IMM:
//         case EBPF_OP_ARSH64_REG:
//             break;

//         case EBPF_OP_LDXW:
//         case EBPF_OP_LDXH:
//         case EBPF_OP_LDXB:
//         case EBPF_OP_LDXDW:
//             break;

//         case EBPF_OP_STW:
//         case EBPF_OP_STH:
//         case EBPF_OP_STB:
//         case EBPF_OP_STDW:
//         case EBPF_OP_STXW:
//         case EBPF_OP_STXH:
//         case EBPF_OP_STXB:
//         case EBPF_OP_STXDW:
//             store = true;
//             break;

//         case EBPF_OP_LDDW:
//             if (i + 1 >= num_insts || insts[i+1].opcode != 0) {
//                 *errmsg = ubpf_error("incomplete lddw at PC %d", i);
//                 return false;
//             }
//             i++; /* Skip next instruction */
//             break;

//         case EBPF_OP_JA:
//         case EBPF_OP_JEQ_REG:
//         case EBPF_OP_JEQ_IMM:
//         case EBPF_OP_JGT_REG:
//         case EBPF_OP_JGT_IMM:
//         case EBPF_OP_JGE_REG:
//         case EBPF_OP_JGE_IMM:
//         case EBPF_OP_JSET_REG:
//         case EBPF_OP_JSET_IMM:
//         case EBPF_OP_JNE_REG:
//         case EBPF_OP_JNE_IMM:
//         case EBPF_OP_JSGT_IMM:
//         case EBPF_OP_JSGT_REG:
//         case EBPF_OP_JSGE_IMM:
//         case EBPF_OP_JSGE_REG:
//             if (inst.offset == -1) {
//                 *errmsg = ubpf_error("infinite loop at PC %d", i);
//                 return false;
//             }
//             int new_pc = i + 1 + inst.offset;
//             if (new_pc < 0 || new_pc >= num_insts) {
//                 *errmsg = ubpf_error("jump out of bounds at PC %d", i);
//                 return false;
//             } else if (insts[new_pc].opcode == 0) {
//                 *errmsg = ubpf_error("jump to middle of lddw at PC %d", i);
//                 return false;
//             }
//             break;

//         case EBPF_OP_CALL:
//             if (inst.imm < 0 || inst.imm >= MAX_EXT_FUNCS) {
//                 *errmsg = ubpf_error("invalid call immediate at PC %d", i);
//                 return false;
//             }
//             if (!vm->ext_funcs[inst.imm]) {
//                 *errmsg = ubpf_error("call to nonexistent function %u at PC %d", inst.imm, i);
//                 return false;
//             }
//             break;

//         case EBPF_OP_EXIT:
//             break;

//         case EBPF_OP_DIV_IMM:
//         case EBPF_OP_MOD_IMM:
//         case EBPF_OP_DIV64_IMM:
//         case EBPF_OP_MOD64_IMM:
//             if (inst.imm == 0) {
//                 *errmsg = ubpf_error("division by zero at PC %d", i);
//                 return false;
//             }
//             break;

//         default:
//             *errmsg = ubpf_error("unknown opcode 0x%02x at PC %d", inst.opcode, i);
//             return false;
//         }

//         if (inst.src > 10) {
//             *errmsg = ubpf_error("invalid source register at PC %d", i);
//             return false;
//         }

//         if (inst.dst > 9 && !(store && inst.dst == 10)) {
//             *errmsg = ubpf_error("invalid destination register at PC %d", i);
//             return false;
//         }
//     }

//     return true;
// }

char *
ebpflow_error(const char *fmt, ...)
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

int
ebpflow_status(struct ebpflow_fw *fw, char **errmsg)
{
    unsigned int val;
    int ret;

    //Clean register copies
    fw->regs.r0_eng_0      = 0;
    fw->regs.r0_eng_1      = 0;
    fw->regs.r0_eng_2      = 0;
    fw->regs.r0_eng_3      = 0;
    fw->regs.wrinst        = 0;
    fw->regs.curr_inst_mem = 0;

    //Read engine 0 register 0  
    ret = readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_ENG0LOR0, &val);
    if(ret){
        *errmsg = ebpflow_error("failed to read lower part of engine 0 register R0\n");
        return -1;
    }

    fw->regs.r0_eng_0 = val;

    ret = readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_ENG0HIR0, &val);
    if(ret){
        *errmsg = ebpflow_error("failed to read higher part of engine 0 register R0\n");
        fw->regs.r0_eng_0 = 0;
        return -1;
    }

    fw->regs.r0_eng_0 |= ((uint64_t)val)<<32;

    //Read engine 1 register 0  
    ret = readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_ENG1LOR0, &val);
    if(ret){
        *errmsg = ebpflow_error("failed to read lower part of engine 1 register R0\n");
        return -1;
    }

    fw->regs.r0_eng_1 = val;

    ret = readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_ENG1HIR0, &val);
    if(ret){
        *errmsg = ebpflow_error("failed to read higher part of engine 1 register R0\n");
        fw->regs.r0_eng_1 = 0;
        return -1;
    }

    fw->regs.r0_eng_1 |= ((uint64_t)val)<<32;

    //Read engine 2 register 0  
    ret = readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_ENG2LOR0, &val);
    if(ret){
        *errmsg = ebpflow_error("failed to read lower part of engine 2 register R0\n");
        return -1;
    }

    fw->regs.r0_eng_2 = val;

    ret = readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_ENG2HIR0, &val);
    if(ret){
        *errmsg = ebpflow_error("failed to read higher part of engine 2 register R0\n");
        fw->regs.r0_eng_2 = 0;
        return -1;
    }

    fw->regs.r0_eng_2 |= ((uint64_t)val)<<32;

    //Read engine 3 register 0  
    ret = readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_ENG3LOR0, &val);
    if(ret){
        *errmsg = ebpflow_error("failed to read lower part of engine 3 register R0\n");
        return -1;
    }

    fw->regs.r0_eng_3 = val;

    ret = readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_ENG3HIR0, &val);
    if(ret){
        *errmsg = ebpflow_error("failed to read higher part of engine 3 register R0\n");
        fw->regs.r0_eng_3 = 0;
        return -1;
    }

    fw->regs.r0_eng_3 |= ((uint64_t)val)<<32;

    ret = readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_WRINST, &val);
    if(ret){
        *errmsg = ebpflow_error("failed to read register WRINST\n");
        fw->regs.r0_eng_0 = 0;
        fw->regs.r0_eng_1 = 0;
        fw->regs.r0_eng_2 = 0;
        fw->regs.r0_eng_3 = 0;
        fw->regs.wrinst = 2; // ERROR
        return -1;
    }

    fw->regs.wrinst = val;

    ret = readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_CURRINSTMEM, &val);
    if(ret){
        *errmsg = ebpflow_error("failed to read register CURRINSTMEM\n");
        return -1;
    }

    fw->regs.curr_inst_mem = val;

    ret = readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_DEBUG, &val);
    if(ret){
        *errmsg = ebpflow_error("failed to read register DEBUG\n");
        return -1;
    }

    fw->regs.debug = val;
 
    printf("\nEngine 0 - Register 0: 0x%016lx\n",fw->regs.r0_eng_0);
    printf("Engine 1 - Register 0: 0x%016lx\n",fw->regs.r0_eng_1);
    printf("Engine 2 - Register 0: 0x%016lx\n",fw->regs.r0_eng_2);
    printf("Engine 3 - Register 0: 0x%016lx\n",fw->regs.r0_eng_3);
    printf("Instructions writen: %x\n",fw->regs.wrinst);
    printf("Current instruction memory: %x\n",fw->regs.curr_inst_mem);
    printf("Debug: 0x%08x\n",fw->regs.debug);

    return 0;
}

#define REG_FORMAT "%20s: "

int
ebpflow_show_debug_info(struct ebpflow_fw *fw){
  unsigned int val;

  printf("\n==============================\n");
  printf("   Debug - eBPF engine          \n");
  printf("==============================\n");
  readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_CTRLFSMSTATEENG0, &val);
  printf(" %5d : ctrl_fsm_state_eng_0 ", val);  

  readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_CTRLFSMSTATEENG1, &val);
  printf("\n %5d : ctrl_fsm_state_eng_1 ", val);  

  readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_CTRLFSMSTATEENG2, &val);
  printf("\n %5d : ctrl_fsm_state_eng_2 ", val);  

  readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_CTRLFSMSTATEENG3, &val);
  printf("\n %5d : ctrl_fsm_state_eng_3 ", val);  

  readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_FWFSMSTATEENG0, &val);
  printf("\n %5d : fw_fsm_state_eng_0 ", val);  

  readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_FWFSMSTATEENG1, &val);
  printf("\n %5d : fw_fsm_state_eng_1 ", val);  

  readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_FWFSMSTATEENG2, &val);
  printf("\n %5d : fw_fsm_state_eng_2 ", val);  

  readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_FWFSMSTATEENG3, &val);
  printf("\n %5d : fw_fsm_state_eng_3 ", val);  

  readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_TUSERREADYENG0, &val);
  printf("\n 0x%08lx : tuser_ready_eng_0 ", val);  

  readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_TUSERREADYENG1, &val);
  printf("\n 0x%08lx : tuser_ready_eng_1 ", val);  

  readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_TUSERREADYENG2, &val);
  printf("\n 0x%08lx : tuser_ready_eng_2 ", val);  

  readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_TUSERREADYENG3, &val);
  printf("\n 0x%08lx : tuser_ready_eng_3 \n", val);  

  printf("\n===============================\n");
  printf("   Debug - Coprocessor arbiter \n");
  printf("===============================\n");
  readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_COPROCARBFSMSTATE, &val);
  printf(" %5d : coproc_arb_fsm_state \n", val);  

  printf("\n===============================\n");
  printf("   Debug - Output arbiter      \n");
  printf("===============================\n");
  readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_OUTARBFSMSTATE, &val);
  printf(" %5d : out_arb_fsm_state \n", val);  

  printf("\n===============================\n");
  printf("   Debug - Rx/Tx packets      \n");
  printf("===============================\n");
  readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_RXPKTENG0, &val);
  printf(" %5d : rx_pkt_eng_0 ", val);  

  readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_RXPKTENG1, &val);
  printf("\n %5d : rx_pkt_eng_1 ", val);  

  readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_RXPKTENG2, &val);
  printf("\n %5d : rx_pkt_eng_2 ", val);  

  readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_RXPKTENG3, &val);
  printf("\n %5d : rx_pkt_eng_3 ", val);  

  readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_TXPKTENG0, &val);
  printf("\n %5d : tx_pkt_eng_0 ", val);  

  readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_TXPKTENG1, &val);
  printf("\n %5d : tx_pkt_eng_1 ", val);  

  readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_TXPKTENG2, &val);
  printf("\n %5d : tx_pkt_eng_2 ", val);  

  readReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_TXPKTENG3, &val);
  printf("\n %5d : tx_pkt_eng_3 \n", val);  
  printf("\n");

}

int
ebpflow_mem_clean(struct ebpflow_fw *fw, uint32_t memid, char **errmsg)
{
    unsigned int val; 
    unsigned int cam_busy;
    unsigned int tcam_busy;
    int ret;

    switch(memid){
        case BPFPROC_MAP_TCAM:
        case BPFPROC_MAP_CAM:
            break;
        default:
            *errmsg = ebpflow_error("No such memory type. Only 1 [TCAM] and 2 [CAM] allowed");
            return -1;
    }

    // Clean memory
    ret = ebpflow_write_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_CLEAN, memid, NULL);
    if(ret) return -1;
      
    //Ack clean memory   
    ret = ebpflow_read_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_CLEANACK, &val, NULL);
    if(ret) return -1;

    if(!val)
      printf("Running clean operation\n");  

    while(!val)
       ebpflow_read_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_CLEANACK, &val, NULL);

    return 0;
}

int
ebpflow_mem_dump(struct ebpflow_fw *fw, uint32_t memid, char **errmsg)
{
    unsigned int val; 
    unsigned int cam_busy; 
    unsigned int tcam_busy; 
    unsigned int ack_operation; 
    int mem_tcam_en = 0;  
    int ret;
   
      
    switch(memid){
        case BPFPROC_MAP_TCAM:
        case BPFPROC_MAP_CAM:
            break;
        default:
            *errmsg = ebpflow_error("No such memory type. Only 1 [TCAM] and 2 [CAM] allowed");
            return -1;
    }
     
    //Check if some call operation is running  
    ret = ebpflow_read_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_CAMBUSY, &cam_busy, NULL);
    if(ret) return -1; 

    ret = ebpflow_read_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_TCAMBUSY, &tcam_busy, NULL);
    if(ret) return -1; 
    
    if(cam_busy) printf("There is operation executing on CAM!\n");
    while(cam_busy)
      ebpflow_read_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_CAMBUSY, &cam_busy, NULL);

    if(tcam_busy) printf("There is operation executing on TCAM!\n");
    while(tcam_busy)
      ebpflow_read_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_TCAMBUSY, &tcam_busy, NULL);

    //Dump operation  
    ret = ebpflow_write_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_SELECTMEMORY, memid, NULL);
    if(ret) return -1;

    ret = ebpflow_write_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_OPERATION, BPFPROC_MAP_DUMP_OP, NULL);
    if(ret) return -1;

    if (memid == BPFPROC_MAP_TCAM){ 
       printf("============================= TCAM =========================\n");   
       printf("Id\t    Key\t\t      Mask\t        Value\n");   
       mem_tcam_en = 1; 
    }

    if (memid == BPFPROC_MAP_CAM) { 
       printf("==================== CAM ================\n");   
       printf("Id          Key\t              Value\n");   
    }  
   
    for (int i=0; i<TABLE_NAME_MAX_LENGTH; i++) 
    {   
       //Clean register copies
       fw->regs.key   = 0; 
       fw->regs.mask  = 0; 
       fw->regs.value = 0; 
       
       //Key 
       ret = ebpflow_read_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_HIKEY, &val, NULL);
       if(ret) return -1;
       fw->regs.key |= ((uint64_t)val)<<32;  
       ret = ebpflow_read_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_LOKEY, &val, NULL);
       if(ret) return -1;
       fw->regs.key |= val; 
   
       //Value
       ret = ebpflow_read_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_HIDIN, &val, NULL);
       if(ret) return -1;
       fw->regs.value |= ((uint64_t)val)<<32;  
       ret = ebpflow_read_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_LODIN, &val, NULL);
       if(ret) return -1;
       fw->regs.value |= val;

       //Mask  
       if (mem_tcam_en) {  
          ret = ebpflow_read_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_HIMASK, &val, NULL);
          if(ret) return -1;
          fw->regs.mask |= ((uint64_t)val)<<32;  
          ret = ebpflow_read_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_LOMASK, &val, NULL);
          if(ret) return -1;
          fw->regs.mask |= val;  
       } 
      
       if (mem_tcam_en)    
         printf("%2d: 0x%016lx 0x%016lx 0x%016lx\n", i, fw->regs.key, fw->regs.mask, fw->regs.value);   
       else   
         printf("%2d: 0x%016lx 0x%016lx\n", i, fw->regs.key, fw->regs.value);   
    } 
    
    //Ack memory   
    ret = ebpflow_read_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_ACK, &ack_operation, NULL);
    if(ret) return -1;

    if(!ack_operation)
      printf("\nRunning dump operation!\n");  

    while(!ack_operation)
       ebpflow_read_register(fw,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_CLEANACK, &val, NULL);

    //printf("\nDump operation finished!\n\n");  

    return 0;
}

int
ebpflow_wrinst_clean(struct ebpflow_fw *fw, char **errmsg)
{
    unsigned int val;
    int ret;

    // Clean WRINST register
    ret = writeReg(fw->conn,SUME_EBPF_OUTPUT_PORT_LOOKUP_0_WRINST, 0);
    if(ret){
        *errmsg = ebpflow_error("failed to write register WRINST");
        fw->regs.wrinst = 2; // ERROR
        return -1;
    }

    // On sucess, clean register copy
    fw->regs.wrinst = 0;

    return 0;
}

uint32_t ebpflow_get_num_insts(const struct ebpflow_fw *fw){
    return fw->num_insts;
}

int
ebpflow_dump_maps(const struct ebpflow_fw *fw)
{
    unsigned int n_maps;
    ght_iterator_t iterator;
    void *key;
    void *elem;
    struct table_entry *map;

    if(fw == NULL){
        printf("Firmware not initialized.\n");
        return 1;
    }

    if(fw->maps == NULL){
        printf("No maps loaded.\n");
        return 0;
    }

    n_maps = ght_size(fw->maps);
    if(n_maps == 0){
        printf("No maps listed.\n");
        return 0;
    }

    // printf("Number of maps: %d\n",n_maps);

    for(elem = ght_first(fw->maps, &iterator, &key); elem; elem = ght_next(fw->maps, &iterator, &key)){
        map = (struct table_entry *) elem;

        printf("[%s]\n id:\t\t%d\n type:\t\t%d\n key_size:\t%d bytes\n val_size:\t%d bytes\n max_elems:\t%d\n",
                (char*)key,map->id,map->type,map->key_size,map->value_size,map->max_entries);
        printf(" -------------------------\n");
        bpf_print_map(map->id);
    }

    printf("\n");

    return 0;
}

int
ebpflow_init_soft_maps(const struct ebpflow_fw *fw, char **errmsg){
    unsigned int n_maps;
    ght_iterator_t iterator;
    void *key;
    void *elem;
    struct table_entry *map;
    int ret;

    if(fw == NULL){
        *errmsg = ebpflow_error("Firmware not initialized.\n");
        return 1;
    }

    // Allocate maps

    if(fw->maps == NULL){
        *errmsg = ebpflow_error("Maps table not initialized.\n");
        return 1;
    }

    n_maps = ght_size(fw->maps);

    for(elem = ght_first(fw->maps, &iterator, &key); elem; elem = ght_next(fw->maps, &iterator, &key)){
        map = (struct table_entry *) elem;
        ret = bpf_create_map(map->type,map->key_size,map->value_size,map->max_entries,map->id);
        if(ret){
            *errmsg = ebpflow_error("Failed to initialize software map.\n");
            goto free_maps;
        }
    }

    return 0;

    free_maps:
    // TODO: Write code to free currently allocated maps
    return -1;
}

uint64_t
ebpflow_exec(const struct ebpflow_fw *fw, void *mem, size_t mem_len)
{
    uint16_t pc = 0;
    const struct ebpf_inst *insts = fw->insts;
    uint64_t reg[16] = {0};
    uint64_t stack[(STACK_SIZE+7)/8];

    if (!insts) {
        /* Code must be loaded before we can execute */
        return UINT64_MAX;
    }

    reg[1] = (uintptr_t)mem;
    reg[10] = (uintptr_t)stack + sizeof(stack);

    while (1) {
        const uint16_t cur_pc = pc;
        struct ebpf_inst inst = insts[pc++];

        switch (inst.opcode) {
        case EBPF_OP_ADD_IMM:
            reg[inst.dst] += inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_ADD_REG:
            reg[inst.dst] += reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_SUB_IMM:
            reg[inst.dst] -= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_SUB_REG:
            reg[inst.dst] -= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MUL_IMM:
            reg[inst.dst] *= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MUL_REG:
            reg[inst.dst] *= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_DIV_IMM:
            reg[inst.dst] = u32(reg[inst.dst]) / u32(inst.imm);
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_DIV_REG:
            if (reg[inst.src] == 0) {
                fprintf(stderr, "uBPF error: division by zero at PC %u\n", cur_pc);
                return UINT64_MAX;
            }
            reg[inst.dst] = u32(reg[inst.dst]) / u32(reg[inst.src]);
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_OR_IMM:
            reg[inst.dst] |= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_OR_REG:
            reg[inst.dst] |= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_AND_IMM:
            reg[inst.dst] &= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_AND_REG:
            reg[inst.dst] &= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_LSH_IMM:
            reg[inst.dst] <<= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_LSH_REG:
            reg[inst.dst] <<= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_RSH_IMM:
            reg[inst.dst] = u32(reg[inst.dst]) >> inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_RSH_REG:
            reg[inst.dst] = u32(reg[inst.dst]) >> reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_NEG:
            reg[inst.dst] = -reg[inst.dst];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MOD_IMM:
            reg[inst.dst] = u32(reg[inst.dst]) % u32(inst.imm);
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MOD_REG:
            if (reg[inst.src] == 0) {
                fprintf(stderr, "uBPF error: division by zero at PC %u\n", cur_pc);
                return UINT64_MAX;
            }
            reg[inst.dst] = u32(reg[inst.dst]) % u32(reg[inst.src]);
            break;
        case EBPF_OP_XOR_IMM:
            reg[inst.dst] ^= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_XOR_REG:
            reg[inst.dst] ^= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MOV_IMM:
            reg[inst.dst] = inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MOV_REG:
            reg[inst.dst] = reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_ARSH_IMM:
            reg[inst.dst] = (int32_t)reg[inst.dst] >> inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_ARSH_REG:
            reg[inst.dst] = (int32_t)reg[inst.dst] >> u32(reg[inst.src]);
            reg[inst.dst] &= UINT32_MAX;
            break;

        case EBPF_OP_LE:
            if (inst.imm == 16) {
                reg[inst.dst] = htole16(reg[inst.dst]);
            } else if (inst.imm == 32) {
                reg[inst.dst] = htole32(reg[inst.dst]);
            } else if (inst.imm == 64) {
                reg[inst.dst] = htole64(reg[inst.dst]);
            }
            break;
        case EBPF_OP_BE:
            if (inst.imm == 16) {
                reg[inst.dst] = htobe16(reg[inst.dst]);
            } else if (inst.imm == 32) {
                reg[inst.dst] = htobe32(reg[inst.dst]);
            } else if (inst.imm == 64) {
                reg[inst.dst] = htobe64(reg[inst.dst]);
            }
            break;


        case EBPF_OP_ADD64_IMM:
            reg[inst.dst] += inst.imm;
            break;
        case EBPF_OP_ADD64_REG:
            reg[inst.dst] += reg[inst.src];
            break;
        case EBPF_OP_SUB64_IMM:
            reg[inst.dst] -= inst.imm;
            break;
        case EBPF_OP_SUB64_REG:
            reg[inst.dst] -= reg[inst.src];
            break;
        case EBPF_OP_MUL64_IMM:
            reg[inst.dst] *= inst.imm;
            break;
        case EBPF_OP_MUL64_REG:
            reg[inst.dst] *= reg[inst.src];
            break;
        case EBPF_OP_DIV64_IMM:
            reg[inst.dst] /= inst.imm;
            break;
        case EBPF_OP_DIV64_REG:
            if (reg[inst.src] == 0) {
                fprintf(stderr, "uBPF error: division by zero at PC %u\n", cur_pc);
                return UINT64_MAX;
            }
            reg[inst.dst] /= reg[inst.src];
            break;
        case EBPF_OP_OR64_IMM:
            reg[inst.dst] |= inst.imm;
            break;
        case EBPF_OP_OR64_REG:
            reg[inst.dst] |= reg[inst.src];
            break;
        case EBPF_OP_AND64_IMM:
            reg[inst.dst] &= inst.imm;
            break;
        case EBPF_OP_AND64_REG:
            reg[inst.dst] &= reg[inst.src];
            break;
        case EBPF_OP_LSH64_IMM:
            reg[inst.dst] <<= inst.imm;
            break;
        case EBPF_OP_LSH64_REG:
            reg[inst.dst] <<= reg[inst.src];
            break;
        case EBPF_OP_RSH64_IMM:
            reg[inst.dst] >>= inst.imm;
            break;
        case EBPF_OP_RSH64_REG:
            reg[inst.dst] >>= reg[inst.src];
            break;
        case EBPF_OP_NEG64:
            reg[inst.dst] = -reg[inst.dst];
            break;
        case EBPF_OP_MOD64_IMM:
            reg[inst.dst] %= inst.imm;
            break;
        case EBPF_OP_MOD64_REG:
            if (reg[inst.src] == 0) {
                fprintf(stderr, "uBPF error: division by zero at PC %u\n", cur_pc);
                return UINT64_MAX;
            }
            reg[inst.dst] %= reg[inst.src];
            break;
        case EBPF_OP_XOR64_IMM:
            reg[inst.dst] ^= inst.imm;
            break;
        case EBPF_OP_XOR64_REG:
            reg[inst.dst] ^= reg[inst.src];
            break;
        case EBPF_OP_MOV64_IMM:
            reg[inst.dst] = inst.imm;
            break;
        case EBPF_OP_MOV64_REG:
            reg[inst.dst] = reg[inst.src];
            break;
        case EBPF_OP_ARSH64_IMM:
            reg[inst.dst] = (int64_t)reg[inst.dst] >> inst.imm;
            break;
        case EBPF_OP_ARSH64_REG:
            reg[inst.dst] = (int64_t)reg[inst.dst] >> reg[inst.src];
            break;

        /*
         * HACK runtime bounds check
         *
         * Needed since we don't have a verifier yet.
         */
#define BOUNDS_CHECK_LOAD(size)
#define BOUNDS_CHECK_STORE(size)

        case EBPF_OP_LDXW:
            BOUNDS_CHECK_LOAD(4);
            reg[inst.dst] = *(uint32_t *)(uintptr_t)(reg[inst.src] + inst.offset);
            break;
        case EBPF_OP_LDXH:
            BOUNDS_CHECK_LOAD(2);
            reg[inst.dst] = *(uint16_t *)(uintptr_t)(reg[inst.src] + inst.offset);
            break;
        case EBPF_OP_LDXB:
            BOUNDS_CHECK_LOAD(1);
            reg[inst.dst] = *(uint8_t *)(uintptr_t)(reg[inst.src] + inst.offset);
            break;
        case EBPF_OP_LDXDW:
            BOUNDS_CHECK_LOAD(8);
            reg[inst.dst] = *(uint64_t *)(uintptr_t)(reg[inst.src] + inst.offset);
            break;

        case EBPF_OP_STW:
            BOUNDS_CHECK_STORE(4);
            *(uint32_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = inst.imm;
            break;
        case EBPF_OP_STH:
            BOUNDS_CHECK_STORE(2);
            *(uint16_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = inst.imm;
            break;
        case EBPF_OP_STB:
            BOUNDS_CHECK_STORE(1);
            *(uint8_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = inst.imm;
            break;
        case EBPF_OP_STDW:
            BOUNDS_CHECK_STORE(8);
            *(uint64_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = inst.imm;
            break;

        case EBPF_OP_STXW:
            BOUNDS_CHECK_STORE(4);
            *(uint32_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = reg[inst.src];
            break;
        case EBPF_OP_STXH:
            BOUNDS_CHECK_STORE(2);
            *(uint16_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = reg[inst.src];
            break;
        case EBPF_OP_STXB:
            BOUNDS_CHECK_STORE(1);
            *(uint8_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = reg[inst.src];
            break;
        case EBPF_OP_STXDW:
            BOUNDS_CHECK_STORE(8);
            *(uint64_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = reg[inst.src];
            break;

        case EBPF_OP_LDDW:
            reg[inst.dst] = (uint32_t)inst.imm | ((uint64_t)insts[pc++].imm << 32);
            break;

        case EBPF_OP_JA:
            pc += inst.offset;
            break;
        case EBPF_OP_JEQ_IMM:
            if (reg[inst.dst] == inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JEQ_REG:
            if (reg[inst.dst] == reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGT_IMM:
            if (reg[inst.dst] > (uint32_t)inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGT_REG:
            if (reg[inst.dst] > reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGE_IMM:
            if (reg[inst.dst] >= (uint32_t)inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGE_REG:
            if (reg[inst.dst] >= reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JLT_IMM:
            if (reg[inst.dst] < (uint32_t)inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JLT_REG:
            if (reg[inst.dst] < reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JLE_IMM:
            if (reg[inst.dst] <= (uint32_t)inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JLE_REG:
            if (reg[inst.dst] <= reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSET_IMM:
            if (reg[inst.dst] & inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSET_REG:
            if (reg[inst.dst] & reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JNE_IMM:
            if (reg[inst.dst] != inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JNE_REG:
            if (reg[inst.dst] != reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGT_IMM:
            if ((int64_t)reg[inst.dst] > inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGT_REG:
            if ((int64_t)reg[inst.dst] > (int64_t)reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGE_IMM:
            if ((int64_t)reg[inst.dst] >= inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGE_REG:
            if ((int64_t)reg[inst.dst] >= (int64_t)reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSLT_IMM:
            if ((int64_t)reg[inst.dst] < inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSLT_REG:
            if ((int64_t)reg[inst.dst] < (int64_t)reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSLE_IMM:
            if ((int64_t)reg[inst.dst] <= inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSLE_REG:
            if ((int64_t)reg[inst.dst] <= (int64_t)reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_EXIT:
            return reg[0];
        case EBPF_OP_CALL:
            reg[0] = fw->ext_funcs[inst.imm](reg[1], reg[2], reg[3], reg[4], reg[5]);
            break;
        }
    }
}
