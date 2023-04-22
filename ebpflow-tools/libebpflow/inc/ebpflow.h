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

#ifndef EBPFLOW_H
#define EBPFLOW_H

#include <stdint.h>
// #include <stddef.h>

#define TABLE_NAME_MAX_LENGTH 32
#define TABLE_MAX_ENTRIES 64

struct table_entry {
    int id;
    int type;
    uint64_t key_size;
    uint64_t value_size;
    int max_entries;
};

#define MAX_EXT_FUNCS         64
#define MAX_MAPS	          64

// Map type definitions for the processor
#define BPFPROC_MAP_TCAM 1
#define BPFPROC_MAP_CAM	 2

// Map operations for the processor
#define BPFPROC_MAP_INSERT_OP 0
#define BPFPROC_MAP_DUMP_OP 4

// Available modes to load code
#define BPFPROC_MODE_TEST 0
#define BPFPROC_MODE_ROUTER 1

struct ebpflow_fw;
// typedef uint64_t (*ubpf_jit_fn)(void *mem, size_t mem_len);

struct ebpflow_fw *ebpflow_create(void);

void ebpflow_destroy(struct ebpflow_fw *fw);

int ebpflow_register(struct ebpflow_fw *fw, unsigned int idx, const char *name, void *fn);

int ebpflow_init_soft_maps(const struct ebpflow_fw *fw, char **errmsg);

int ebpflow_soft_map_insert(const struct ebpflow_fw *fw, char* map_name, uint64_t key, uint64_t val);

int ebpflow_install_rules(struct ebpflow_fw *fw, char **inrules);

int ebpflow_load_code(struct ebpflow_fw *fw, const void *code, uint32_t code_len, int mode, int payload, char **errmsg);

int ebpflow_load_txt(struct ebpflow_fw *fw, char* filepath, int mode, int payload, char **errmsg);

uint32_t ebpflow_parse_elf(struct ebpflow_fw *fw, char *filepath, void **code, char **errmsg);

int ebpflow_status(struct ebpflow_fw *fw, char **errmsg);

int ebpflow_show_debug_info(struct ebpflow_fw *fw);

int ebpflow_mem_clean(struct ebpflow_fw *fw, uint32_t memid, char **errmsg);

int ebpflow_mem_dump(struct ebpflow_fw *fw, uint32_t memid, char **errmsg);

int ebpflow_wrinst_clean(struct ebpflow_fw *fw, char **errmsg);

int ebpflow_dump_maps(const struct ebpflow_fw *fw);

uint64_t ebpflow_exec(const struct ebpflow_fw *fw, void *mem, size_t mem_len);

uint32_t ebpflow_get_num_insts(const struct ebpflow_fw *fw);

#endif
