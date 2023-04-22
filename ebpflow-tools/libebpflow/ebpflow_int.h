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

#ifndef EBPFLOW_INT_H
#define EBPFLOW_INT_H

#include <ebpflow.h>
#include <ght_hash_table.h>

#include "ebpf.h"

#define MAX_INSTS 65536
#define STACK_SIZE 16384

struct ebpf_inst;
typedef uint64_t (*ext_func)(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4);

struct ebpflow_regs {
    uint64_t r0_eng_0;
    uint64_t r0_eng_1;
    uint64_t r0_eng_2;
    uint64_t r0_eng_3;
    uint32_t wrinst;
    uint32_t curr_inst_mem;
    uint64_t key;
    uint64_t mask;
    uint64_t value;



    uint32_t debug;
};

struct ebpflow_fw {
    int conn; // connection to NetFPGA
    struct ebpf_inst *insts;
    uint16_t num_insts;
    // ubpf_jit_fn jitted;
    // size_t jitted_size;
    ext_func *ext_funcs;
    const char **ext_func_names;
    ght_hash_table_t* maps; // Hash table containing the list of maps
    struct ebpflow_regs regs;
};

char *ebpflow_error(const char *fmt, ...);
unsigned int ebpflow_lookup_registered_function(struct ebpflow_fw *fw, const char *name);

#endif
