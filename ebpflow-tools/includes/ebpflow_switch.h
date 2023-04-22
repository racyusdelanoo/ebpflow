#ifndef __EBPF_SWITCH_H
#define __EBPF_SWITCH_H

#include <linux/bpf.h>
#include "ebpflow_consts.h"
#include "ebpflow_functions.h"

#define SEC(NAME) __attribute__((section(NAME), used))

struct bpf_map_def {
	unsigned int type;
	uint64_t     key_size;
	uint64_t     value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

#endif
