#ifndef __EBPFLOW_SWITCH_CONSTS_H
#define __EBPFLOW_SWITCH_CONSTS_H

#include <linux/if_ether.h>
#include <stdint.h>

// Actions
#define DROP       0xfff0
#define CONTROLLER 0xfff1
#define FLOOD      0xffff

// Return codes
#define LOOKUP_FAIL 0xFFFFFFFF

// We need this so we can run the loader on kernels
// older than 4.11. The NetFPGA requires 4.10.17
#ifndef BPF_MAP_TYPE_HASH
#define BPF_MAP_TYPE_HASH 2
#endif

#ifndef BPF_MAP_TYPE_LPM_TRIE
#define BPF_MAP_TYPE_LPM_TRIE 11
#endif

// Metadata header (32 Bytes)
struct metadatahdr {
	uint8_t   in_port;
	uint8_t   src_queue;
	uint8_t   dst_queue;
	uint32_t  timestamp_sec;
	uint32_t  timestamp_nsec;
	uint16_t  length_pkt;
	uint8_t   headroom[19];
} __attribute__((packed));

struct packet {
	struct metadatahdr metadata;
	struct ethhdr eth;
};

#endif /* __EBPFLOW_SWITCH_CONSTS_H */
