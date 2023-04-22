/* ======================= IP Router =======================
 * This example implements a basic IP router.
 */

#include <linux/if_ether.h>
#include <linux/ip.h>
#include "ebpflow_switch.h"
#include "ebpf_endian.h"

struct bpf_map_def SEC("maps") route = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = sizeof(uint32_t),   // IP dest
	.value_size = sizeof(uint32_t), // Output port
	.max_entries = 16,              // No effect for now
};

uint64_t prog(struct packet *pkt)
{
	uint64_t out_port;
	uint32_t pkt_len = pkt->metadata.length_pkt;
	struct ethhdr *eth = &pkt->eth;
	struct iphdr *ip;

	if(eth->h_proto != bpf_htons(ETH_P_IP))
		return DROP;

	ip = (void*) &pkt->eth + sizeof(struct ethhdr);

	if((void*)(ip + 1) > (void*)(&pkt->eth + pkt_len))
		return DROP; 

	out_port = bpf_map_lookup_elem(&route,&ip->daddr);

	if(out_port == LOOKUP_FAIL)
		return DROP; 

	return out_port;
}
