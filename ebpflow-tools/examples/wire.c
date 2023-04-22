#include <linux/if_ether.h>
#include "ebpflow_switch.h"

uint64_t prog(struct packet *pkt)
{
	return pkt->metadata.in_port ^ 1;
}
char _license[] SEC("license") = "GPL";