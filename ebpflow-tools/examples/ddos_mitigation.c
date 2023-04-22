#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "ebpf_endian.h"
#include "ebpflow_switch.h"

// #include "ebpf_helpers.h"

/* 0x3FFF mask to check for fragment offset field */
#define IP_FRAGMENTED 65343

#define DROP_PORT 4000

static inline int process_packet(struct packet *pkt, __u64 off){
	void *data = (void*)&pkt->eth;
	void *data_end = (void*)((char*)data + pkt->metadata.length_pkt);
	struct iphdr *iph;
	__u8 protocol;

	iph = data + off;
	if ((void*)(iph + 1) > data_end)
		return DROP;
	if (iph->ihl != 5)
		return DROP;

	protocol = iph->protocol;
	off += sizeof(struct iphdr);

	/* do not support fragmented packets as L4 headers may be missing */
	if (iph->frag_off & IP_FRAGMENTED)
		return DROP;

	/* obtain port numbers for UDP and TCP traffic */
	if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
		struct udphdr *tudp = data + off;
		/* Port offset on both TCP and UDP is the same, so we can
		   actually access either one using the same struct
		   OBS: This only works for port values.*/

		if(bpf_ntohs(tudp->dest) == DROP_PORT){
			return DROP;
		}
	} else {
		return DROP;
	}

	return 0;
}

uint64_t prog(struct packet *pkt){
	void *data = (void*)&pkt->eth;
	void *data_end = (void*)((char*)data + pkt->metadata.length_pkt);
	struct ethhdr *eth = data;
	__u32 eth_proto;
	__u32 nh_off;
	int ret = 0;

	nh_off = sizeof(struct ethhdr);
	if (data + nh_off > data_end)
		goto pass;

	eth_proto = eth->h_proto;

	/* demo program only accepts ipv4 packets */
	if (eth_proto == bpf_htons(ETH_P_IP))
		ret = process_packet(pkt, nh_off);

	if(ret)
		return DROP;

pass:
	return pkt->metadata.in_port ^ 0x1;
}