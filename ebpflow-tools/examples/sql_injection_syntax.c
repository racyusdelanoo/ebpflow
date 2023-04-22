#include <stdbool.h>
#include <string.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <limits.h>
#include "ebpf_endian.h"
#include "ebpflow_switch.h"
#include "jhash.h"

/* 0x3FFF mask to check for fragment offset field */
#define IP_FRAGMENTED 65343

// Regular expression to find SQL injection attack using SQL syntax
static __always_inline int lex(uint8_t *pkt_data, uint32_t payload_len) {
    {
        uint8_t yych;
        uint16_t off = payload_len - 55;
        uint32_t i = 0;
        yych = *pkt_data;
        yy1:
            if (yych == 0x22) goto yy2;
            if (yych == 0x27) goto yy2;
            if (i == off) return 0;
            yych = *++pkt_data;
            i += 1;
            goto yy1;

        yy2:
            if (i == off) return 0;
            yych = *++pkt_data;
            i += 1;
            if (yych == 0x09) goto yy2;
            if (yych == 0x20) goto yy2;
            if (yych == 'o') goto yy4;
            if (yych == 'O') goto yy4;
            goto yy1;

        yy4:
            if (i == off) return 0;
            yych = *++pkt_data;
            i += 1;
            if (yych == 'r') goto yy5;
            if (yych == 'R') goto yy5;
            goto yy1;

        yy5: {return DROP;}
    }
}

// Regular expression to find HTTP headers
static __always_inline int http_verb_sniffer(uint8_t *pkt_data, uint32_t payload_len) {

	switch (*pkt_data) {
    	case 'D':	goto d;
    	case 'G':	goto g;
    	case 'P':	goto p;
    	default:	goto http_pass;
	}

    // DELETE
    d:
        if ((*(pkt_data + 1) == 'E') && (*(pkt_data + 2) == 'L')
        && (*(pkt_data + 3) == 'E') && (*(pkt_data + 4) == 'T')
        && (*(pkt_data + 5) == 'E')) {return 6;}
        goto http_pass;

    // GET
    g:
        if ((*(pkt_data + 1) == 'E')
        && (*(pkt_data + 2) == 'T')) {return 3;};
        goto http_pass;

    // PUT, POST, PATCH
    p:
        if ((*(pkt_data + 1) == 'U')
        && (*(pkt_data + 2) == 'T')) {return 3;}
        else if ((*(pkt_data + 1) == 'O')
        && (*(pkt_data + 2) == 'S') && (*(pkt_data + 3) == 'T')) {return 4;}
        else if ((*(pkt_data + 1) == 'A') && (*(pkt_data + 2) == 'T')
        && (*(pkt_data + 3) == 'C') && (*(pkt_data + 4) == 'H')) {return 5;}
        goto http_pass;

    // No HTTP verb
    http_pass:
        return 0;
}

// Function responsible for parsing TCP header
static __always_inline int parse_tcp(void *data, __u64 off, void *data_end) {

    uint64_t hlen;
	struct tcphdr *tcp;

	tcp = data + off;
	if ((void*)(tcp + 1) > data_end) return 0;

    hlen = ((uint64_t) tcp->doff) << 2;

	if ((void*)tcp + hlen > data_end) return 0;

	return hlen;
}

// Function responsible for start parsing protocols and processing packet contents
static __always_inline int process_packet(struct packet *pkt, __u64 off) {
    
	struct iphdr *iph;
	void* pkt_end = (void*)&pkt->eth + pkt->metadata.length_pkt;
	__u8 protocol;
    __u64 ret = 0;

	iph = (void*)&pkt->eth + off;
	if (iph->ihl != 5) return 0;

	protocol = iph->protocol;
	off += sizeof(struct iphdr);

	// Do not support fragmented packets as L4 headers may be missing
	if (iph->frag_off & IP_FRAGMENTED) return 0;
    
	if (protocol == IPPROTO_TCP) {
		if (!(ret = parse_tcp(&pkt->eth, off, pkt_end))) return 0;
        else off += ret;
    }
	else return 0;

    // Drop the packet to avoid invalid memory access
    // http://stackoverflow.com/questions/25047905/http-request-minimum-size-in-bytes
    //Tests with pktgen comment this line because it doesn't generate 
    //HTTP packets 
    //if (pkt->metadata.length_pkt - 54 < 16) return 0;
   
    uint8_t *pkt_data = (void*)&pkt->eth + off;

    //Tests with pktgen comment this line because it doesn't generate 
    //HTTP packets 
    //if (!(ret = http_verb_sniffer(pkt_data, pkt->metadata.length_pkt))) return 0;
    //pkt_data += ret;

    if(lex(pkt_data, pkt->metadata.length_pkt - ret)) return DROP;
    return 0;
}

// Main eBPF function
uint64_t prog(struct packet *pkt) {
    
	struct ethhdr *eth = &pkt->eth;
	__u32 nh_off;

	nh_off = sizeof(struct ethhdr);

	if(eth->h_proto != bpf_htons(ETH_P_IP))
		return DROP;
   
	if(process_packet(pkt, nh_off)) return DROP;
    
   return pkt->metadata.in_port ^ 0x1;
}
