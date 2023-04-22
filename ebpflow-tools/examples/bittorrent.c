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

// Regular expression to find bittorrent packets
static __always_inline int lex(uint8_t *pkt_data, void *pkt_end) {

    uint8_t yych;
    yych = *pkt_data;

    if (yych == 'g') goto yy1;
    if (yych == 'G') goto yy2;
    if (yych == 'a') goto yy3;
    if (yych == 0x13) goto yy4;
    return 0;

    yy1:
      if((void*) pkt_data + 20 > pkt_end - 1) return 0;
      pkt_data++;
      if ((*pkt_data == 'e') && (*++pkt_data == 't') && (*++pkt_data == ' ') && (*++pkt_data == '/') && (*++pkt_data == 'c') &&
         (*++pkt_data == 'l') && (*++pkt_data == 'i') && (*++pkt_data == 'e') && (*++pkt_data == 'n') && (*++pkt_data == 't') &&
         (*++pkt_data == '/') && (*++pkt_data == 'b') && (*++pkt_data == 'i') && (*++pkt_data == 't') && (*++pkt_data == 'c') &&
         (*++pkt_data == 'o') && (*++pkt_data == 'm') && (*++pkt_data == 'e') && (*++pkt_data == 't') && (*++pkt_data == '/')) return 1;
      return 0;

    yy2:
      if((void*) pkt_data + 13 > pkt_end - 1) return 0;
      pkt_data++;
      if ((*pkt_data == 'E') && (*++pkt_data == 'T') && (*++pkt_data == ' ') && (*++pkt_data == '/') && (*++pkt_data == 'd') &&
         (*++pkt_data == 'a') && (*++pkt_data == 't') && (*++pkt_data == 'a') && (*++pkt_data == '?') && (*++pkt_data == 'f') &&
        (*++pkt_data == 'i') && (*++pkt_data == 'd') && (*++pkt_data == '=')) return 1;
      return 0;

    yy3:
      if((void*) pkt_data + 6 > pkt_end - 1) return 0;
      pkt_data++;
      if ((*pkt_data == 'z') && (*++pkt_data == 'v') && (*++pkt_data == 'e') &&
         (*++pkt_data == 'r') && (*++pkt_data == 0x01) && (*++pkt_data == '$')) return 1;
      return 0;

    yy4:
      if((void*) pkt_data + 19 > pkt_end - 1) return 0;
      pkt_data++;
      if ((*pkt_data == 'b') && (*++pkt_data == 'i') && (*++pkt_data == 't') && (*++pkt_data == 't') && (*++pkt_data == 'o') &&
         (*++pkt_data == 'r') && (*++pkt_data == 'r') && (*++pkt_data == 'e') && (*++pkt_data == 'n') && (*++pkt_data == 't') &&
         (*++pkt_data == ' ') && (*++pkt_data == 'p') && (*++pkt_data == 'r') && (*++pkt_data == 'o') && (*++pkt_data == 't') &&
         (*++pkt_data == 'o') && (*++pkt_data == 'c') && (*++pkt_data == 'o') && (*++pkt_data == 'l')) return 1;
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

    uint8_t *pkt_data = (void*)&pkt->eth + off;

    if (lex(pkt_data, pkt_end)) return DROP;
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

