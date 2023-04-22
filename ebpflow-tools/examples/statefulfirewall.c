/* ==================== UDP Stateful Firewall ====================
 * This example implements a UDP Stateful Firewall. The code
 * is a direct adaptation of the same example from FlowBlaze 
 * project.
 */

#include <linux/if_ether.h>
#include "ebpflow_switch.h"

struct bpf_map_def SEC("maps") inports = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size 	= 1,   //Input port is the key
	.value_size = sizeof(uint8_t), //Ouput port is the value
	.max_entries = 256,
};

uint64_t prog(struct packet *pkt)
{

 /* 
 -> Rules 
 - 1: port 1 -> port 0;   
 - 2: port 0 -> port 1; 
 
 -> Note: 
 - R1: Accept connection and forward the packet;
 - R2: Check R1 and establish connection if R1 there is on map; 
 */

 uint8_t  port_0 = 0; 
 uint8_t  port_1 = 1; 
 uint64_t outport; 
  
 //Lookup reverse flow. 
 outport = bpf_map_lookup_elem(&inports, &port_1);
 if (outport == LOOKUP_FAIL) {
   //Add reverse flow rule 
   if (pkt->metadata.in_port == port_1)
     bpf_map_update_elem(&inports, &port_1, &port_0, 0);

   return DROP; 
 }

 if (pkt->metadata.in_port == port_0)
   return port_1; 

 return outport;

}

char _license[] SEC("license") = "GPL";

