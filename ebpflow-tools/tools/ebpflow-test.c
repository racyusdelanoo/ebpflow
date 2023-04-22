#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <pcap.h>
#include <string.h>
#include <linux/if_ether.h>
#include <errno.h>
#include <limits.h>

#include <ebpflow.h>

#include "ebpflow_consts.h"
#include "elf_utils.h"
// #include "ebpf.h"

#define MAXMTU 1500

/* Flags */
#define SHOW_BEFORE 0x1
#define SHOW_AFTER	0x2

struct args {
		struct ebpflow_fw *fw;
		unsigned char *pktbuf;
		size_t buflen;
		int count;
		int flags;
		uint8_t inport;
		pcap_dumper_t *dumper;
};

void hex_dump(char* desc, void* addr, int len){
		int i;
		unsigned char buff[17];
		unsigned char *pc = (unsigned char*)addr;

		// Output description if given.
		if (desc != NULL)
				printf ("%s:\n", desc);

		if (len == 0) {
				printf("  ZERO LENGTH\n");
				return;
		}
		if (len < 0) {
				printf("  NEGATIVE LENGTH: %i\n",len);
				return;
		}

		// Process every byte in the data.
		for (i = 0; i < len; i++) {
				// Multiple of 16 means new line (with line offset).

				if ((i % 16) == 0) {
						// Just don't print ASCII for the zeroth line.
						if (i != 0)
								printf ("  %s\n", buff);

						// Output the offset.
						printf ("  %04x ", i);
				}

				// Now the hex code for the specific character.
				printf (" %02x", pc[i]);

				// And store a printable ASCII character for later.
				if ((pc[i] < 0x20) || (pc[i] > 0x7e))
						buff[i % 16] = '.';
				else
						buff[i % 16] = pc[i];
				buff[(i % 16) + 1] = '\0';
		}

		// Pad out last line if not exactly 16 characters.
		while ((i % 16) != 0) {
				printf ("   ");
				i++;
		}

		// And print the final ASCII bit.
		printf ("  %s\n", buff);
}

void try_message(){
		printf("Try 'ebpflow-test -h' for more information.\n");
}

void usage(){
		printf(
				"Usage: ebpflow-test [FLAGS] -f <pcap-file> <ebpf-file.o>\n"
				"Tool to test eBPF code on eBPFlow Switch emulator.\n"
				"\n"
				"Options:\n"
				"   -f PCAP-FILE             Input pcap file (required)\n"
				"   -r RULES-FILE            Rules to be added to maps before running the code\n"
				"   -a                       Show packet before running code\n"
				"   -b                       Show packet after running code\n"
				"   -o FILE                  Output modified packets to file\n"
				"   -p PORT                  Choose packets input port (Fixed, for now)\n"
				"   -h                       Print this help message\n"
		);
}

int insert_map_rules(struct ebpflow_fw *fw, char *inrules){
	FILE *fin;
	char buf[1024];
	char map_name[64];
	uint64_t key = 0, val = 0, mask = 0;

	fin = fopen(inrules,"r");
	if(fin == NULL){
		return -1;
	}

	int c = 0;
	while(fgets(buf,sizeof(buf),fin)){
		if(buf[0] == '#' || buf[0] == '\n') // Skip comment and empty lines
			continue;

		sscanf(buf,"%s 0x%lx 0x%lx 0x%lx",map_name,&key,&mask,&val);

		ebpflow_soft_map_insert(fw,map_name,key,val);
	}
}

void run_code(unsigned char *args, const struct pcap_pkthdr *meta, const unsigned char *packet){
		struct args *myargs = (struct args *) args;
		struct ebpflow_fw *fw = myargs->fw;
		unsigned char *buf = myargs->pktbuf;
		size_t buflen = myargs->buflen;
		int flags = myargs->flags;
		struct timeval t;
		struct packet pkt;
		struct metadatahdr *metadata = (struct metadatahdr*) buf;
		uint64_t r0 = 0;
		size_t totlen = sizeof(struct metadatahdr) + meta->caplen;
		void *pkt_init;

		myargs->count++;
		printf("[Packet #%d] ",myargs->count);

		if(totlen > buflen){
				printf("Packet too big: %lu. Skipping...\n",totlen);
				return;
		}

		metadata->length_pkt     = meta->caplen;
		metadata->timestamp_sec  = meta->ts.tv_sec;
		metadata->timestamp_nsec = meta->ts.tv_usec*1000;
		metadata->in_port        = myargs->inport;
		// The other metadata will be left as default

		// We have to copy the packet because metadata + pkt should
		// be contiguous in memory
		pkt_init = buf+sizeof(struct metadatahdr);
		memcpy(pkt_init,packet,meta->caplen);

		if(flags & SHOW_BEFORE)
			hex_dump("\nPacket before",pkt_init,meta->caplen);

		r0 = ebpflow_exec(fw,buf,totlen);

		if(r0 == UINT64_MAX){
				printf("Error while executing code\n");
				return;
		}

		// Not printing metadata, only packet!!!
		if(flags & SHOW_AFTER)
			hex_dump("\nPacket after",pkt_init,meta->caplen);

		printf("R0 = 0x%016lx\n",r0);

		if(myargs->dumper){
			pcap_dump((unsigned char *)myargs->dumper,meta,pkt_init);
		}
}

int main(int argc, char** argv){
		int opt;
		char *filepath = NULL;
		char *inpcap = NULL;
		char *outpcap = NULL;
		char *inrules = NULL;
		char *errmsg;
		char error_buffer[PCAP_ERRBUF_SIZE];
		struct ebpflow_fw *fw = NULL;
		void *code;
		uint32_t code_len;
		struct packet *pkts;
		unsigned char *buf;
		size_t buflen = 0;
		int ret;
		int flags = 0;
		pcap_dumper_t *dumper = NULL;
		uint8_t inport = 0;
		char *endptr;

		// Flags
		int dry_run = 0;

		while( (opt = getopt(argc,argv,"f:r:abo:p:h")) != -1){
				switch(opt){
						case 'f':
								inpcap = optarg;
								break;
						case 'r':
								inrules = optarg;
								break;
						case 'a':
								flags |= SHOW_AFTER;
								break;
						case 'b':
								flags |= SHOW_BEFORE;
								break;
						case 'o':
								outpcap = optarg;
								break;
						case 'p':
								errno = 0;
								unsigned long val = strtoul(optarg, &endptr, 10);

								if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
										|| (errno != 0 && val == 0)) {
									perror("strtol");
									exit(EXIT_FAILURE);
								}

								if (endptr == optarg) {
									fprintf(stderr, "No digits were found for port value\n");
									exit(EXIT_FAILURE);
								}

								inport = (uint8_t) val;
								break;
						case 'h':
								usage();
								return 0;
						default:
								try_message();
								exit(1);
								break;
				}
		}

		if(inpcap == NULL){
			printf("Expected pcap file.\n");
			try_message();
			return 1;
		}

		fw = ebpflow_create();
		if(fw == NULL){
			printf("Failed to interact with switch.\n");
			exit(1);
		}

		if(argc == optind){
			printf("Expected .o file to load.\n");
			try_message();
			return 1;
		}

		// Filename should always be the last argument
		filepath = argv[optind];

		code_len = ebpflow_parse_elf(fw,filepath,&code,&errmsg);
		if(code_len == 0) goto error;

		// The loader adds two instructions at the beginning of
		// every code to enable passing the correct pointer to
		// packet and stack. To emulate the code, we need to
		// skip these two intstructions. If not, we'll cause
		// a segmentation fault.
		code = code + 2*sizeof(uint64_t);
		code_len -= 2*sizeof(uint64_t);

		// Start soft maps
		ret = ebpflow_init_soft_maps(fw,&errmsg);
		if(ret) goto error;

		ret = ebpflow_load_code(fw, code, code_len, -1, 0, &errmsg);
		if(ret) goto error;

		if(inrules != NULL){
			ret = insert_map_rules(fw, inrules);
			if(ret){
				errmsg = "Failed to insert rules.";
				goto error;
			}
		}

		// Buffer to hold packet
		buflen = MAXMTU+sizeof(struct metadatahdr);
		buf = (unsigned char*) calloc(buflen,1);

		pcap_t *handle = pcap_open_offline(inpcap, error_buffer);

		if(outpcap != NULL){
			dumper = pcap_dump_open(handle,outpcap);
		}

		struct args myargs = {fw,buf,buflen,0,flags,inport,dumper};

		// -1 will cause to process the entire file
		pcap_loop(handle, -1, run_code, (unsigned char*)&myargs);

		printf("\n");
		ebpflow_dump_maps(fw);

		if(fw != NULL){
				ebpflow_destroy(fw);
		}

		if(dumper != NULL){
			pcap_dump_close(dumper);
		}

		return 0;

		error:
		printf("%s\n",errmsg);
		exit(1);
}
