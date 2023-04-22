#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#include <ebpflow.h>

#include "elf_utils.h"
#include "ebpf.h"

void try_message(){
    printf("Try 'ebpflow-load -h' for more information.\n");
}

void usage(){
    printf(
        "Usage: ebpflow-load [FLAGS] <ebpf-file.o>\n"
        "Tool to load eBPF code into eBPFlow Switch.\n"
        "\n"
        "Options:\n"
        "   -n                  Dry run without actually loading the code\n"
        "   -x                  Show hex instructions after loading\n"
        "   -d                  Disassemble instructions after loading\n"
        "   -m MODE             Router mode to use (default is 1 [Router])\n"
        "   -r RULES-FILE       Rules to be added to maps\n"
        "   -s                  Checks and prints registers status\n"
        "   -t                  Show table definitions\n"
        "   -c MEM              Clean memory. See possible MEM values below\n"
        "   -u MEM              Dump memory. See possible MEM values below\n"
        //"   -p                  Enable payload processing\n"
        "   -g                  Enable debug info (should be used with -s)\n"
        "   -f                  Load instructions from raw .txt file\n"
        "   -h                  Print this help message\n"
        "\n"
        "MEM:\n"
        "   %d -> TCAM\n"
        "   %d -> CAM\n\n"
        "Currently the -f flag is not compatible with the other options, thus\n"
        "should be used by itself with the corresponding argument.\n"
        ,BPFPROC_MAP_TCAM
        ,BPFPROC_MAP_CAM
        );
}

int main(int argc, char** argv){
    int opt;
    char *filepath = NULL;
    char *rulefile = NULL;
    char* txtfile = NULL;
    char* errmsg;
    struct ebpflow_fw *fw = NULL;
    void *code;
    uint32_t code_len;
    int ret;
    uint32_t memid;

    // Flags
    int hex_contents = 0;
    int mode = BPFPROC_MODE_ROUTER;
    int dry_run = 0;
    int show_regs = 0;
    int disasm = 0;
    int show_tables = 0;
    int clean_mem = 0;
    int dump_mem = 0;
    int payload = 0; // Default: no payload
    int debug = 0;
    int fromtxt = 0;

    while( (opt = getopt(argc,argv,"ndxm:r:u:stc:pgf:h")) != -1){
        switch(opt){
            case 'n':
                dry_run = 1;
                break;
            case 'd':
                disasm = 1;
                break;
            case 'x':
                hex_contents = 1;
                break;
            case 'm':
                mode = atoi(optarg);
                if(mode != 0 && mode != 1){
                    printf("Error: mode should be 0 [TEST] or 1 [ROUTER]\n");
                    exit(1);
                }
                break;
            case 'r':
                rulefile = optarg;
                break;
            case 's':
                show_regs = 1;
                break;
            case 't':
                show_tables = 1;
                break;
            case 'c':
                clean_mem = 1;
                memid = atoi(optarg);
                if(memid != BPFPROC_MAP_CAM && memid != BPFPROC_MAP_TCAM){
                    printf("Error: MEM should be %d [TCAM] or %d [CAM]\n",
                        BPFPROC_MAP_TCAM,BPFPROC_MAP_CAM);
                    exit(1);
                }
                break;
            case 'u':
                dump_mem = 1;
                memid = atoi(optarg);
                if(memid != BPFPROC_MAP_CAM && memid != BPFPROC_MAP_TCAM){
                    printf("Error: MEM should be %d [TCAM] or %d [CAM]\n",
                        BPFPROC_MAP_TCAM,BPFPROC_MAP_CAM);
                    exit(1);
                }
                break;
            case 'p':
                payload = 1;
                break;
            case 'g':
                debug = 1;
                break;
            case 'f':
                fromtxt = 1;
                txtfile = optarg;
                break;
            case 'h':
                usage();
                return 0;
                break;
            default:
                try_message();
                exit(1);
                break;
        }
    }

    if(argc == optind && !show_regs && !clean_mem && !dump_mem && !fromtxt){
        printf("Expected .o file to load\n");
        try_message();
        return 0;
    }

    fw = ebpflow_create();
    if(fw == NULL){
        printf("Failed to interact with switch\n");
        exit(1);
    }

    // TODO: allow using this flag along with others
    if(fromtxt){
        if(ebpflow_load_txt(fw, txtfile, mode, payload, &errmsg)){
            printf("%s",errmsg);
            return -1;
        }else{
            printf("Program loaded successfully!\n");
        }

        goto clean;
    }

    if(show_regs && !dry_run){
        ret = ebpflow_status(fw,&errmsg);
        if(ret){
            printf("%s",errmsg);
            return -1;
        }else if(debug){
            ebpflow_show_debug_info(fw);
        }

        goto clean;
    }

    if(clean_mem){
        ret = ebpflow_mem_clean(fw,memid,&errmsg);
        if(ret){
            printf("%s",errmsg);
            return -1;
        }

        goto clean;
    }

    if(dump_mem){
        ret = ebpflow_mem_dump(fw,memid,&errmsg);
        if(ret){
            printf("%s",errmsg);
            return -1;
        }

        goto clean;
    }

    // Filename should always be the last argument
    filepath = argv[optind];
    
    code_len = ebpflow_parse_elf(fw,filepath,&code,&errmsg);

    if(code_len == 0){
        printf("%s\n",errmsg);
        exit(1);
    }

    if(dry_run){
        printf("Dry run. Not loading code to switch.\n");
        disasm = 1; // Enable code disassembly
        mode = -1;  // Disable loading code
    }else{
        // Clean WRINST register
        if(ebpflow_wrinst_clean(fw,&errmsg)){
            printf("Error erasing WRINST!\n%s\n",errmsg);
            exit(1);
        }
    }

    if(ebpflow_load_code(fw,code,code_len,mode,payload,&errmsg)){
        printf("Error loading instructions!\n%s\n",errmsg);
        exit(1);
    }else if(!dry_run){
        printf("Program loaded successfully!\n");

        // Install rules, if any
        if(rulefile){
            ret = ebpflow_install_rules(fw,&rulefile);
            if(ret){
                printf("Error while installing rules.\n");
                return -1;
            }
            printf("Rules installed succesfully!\n");
        }
    }

    if(show_tables){
        printf("\n~> Maps\n\n");
        if(ebpflow_dump_maps(fw)){
            printf("Error dumping maps!\n");
            exit(1);
        }
    }

    uint64_t *insts = (uint64_t*) code;
    uint32_t num_insts = code_len/sizeof(uint64_t);

    if(hex_contents){
        unsigned hi_inst;
        unsigned lo_inst;

        printf("\n~> Hex dump of instructions\n\n");
        for (int i = 0 ; i < num_insts ; i++){
            lo_inst = insts[i] & 0xFFFFFFFF;
            hi_inst = (insts[i]>>32) & 0xFFFFFFFF;
            printf("%4s0x%08x 0x%08x\n","",hi_inst, lo_inst);
        }
    }

    if(disasm){
        printf("\n~> Disassembled code\n\n");
        ebpf_disassemble_many(code,num_insts);
    }

clean:
    if(fw != NULL){
        ebpflow_destroy(fw);
    }

    return 0;
}
