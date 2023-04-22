#include <stdio.h>
#include "ebpf.h"

#define PRINT(s) printf("%7s  ",s)

void
ebpf_print_opcode(int opcode){

    switch(opcode){
        /* =================== ALU Class =================== */
        case EBPF_OP_ADD_IMM    :
        case EBPF_OP_ADD_REG    : PRINT("add32");     break;
        case EBPF_OP_SUB_IMM    :
        case EBPF_OP_SUB_REG    : PRINT("sub32");     break;
        case EBPF_OP_MUL_IMM    :
        case EBPF_OP_MUL_REG    : PRINT("mul32");     break;
        case EBPF_OP_DIV_IMM    :
        case EBPF_OP_DIV_REG    : PRINT("div32");     break;
        case EBPF_OP_OR_IMM     :
        case EBPF_OP_OR_REG     : PRINT("or21");      break;
        case EBPF_OP_AND_IMM    :
        case EBPF_OP_AND_REG    : PRINT("and32");     break;
        case EBPF_OP_LSH_IMM    :
        case EBPF_OP_LSH_REG    : PRINT("lsh32");     break;
        case EBPF_OP_RSH_IMM    :
        case EBPF_OP_RSH_REG    : PRINT("rsh32");     break;
        case EBPF_OP_NEG        : PRINT("neg32");     break;
        case EBPF_OP_MOD_IMM    :
        case EBPF_OP_MOD_REG    : PRINT("mod32");     break;
        case EBPF_OP_XOR_IMM    :
        case EBPF_OP_XOR_REG    : PRINT("xor32");     break;
        case EBPF_OP_MOV_IMM    :
        case EBPF_OP_MOV_REG    : PRINT("mov32");     break;
        case EBPF_OP_ARSH_IMM   :
        case EBPF_OP_ARSH_REG   : PRINT("arsh32");    break;
        case EBPF_OP_LE         : printf("%3sle","");       break;
        case EBPF_OP_BE         : printf("%3sbe","");       break;

        /* ================== ALU64 Class ================== */
        case EBPF_OP_ADD64_IMM  :
        case EBPF_OP_ADD64_REG  : PRINT("add");   break;
        case EBPF_OP_SUB64_IMM  :
        case EBPF_OP_SUB64_REG  : PRINT("sub");   break;
        case EBPF_OP_MUL64_IMM  :
        case EBPF_OP_MUL64_REG  : PRINT("mul");   break;
        case EBPF_OP_DIV64_IMM  :
        case EBPF_OP_DIV64_REG  : PRINT("div");   break;
        case EBPF_OP_OR64_IMM   :
        case EBPF_OP_OR64_REG   : PRINT("or");    break;
        case EBPF_OP_AND64_IMM  :
        case EBPF_OP_AND64_REG  : PRINT("and");   break;
        case EBPF_OP_LSH64_IMM  :
        case EBPF_OP_LSH64_REG  : PRINT("lsh");   break;
        case EBPF_OP_RSH64_IMM  :
        case EBPF_OP_RSH64_REG  : PRINT("rsh");   break;
        case EBPF_OP_NEG64      : PRINT("neg");   break;
        case EBPF_OP_MOD64_IMM  :
        case EBPF_OP_MOD64_REG  : PRINT("mod");   break;
        case EBPF_OP_XOR64_IMM  :
        case EBPF_OP_XOR64_REG  : PRINT("xor");   break;
        case EBPF_OP_MOV64_IMM  :
        case EBPF_OP_MOV64_REG  : PRINT("mov");   break;
        case EBPF_OP_ARSH64_IMM :
        case EBPF_OP_ARSH64_REG : PRINT("arsh");  break;

        /* ============ Load and Store Classes ============= */
        case EBPF_OP_LDXW       : PRINT("ldxw");    break;
        case EBPF_OP_LDXH       : PRINT("ldxh");    break;
        case EBPF_OP_LDXB       : PRINT("ldxb");    break;
        case EBPF_OP_LDXDW      : PRINT("ldxdw");   break;
        case EBPF_OP_STW        : PRINT("stw");     break;
        case EBPF_OP_STH        : PRINT("sth");     break;
        case EBPF_OP_STB        : PRINT("stb");     break;
        case EBPF_OP_STDW       : PRINT("stdw");    break;
        case EBPF_OP_STXW       : PRINT("stxw");    break;
        case EBPF_OP_STXH       : PRINT("stxh");    break;
        case EBPF_OP_STXB       : PRINT("stxb");    break;
        case EBPF_OP_STXDW      : PRINT("stxdw");   break;
        case EBPF_OP_LDDW       : PRINT("lddw");    break;
        case EBPF_OP_LDDW2      : PRINT("lddw2");   break; /* Custom */
        case 0x00               : PRINT("...");     break; /* LDDW continued*/
        case EBPF_OP_LDABSW     : PRINT("ldabsw");  break;
        case EBPF_OP_LDABSH     : PRINT("ldabsh");  break;
        case EBPF_OP_LDABSB     : PRINT("ldabsb");  break;
        case EBPF_OP_LDABSDW    : PRINT("ldabsdw"); break;
        case EBPF_OP_LDINDW     : PRINT("ldindw");  break;
        case EBPF_OP_LDINDH     : PRINT("ldindh");  break;
        case EBPF_OP_LDINDB     : PRINT("ldindb");  break;
        case EBPF_OP_LDINDDW    : PRINT("ldinddw"); break;

        /* ================== Jump Class =================== */
        case EBPF_OP_JA         : PRINT("ja");      break;
        case EBPF_OP_JEQ_IMM    :
        case EBPF_OP_JEQ_REG    : PRINT("jeq");     break;
        case EBPF_OP_JGT_IMM    :
        case EBPF_OP_JGT_REG    : PRINT("jgt");     break;
        case EBPF_OP_JGE_IMM    :
        case EBPF_OP_JGE_REG    : PRINT("jge");     break;
        case EBPF_OP_JSET_IMM   :
        case EBPF_OP_JSET_REG   : PRINT("jset");    break;
        case EBPF_OP_JNE_IMM    :
        case EBPF_OP_JNE_REG    : PRINT("jne");     break;
        case EBPF_OP_JSGT_IMM   :
        case EBPF_OP_JSGT_REG   : PRINT("jsgt");    break;
        case EBPF_OP_JSGE_IMM   :
        case EBPF_OP_JSGE_REG   : PRINT("jsge");    break;
        case EBPF_OP_CALL       : PRINT("call");    break;
        case EBPF_OP_EXIT       : PRINT("exit");    break;
        default                 : PRINT("???");     break;
    } 
}

void
ebpf_disassemble_one(const void *instruction){

    const struct ebpf_inst *inst = instruction;
    uint8_t class = inst->opcode & 7;
    uint8_t op    = inst->opcode;

    ebpf_print_opcode(op);

    switch(class){
        case EBPF_CLS_ALU:
        case EBPF_CLS_ALU64:
            if(op == EBPF_OP_LE || op == EBPF_OP_BE){
                printf("%d r%d", inst->imm, inst->dst);
            }else if(op == EBPF_OP_NEG || op == EBPF_OP_NEG64){
                printf("r%d", inst->dst);
            }else if(op & EBPF_SRC_REG){
                printf("r%d, r%d", inst->dst, inst->src);
            }else{
                printf("r%d, %d", inst->dst, inst->imm);
            }
            break;
        case EBPF_CLS_JMP:
            if(op == EBPF_OP_EXIT){
                // Nothing else to do if EXIT op
                break;
            }else if(op == EBPF_OP_CALL){
                printf("%d", inst->imm);
            }else if(op == EBPF_OP_JA){
                printf("%d", inst->offset);
            }else if(op & EBPF_SRC_REG){
                printf("r%d, r%d, +%d", inst->dst, inst->src,inst->offset);
            }else{
                printf("r%d, %d, +%d", inst->dst, inst->imm,inst->offset);
            }
            break;
        case EBPF_CLS_LD:
            if(op == EBPF_OP_LDDW){
                printf("r%d, 0x%08x",inst->dst,inst->imm);
            }else if(op == 0x00){
                printf("__, 0x%08x",inst->imm);
            }else{
                //printf(" ~TODO~");
                if (inst->src == 0xA) //Access on stack, address is decremented.  
                  printf(" r%d, [r%d - %d]",inst->dst,inst->src,inst->imm);
                else 
                  printf(" r%d, [r%d + %d]",inst->dst,inst->src,inst->imm);
            }
            // printf(" r%d, [r%d + %d]",inst->dst,inst->src,inst->imm);
            break;
        case EBPF_CLS_LDX:
            if (inst->src == 0xA) //Access on stack, address is decremented.  
              printf("r%d, [r%d - %d]",inst->dst,inst->src,inst->offset);
            else 
              printf("r%d, [r%d + %d]",inst->dst,inst->src,inst->offset);
            break;
        case EBPF_CLS_ST:
            if (inst->dst == 0xA) //Access on stack, address is decremented.  
              printf("[r%d - %d], %d",inst->dst,inst->offset,inst->imm);
            else  
              printf("[r%d + %d], %d",inst->dst,inst->offset,inst->imm);
            break;
        case EBPF_CLS_STX:
            if (inst->dst == 0xA) //Access on stack, address is decremented.  
              printf("[r%d - %d], r%d",inst->dst,inst->offset,inst->src);
            else 
              printf("[r%d + %d], r%d",inst->dst,inst->offset,inst->src);
            break;
        default:
            break;
    }
}

void
ebpf_disassemble_many(const void *insts, unsigned int num_insts){
    unsigned int i;
    const struct ebpf_inst *code = insts;

    for(i = 0 ; i < num_insts ; i++){
        printf("%5d: ",i);
        ebpf_disassemble_one(&code[i]);
        printf("\n");
    }
}
