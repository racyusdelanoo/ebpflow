ifeq ($(COVERAGE),1)
CFLAGS += -fprofile-arcs -ftest-coverage
LDFLAGS += -fprofile-arcs
endif

ifeq ($(ASAN),1)
CFLAGS += -fsanitize=address
LDFLAGS += -fsanitize=address
endif

# Location of binary files
BINDIR ?= /usr/local/bin

INSTALL_PREFIX ?= /usr/local

UTILS = ../utils

# Location of some needed dependencies (NetFPGA SUME stuff)
LIBS = ../libs

HASHLIB_PATH = ./libghthash

ebpflow_parts += ebpflow_firmware
ebpflow_parts += ebpflow_parser
# ebpflow_parts += ebpf_disassembler
ebpflow_parts += libghthash/hash_functions
ebpflow_parts += libghthash/hash_table
ebpflow_parts += bpfmap/bpfmap
ebpflow_parts += bpfmap/hashtab

CFLAGS = -g -Iinc -I../includes -I./libghthash -I../utils -I$(LIBS) -I./bpfmap -O2 -g
LDFLAGS += -lm 
CC = gcc

all : libebpflow.a common

libebpflow.a: $(ebpflow_parts:%=%.o) $(UTILS)/ebpf.o $(UTILS)/elf_utils.o $(LIBS)/nf_util.o $(LIBS)/sume_util.o
	$(AR) r '$@' $^

ghthash:
	$(MAKE) -C $(HASHLIB_PATH)

clean:
	$(MAKE) -C libghthash clean
	$(MAKE) -C bpfmap clean
	rm -fr *.o *.a *.bpf *.raw

.PHONY: all common libebpflow.a ghthash clean
