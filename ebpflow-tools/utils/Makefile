CC = gcc

all: ebpf elfutils

ebpf: 
	$(CC) -c ebpf.c

elfutils: 
	$(CC) -c elf_utils.c

clean:
	rm -f *.o