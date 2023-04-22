CFLAGS = -g -O2 -g
LDLIBS := -lm
CC = gcc

all: build

hashlib_parts += hash_functions
hashlib_parts += hash_table

build: $(hashlib_parts:%=%.o)

clean:
	rm -f *.o *.a

.PHONY: all clean build