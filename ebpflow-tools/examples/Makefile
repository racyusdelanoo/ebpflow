SRC = $(wildcard *.c)
TAR = $(SRC:.c=.o)

.PHONE: all clean

all: $(TAR)

%.o: %.c
	clang -Wall -O2 -target bpfel -I ../includes -I../utils -c $< -o $@

clean:
	rm -f $(TAR)