EBPFLOW = ../libebpflow
UTILS = ../utils
INCLUDES = ../includes

CFLAGS = -g -I$(INCLUDES) -I$(EBPFLOW)/inc -I$(EBPFLOW) -I$(UTILS) -O2 -g
LDLIBS = -L$(EBPFLOW) -lebpflow -lpcap -lrt #-L$(SUME) -lsume
CC = gcc

PYSRC = $(wildcard *.py)
PYTOOLS = $(PYSRC:.py=)

CSRC = $(wildcard *.c)
CTOOLS = $(CSRC:.c=)

TOOLS = $(CTOOLS)
TOOLS += $(PYTOOLS)

ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif

all: $(TOOLS)

$(CTOOLS): % : %.c
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

$(PYTOOLS): % : %.py
	cp $< $@

install: $(TOOLS)
	mkdir -p $(PREFIX)/bin
	cp $^ $(PREFIX)/bin

uninstall:
	cd $(PREFIX)/bin; rm -f $(TOOLS); cd -

clean:
	rm -f *.o $(TOOLS)

.PHONY: all load clean install uninstall $(TOOLS)
