CFLAGS = -g -O2 -g
LDLIBS := -lm
CC = gcc

all: utils libebpflow tools examples serverless

utils:
	$(MAKE) -C utils

libebpflow:
	$(MAKE) -C libebpflow

tools:
	$(MAKE) -C tools

examples:
	$(MAKE) -C examples

serverless:
	$(MAKE) -C serverless

install:
	$(MAKE) -C tools install

uninstall:
	$(MAKE) -C tools uninstall

clean:
	$(MAKE) -C utils clean
	$(MAKE) -C libebpflow clean
	$(MAKE) -C tools clean
	$(MAKE) -C examples clean
	$(MAKE) -C serverless clean

.PHONY: all utils libebpflow tools examples serverless clean install uninstall
