all::

INSTALL=install
PREFIX=/usr/local

-include bpfmap-env.mk

all:: libbpfmap.a

bpfmap_mods += bpfmap
bpfmap_mods += hashtab

libbpfmap.a: $(bpfmap_mods:%=%.o)
	$(AR) r '$@' $(bpfmap_mods:%=%.o)

clean::
	$(RM) *.o */*.o *.a

install:: install-headers install-libraries

install-headers::
	$(INSTALL) -m 755 -d $(PREFIX)/include
	$(INSTALL) -m 644 bpfmap.h $(PREFIX)/include

install-libraries::
	$(INSTALL) -m 755 -d $(PREFIX)/lib
	$(INSTALL) -m 644 libbpfmap.a $(PREFIX)/lib
