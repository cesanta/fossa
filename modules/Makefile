include modules.mk

all: ../fossa.c ../fossa.h

../fossa.h: Makefile $(HEADERS)
	@cat $(HEADERS) | sed '/^#include "/d' >$@

../fossa.c: Makefile $(SOURCES)
	@(echo '#include "fossa.h"'; (cat internal.h $(SOURCES) | sed '/^#include "/d')) >$@
