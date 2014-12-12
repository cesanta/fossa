include modules.mk

all: ../fossa.c ../fossa.h

../fossa.h: Makefile modules.mk $(HEADERS)
	@cat $(HEADERS) | sed '/^#include "/d' >$@

../fossa.c: Makefile modules.mk $(SOURCES)
	@(echo '#include "fossa.h"'; ../scripts/amalgam internal.h $(SOURCES)) >$@
