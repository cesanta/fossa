include modules.mk

all: ../fossa.c ../fossa.h

../fossa.h: Makefile $(HEADERS)
	@cat $(HEADERS) >$@

../fossa.c: Makefile $(SOURCES)
	@(echo '#include "fossa.h"'; cat internal.h; (cat $(SOURCES) | sed '/^#include "/d')) >$@
