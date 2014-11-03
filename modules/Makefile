include modules.mk

all: ../fossa.c ../fossa.h

../fossa.h: Makefile $(HEADERS)
	$(MAKE) -s --no-print-directory merge_fossa.h >$@

../fossa.c: Makefile $(SOURCES)
	$(MAKE) -s --no-print-directory merge_fossa.c >$@

merge_fossa.h: Makefile $(HEADERS)
	@cat $(HEADERS)

merge_fossa.c: Makefile $(SOURCES)
	@(echo '#include "fossa.h"'; (cat $(SOURCES) | sed '/^#include "/d'))
