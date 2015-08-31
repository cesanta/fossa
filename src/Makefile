include modules.mk

all: ../fossa.c ../fossa.h

../fossa.h: Makefile modules.mk $(HEADERS)
	@echo "AMALGAMATING\tfossa.h"
	@echo "#ifdef __AVR__\n#include \"avrsupport.h\"\n#endif" > $@
	@cat $(HEADERS) | sed '/^#include "/d' >>$@

../fossa.c: Makefile internal.h modules.mk $(SOURCES)
	@echo "AMALGAMATING\tfossa.c"
	@(echo '#include "fossa.h"'; ../../tools/amalgam --srcdir src internal.h $(SOURCES)) >$@
