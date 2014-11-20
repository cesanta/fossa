PROG = unit_test
SSL=-DNS_ENABLE_SSL
CFLAGS = -W -Wall -Werror $(SSL) -DNS_ENABLE_IPV6 -pthread -g -O0 $(CFLAGS_EXTRA)
PEDANTIC=$(shell gcc --version 2>/dev/null | grep -q clang && echo -pedantic)
AMALGAMATED_SOURCES = $(PROG).c ../fossa.c
EAT_MALLOC_WARNINGS=MallocLogFile=/dev/null

include ../modules/modules.mk

# http://crossgcc.rts-software.org/doku.php?id=compiling_for_win32
MINGW_GCC=/usr/local/gcc-4.8.0-qt-4.8.4-for-mingw32/win32-gcc/bin/i586-mingw32-gcc

all: clean $(PROG)_ansi $(PROG)_c99 $(PROG) $(PROG)_coverage

.PHONY: clean clean_coverage lcov valgrind docker cpplint $(PROG) $(PROG)_ansi $(PROG)_c99 $(PROG)_coverage $(PROG).exe $(PROG)_mingw.exe

$(PROG): Makefile
	g++ -x c++ $(AMALGAMATED_SOURCES) -o $(PROG) $(CFLAGS) -lssl
	$(EAT_MALLOC_WARNINGS) ./$(PROG) $(TEST_FILTER)

$(PROG)_ansi: Makefile
	gcc $(PEDANTIC) -ansi $(AMALGAMATED_SOURCES) -o $(PROG)_ansi $(CFLAGS) -lssl
	$(EAT_MALLOC_WARNINGS) ./$(PROG)_ansi $(TEST_FILTER)

$(PROG)_c99: Makefile
	gcc $(PEDANTIC) -std=c99 $(AMALGAMATED_SOURCES) -o $(PROG)_c99 $(CFLAGS) -lssl
	$(EAT_MALLOC_WARNINGS) ./$(PROG)_c99 $(TEST_FILTER)

$(PROG)_mingw.exe: Makefile
	$(MINGW_GCC) $(AMALGAMATED_SOURCES) -o $(PROG)_mingw.exe -W -Wall -Werror

$(PROG).exe:
	wine cl $(AMALGAMATED_SOURCES) /MD /I.. /Zi $(CFLAGS_EXTRA) && echo "Compiled OK\n"

win: $(PROG).exe
	wine $(PROG).exe

$(PROG)_coverage: Makefile
	$(MAKE) clean_coverage
	gcc $(PEDANTIC) -std=c99 -fprofile-arcs -ftest-coverage $(PROG).c $(addprefix ../modules/, $(SOURCES)) -o $(PROG)_coverage $(CFLAGS) -lssl
	$(EAT_MALLOC_WARNINGS) ./$(PROG)_coverage $(TEST_FILTER)
	gcov -p $(PROG).c $(notdir $(SOURCES)) >/dev/null

lcov: clean $(PROG)_coverage
	lcov -o lcov.info -c -d .
	genhtml -o lcov lcov.info

valgrind:
	gcc $(PEDANTIC) -std=c99 $(PROG).c $(addprefix ../modules/, $(SOURCES)) -o $(PROG)_valgrind $(CFLAGS) -DNO_DNS_TEST -UNS_ENABLE_SSL -lssl
	valgrind ./unit_test_valgrind

valgrind-leak:
	gcc $(PEDANTIC) -std=c99 $(PROG).c $(addprefix ../modules/, $(SOURCES)) -o $(PROG)_valgrind $(CFLAGS) -DNO_DNS_TEST -UNS_ENABLE_SSL -lssl
	valgrind --leak-check=full ./unit_test_valgrind

# Interactive:
#   docker run -v $(CURDIR)/../..:/cesanta -t -i --entrypoint=/bin/bash cesanta/fossa_test
docker:
	docker run --rm -v $(CURDIR)/../..:/cesanta cesanta/fossa_test

cpplint:
	cpplint.py --verbose=0 --extensions=c,h ../modules/*.[ch] >/dev/null

clean: clean_coverage
	rm -rf $(PROG) $(PROG)_ansi $(PROG)_c99 $(PROG)_coverage *.txt *.exe *.obj *.o a.out *.pdb *.opt

clean_coverage:
	rm -rf *.gc* *.dSYM
