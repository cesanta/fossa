PROG = unit_test
PROF = -fprofile-arcs -ftest-coverage -g -O0
CFLAGS = -W -Wall -Werror -I.. -DNS_ENABLE_SSL -pthread $(PROF) $(CFLAGS_EXTRA)
SOURCES = $(PROG).c ../net_skeleton.c

all: clean ismerged $(PROG)_ansi $(PROG)_c99 $(PROG)

.PHONY: clean clean_coverage $(PROG) $(PROG)_ansi $(PROG)_c99

ismerged:
	$(MAKE) -C ../modules -s --no-print-directory merge_net_skeleton.c | diff ../net_skeleton.c -
	$(MAKE) -C ../modules -s --no-print-directory merge_net_skeleton.h | diff ../net_skeleton.h -

$(PROG): Makefile
	$(MAKE) clean_coverage
	g++ -x c++ $(PROG).c -o $(PROG) $(CFLAGS) -lssl && ./$(PROG)
	gcov -b $(PROG).c

$(PROG)_ansi: Makefile
	$(MAKE) clean_coverage
	gcc -pedantic -ansi $(PROG).c -o $(PROG)_ansi $(CFLAGS) -lssl && ./$(PROG)_ansi
	gcov -b $(PROG).c

$(PROG)_c99: Makefile
	$(MAKE) clean_coverage
	gcc -pedantic -std=c99 $(PROG).c -o $(PROG)_c99 $(CFLAGS) -lssl && ./$(PROG)_c99


$(PROG).exe:
	wine cl $(PROG).c /MD && wine $(PROG).exe

clean: clean_coverage
	rm -rf $(PROG) $(PROG)_ansi $(PROG)_c99 *.txt *.exe *.obj *.o a.out

clean_coverage:
	rm -rf *.gc* *.dSYM
