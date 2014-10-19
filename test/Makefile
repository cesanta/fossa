PROG = unit_test
PROF = -fprofile-arcs -ftest-coverage -g -O0
CFLAGS = -W -Wall -I.. -DNS_ENABLE_SSL -pthread $(PROF) $(CFLAGS_EXTRA)
SOURCES = $(PROG).c ../net_skeleton.c

all: clean ismerged $(PROG)

ismerged:
	$(MAKE) -C ../modules -s --no-print-directory merge_net_skeleton.c | diff ../net_skeleton.c -
	$(MAKE) -C ../modules -s --no-print-directory merge_net_skeleton.h | diff ../net_skeleton.h -

$(PROG):
	g++ $(PROG).c -o $(PROG) $(CFLAGS) -lssl && ./$(PROG)
	gcov -b $(PROG).c

$(PROG).exe:
	wine cl $(PROG).c /MD && wine $(PROG).exe

clean:
	rm -rf *.gc* *.dSYM $(PROG) *.txt *.exe *.obj *.o a.out
