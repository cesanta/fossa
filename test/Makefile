PROG = unit_test
PROF = -fprofile-arcs -ftest-coverage -g -O0
CFLAGS = -W -Wall -I.. -DNS_ENABLE_SSL -pthread $(PROF) $(CFLAGS_EXTRA)
SOURCES = $(PROG).c ../net_skeleton.c

all: clean $(PROG)

$(PROG):
	g++ $(PROG).c -o $(PROG) $(CFLAGS) -lssl && ./$(PROG)
	gcov -b $(PROG).c

$(PROG).exe:
	wine cl $(PROG).c /MD && wine $(PROG).exe

clean:
	rm -rf *.gc* *.dSYM $(PROG) *.txt *.exe *.obj *.o a.out
