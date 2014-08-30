PROG = unit_test
PROF = -fprofile-arcs -ftest-coverage -g -O0
CFLAGS = -W -Wall -O0 -g -I.. -DNS_ENABLE_SSL -pthread $(CFLAGS_EXTRA)
SOURCES = $(PROG).c ../net_skeleton.c

all: $(PROG)

$(PROG):
	cc $(PROG).c -o $(PROG) $(CFLAGS) -lssl && ./$(PROG)
	g++ $(PROG).c -o $(PROG) $(CFLAGS) -lssl && ./$(PROG)
	clang $(PROG).c -o $(PROG) $(CFLAGS) -lssl $(PROF) && ./$(PROG)
	gcov -a $(PROG).c

$(PROG).exe:
	wine cl $(PROG).c /MD && wine $(PROG).exe

clean:
	rm -rf *.gc* *.dSYM $(PROG) *.txt *.exe *.obj *.o a.out
