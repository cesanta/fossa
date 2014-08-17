PROF = -fprofile-arcs -ftest-coverage -g -O0
CFLAGS = -W -Wall -pedantic -std=c99 -O0 -g -I.. -pthread $(CFLAGS_EXTRA)

all: echo pubsub u2 nc

echo: echo.c ../net_skeleton.c
	$(CC) echo.c ../net_skeleton.c -o $@ $(CFLAGS)

pubsub: pubsub.c ../net_skeleton.c
	$(CC) pubsub.c ../net_skeleton.c -o $@ $(CFLAGS)

nc: nc.c
	$(CC) nc.c ../net_skeleton.c -DNS_ENABLE_SSL -lssl -o $@ $(CFLAGS)
  
u2:
	cc unit_test.c -o unit_test $(CFLAGS) -lssl

u:
	cc unit_test.c -o unit_test $(CFLAGS) -lssl && ./unit_test
	g++ unit_test.c -o unit_test $(CFLAGS) -lssl && ./unit_test
	clang unit_test.c -o unit_test $(CFLAGS) -lssl $(PROF) && ./unit_test
	gcov -a unit_test.c

w:
	wine cl unit_test.c /MD && wine unit_test.exe

clean:
	rm -rf *.gc* *.dSYM unit_test *.txt *.exe *.obj a.out echo pubsub nc
