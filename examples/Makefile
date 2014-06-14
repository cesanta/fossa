PROF = -fprofile-arcs -ftest-coverage -g -O0
CFLAGS = -W -Wall -pedantic -O0 -g -I.. $(CFLAGS_EXTRA)

all: echo pubsub nsv7

echo: echo.c ../net_skeleton.c
	$(CC) echo.c ../net_skeleton.c -o $@ $(CFLAGS)

pubsub: pubsub.c ../net_skeleton.c
	$(CC) pubsub.c ../net_skeleton.c -o $@ $(CFLAGS)

nslua: nslua.c ../net_skeleton.c
	$(CC) nslua.c ../net_skeleton.c -o $@ $(CFLAGS) -llua

V7 = ../../v7
nsv7: nsv7.c ../net_skeleton.c $(V7)/v7.c
	$(CC) nsv7.c ../net_skeleton.c $(V7)/v7.c -o $@ $(CFLAGS) -I$(V7)

u:
	cc unit_test.c -o unit_test $(CFLAGS) -lssl && ./unit_test
	g++ unit_test.c -o unit_test $(CFLAGS) -lssl && ./unit_test
	clang unit_test.c -o unit_test $(CFLAGS) -lssl $(PROF) && ./unit_test
	gcov -a unit_test.c

w:
	wine cl unit_test.c /MD && wine unit_test.exe

clean:
	rm -rf *.gc* *.dSYM unit_test *.txt *.exe a.out echo pubsub ssl_term nsv7
