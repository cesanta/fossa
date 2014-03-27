PROF = -fprofile-arcs -ftest-coverage -g -O0
CFLAGS = -W -Wall -pedantic -O0 -g -lssl -I.. -DNS_ENABLE_SSL $(CFLAGS_EXTRA)

all:
	@echo "Usage: make [echo|pubsub]"

echo: echo.c ../net_skeleton.c
	$(CC) echo.c ../net_skeleton.c -o $@ $(CFLAGS)

pubsub: pubsub.c ../net_skeleton.c
	$(CC) pubsub.c ../net_skeleton.c -o $@ $(CFLAGS)

ssl_term: ssl_term.c ../net_skeleton.c
	$(CC) ssl_term.c ../net_skeleton.c -o $@ $(CFLAGS)

u:
	cc unit_test.c -o unit_test $(CFLAGS) && ./unit_test
	g++ unit_test.c -o unit_test $(CFLAGS) && ./unit_test
	clang unit_test.c -o unit_test $(CFLAGS) $(PROF) && ./unit_test
	gcov -a unit_test.c

w:
	wine cl unit_test.c /MD && wine unit_test.exe

clean:
	rm -rf *.gc* *.dSYM unit_test *.txt *.exe a.out echo pubsub ssl_term
