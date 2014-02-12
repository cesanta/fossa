PROF = -fprofile-arcs -ftest-coverage -g -O0
CFLAGS = -W -Wall -pedantic -O3 -lssl -I.. $(CFLAGS_EXTRA)

all:
	@echo "Usage: make [echo|pubsub]"

echo: echo.c ../tcp_skeleton.c
	cc echo.c ../tcp_skeleton.c -o $@ $(CFLAGS)

u:
	cc unit_test.c -o unit_test $(CFLAGS) && ./unit_test
	g++ unit_test.c -o unit_test $(CFLAGS) && ./unit_test
	clang unit_test.c -o unit_test $(CFLAGS) $(PROF) && ./unit_test
	gcov -a unit_test.c

w:
	wine cl unit_test.c ws2_32.lib && wine unit_test.exe

clean:
	rm -rf *.gc* *.dSYM unit_test *.txt *.exe a.out echo
