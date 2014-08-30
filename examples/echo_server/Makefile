CFLAGS = -W -Wall -I../.. -pthread $(CFLAGS_EXTRA)
SOURCES = echo_server.c ../../net_skeleton.c
PROG = echo_server

all: $(PROG)

$(PROG): $(SOURCES)
	$(CC) $(SOURCES) -o $@ $(CFLAGS)

$(PROG).exe: $(SOURCES)
	cl $(SOURCES) /I../.. /MD /Fe$@

clean:
	rm -rf *.gc* *.dSYM *.exe *.obj *.o a.out $(PROG)
