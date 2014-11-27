PROG = api_server
SOURCES = $(PROG).c sqlite3.c db_plugin_sqlite.c ../../fossa.c
CFLAGS = -W -Wall -pthread $(CFLAGS_EXTRA)

all: $(PROG)

$(PROG): $(SOURCES)
	$(CC) $(SOURCES) -o $@ $(CFLAGS)

$(PROG).exe: $(SOURCES)
	cl $(SOURCES) /I.. /MD /Fe$@

test: $(PROG)
	sh unit_test.sh $$(pwd)/$(PROG)

clean:
	rm -rf *.gc* *.dSYM *.exe *.obj *.o a.out $(PROG)
