PROG = broker
SOURCES = $(PROG).c ../../fossa.c
CFLAGS = -W -Wall -I../.. -pthread -DNS_ENABLE_SSL -DNS_ENABLE_MQTT_BROKER -lssl $(CFLAGS_EXTRA)

all: $(PROG)

$(PROG): $(SOURCES)
	$(CC) $(SOURCES) -o $@ $(CFLAGS)

$(PROG).exe: $(SOURCES)
	cl $(SOURCES) /I../.. /DNS_ENABLE_SSL /DNS_ENABLE_MQTT_BROKER /MD /Fe$@

clean:
	rm -rf *.gc* *.dSYM *.exe *.obj *.o a.out $(PROG)
