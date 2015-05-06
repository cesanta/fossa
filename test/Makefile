SOURCES=unit_test.c ../fossa.c
CFLAGS = -W -Wall -I../.. -pthread -DNS_ENABLE_COAP -DNS_ENABLE_IPV6 -DNS_ENABLE_THREADS -DNS_ENABLE_MQTT_BROKER -DNS_ENABLE_DNS_SERVER \
	       -DNS_INTERNAL="" -DNS_MODULE_LINES -include unit_test.h -DNS_MALLOC=test_malloc -DNS_CALLOC=test_calloc -lssl $(CFLAGS_EXTRA)

all: test

unit_test: $(SOURCES) ../fossa.h
	@$(CC) $(SOURCES) -o $@ $(CFLAGS)

test: unit_test
	@MallocLogFile=/dev/null ./unit_test $(TEST_FILTER)
