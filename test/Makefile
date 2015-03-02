PROG = unit_test
SRC_DIR=../src
SSL=-DNS_ENABLE_SSL
CFLAGS = -W -Wall -Werror $(SSL) -DNS_ENABLE_COAP -DNS_ENABLE_IPV6 -DNS_ENABLE_THREADS -DNS_ENABLE_MQTT_BROKER -DNS_ENABLE_DNS_SERVER -DNS_INTERNAL="" -DNS_MODULE_LINES -include unit_test.h -DNS_MALLOC=test_malloc -DNS_CALLOC=test_calloc -pthread -g -O0 $(CFLAGS_EXTRA)
LDFLAGS=-lssl
AMALGAMATED_SOURCES = ../fossa.c

include test.mk
include $(SRC_DIR)/modules.mk

# http://crossgcc.rts-software.org/doku.php?id=compiling_for_win32
MINGW_GCC=/usr/local/gcc-4.8.0-qt-4.8.4-for-mingw32/win32-gcc/bin/i586-mingw32-gcc

.PHONY: $(PROG).exe $(PROG)_mingw.exe

$(PROG)_mingw.exe: Makefile
	$(MINGW_GCC) $(AMALGAMATED_SOURCES) -o $(PROG)_mingw.exe -W -Wall -Werror

$(PROG).exe:
	wine cl $(AMALGAMATED_SOURCES) /MD /I.. /Zi $(CFLAGS_EXTRA) && echo "Compiled OK\n"

win: $(PROG).exe
	wine $(PROG).exe

# Interactive:
#   docker run -v $(CURDIR)/../..:/cesanta -t -i --entrypoint=/bin/bash cesanta/fossa_test
docker:
	docker run --rm -v $(CURDIR)/../..:/cesanta cesanta/fossa_test
