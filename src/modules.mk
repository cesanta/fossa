COMMON = ../../common
FROZEN = ../deps/frozen

HEADERS = common.h \
          $(COMMON)/osdep.h \
          $(COMMON)/mbuf.h \
          $(COMMON)/sha1.h \
          $(COMMON)/md5.h \
          $(COMMON)/base64.h \
          $(COMMON)/str_util.h \
          $(FROZEN)/frozen.h \
          net.h \
          util.h \
          http.h \
          json-rpc.h \
          mqtt.h \
          mqtt-broker.h \
          dns.h \
          dns-server.h \
          resolv.h \
          coap.h

SOURCES = $(COMMON)/mbuf.c \
          $(COMMON)/sha1.c \
          $(COMMON)/md5.c \
          $(COMMON)/base64.c \
          $(COMMON)/str_util.c \
          $(COMMON)/dirent.c \
          $(FROZEN)/frozen.c \
          net.c \
          multithreading.c \
          http.c \
          util.c \
          json-rpc.c \
          mqtt.c \
          mqtt-broker.c \
          dns.c \
          dns-server.c \
          resolv.c \
          coap.c
