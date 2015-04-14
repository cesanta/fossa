/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#ifndef AVRDEBUG_HEADER_INCLUDED
#define AVRDEBUG_HEADER_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif
/* Blinks ($times) times with ($ms) delay */
void blink(int times, int ms);

/* Returns free memory size */
int get_freememsize();

#if defined(AVR_ENABLE_DEBUG)

#define DUMPINIT() Serial.begin(9600)
#define DUMPSTR(msg) Serial.println(msg)
#define DUMPDEC(num) Serial.println(num, DEC)
#define DUMPFREEMEM()         \
  Serial.print("Free mem: "); \
  Serial.println(get_freememsize())

#define DUMPFUNCNAME() Serial.println(__func__)

#define BLINK(t, m) blink(t, m);

#else

#define DUMPINIT()
#define DUMPFUNCNAME()
#define DUMPFREEMEM()
#define BLINK(t, m)
#define DUMPSTR(msg)
#define DUMPDEC(num)

#endif

#ifdef __cplusplus
}
#endif

#endif /* NS_AVRDEBUG_HEADER_INCLUDED */
       /*
        * Copyright (c) 2015 Cesanta Software Limited
        * All rights reserved
        */

#ifndef AVRLIBC_COMPAT_HEADER_INCLUDED
#define AVRLIBC_COMPAT_HEADER_INCLUDED

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

/*
 * Some of this stuff breaks
 * Fossa o Arduino
 * TODO(alashkin): remove these defines when
 * some kind of AVR-build-test will be ready
 */
#define NS_DISABLE_HTTP_DIGEST_AUTH
#define NS_DISABLE_MQTT
#define NS_DISABLE_MD5
#define NS_DISABLE_JSON_RPC
#define NS_DISABLE_SOCKETPAIR
#define NS_DISABLE_SSI
#define NS_DISABLE_POPEN
#define NS_DISABLE_DIRECTORY_LISTING
#define NS_DISABLE_DAV
#define NS_DISABLE_DNS
#define NS_DISABLE_RESOLVER
#define NS_DISABLE_CGI

#ifdef __cplusplus
extern "C" {
#endif

/* fossa requires to64, so define it' instead of strtol & co */
long long int to64(const char* str);

char* strerror(int errnum);

/* Time declaration & functions */
typedef unsigned long time_t;

#ifndef TIMEVAL
struct timeval {
  uint32_t tv_sec;
  uint32_t tv_usec;
};
#define TIMEVAL
#endif

time_t time(time_t* timer);

/* TODO(alashkin): add (at least) in-flash "files" operations */

#define AVR_NOFS
#define AVR_LIBC

#ifdef __cplusplus
}
#endif

#endif
/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */
#ifndef CC3000UTILS_HEADER_INCLUDED
#define CC3000UTILS_HEADER_INCLUDED

#define WIFI_CC3000

#ifdef __cplusplus
extern "C" {
#endif

int avr_netinit(const char* wlan_ssid, const char* wlan_pwd, int wlan_security,
                uint32_t ip, uint32_t subnet_mask, uint32_t gateway,
                uint32_t dns);

#include <utility/socket.h>
#include <utility/wlan.h>

#define close(x) closesocket(x)

#ifdef __cplusplus
}
#endif

#endif
