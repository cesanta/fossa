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

struct timeval {
  long tv_sec;
  long tv_usec;
};

time_t time(time_t* timer);

/* TODO(alashkin): add (at least) in-flash "files" operations */

#define AVR_NOFS
#define AVR_LIBC

#ifdef __cplusplus
}
#endif

#endif
