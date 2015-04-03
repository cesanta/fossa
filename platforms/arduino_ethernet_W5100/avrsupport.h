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
/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 *
 * Partially BSD-compatible sockets for Wiznet W5100.
 *
 * Note: this implementation is intended for Fossa network library only.
 * It supports only non-blocking mode and contains some
 * simplifications.
 */

#ifndef W5100_SOCKETS_HEADER_INCLUDED
#define W5100_SOCKETS_HEADER_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

typedef void* sock_t;

#define INVALID_SOCKET NULL

#define SOCKET_ERROR -1
#define INADDR_ANY 0
#define AF_INET 2

#define SOCK_STREAM 0
#define SOCK_DGRAM 1

#define SOMAXCONN 0 /* use hardware-specific maxconn */

#define SOL_SOCKET 1
#define SO_ERROR 1
#define SO_REUSEADDR 2

#define FD_CLOEXEC 1

#define F_GETFL 1
#define F_SETFL 2
#define F_SETFD 3

#define O_NONBLOCK 1

/* errors */
#define ENOENT 2
#define EINTR 4
#define EINPROGRESS 115
#define EAGAIN 11
#define EWOULDBLOCK EAGAIN
/* TODO(alashkin): change to darwin values */
#define ENOTCONN 10057
#define EMSGSIZE 10040
#define EINVAL 10022

#define BUFSIZ 128

typedef int16_t socklen_t;
typedef uint8_t sa_family_t;
typedef uint16_t in_port_t;
typedef uint8_t ushort_t;
typedef uint32_t ulong_t;

typedef uint32_t in_addr_t;

struct in_addr {
  in_addr_t s_addr;
};

struct sockaddr_in {
  sa_family_t sin_family;
  in_port_t sin_port;
  struct in_addr sin_addr;
};

struct sockaddr {
  union {
    sa_family_t sa_family;
    struct sockaddr_in sin;
  };
};

struct hostent {
  /*
   * 1. only one ip address is supported
   * 2. fossa uses only one field, so, gethostbyname fills only it
   */
  char* h_addr_list[1][sizeof(uint32_t)];
};

#define FD_SETSIZE 4 /* W5100 has four sockets only */

typedef struct _fd_set {
  uint8_t fd_count;
  sock_t fd_array[FD_SETSIZE];
} fd_set;

/*
 * Usually, FD_XXX and xtoy are macroses,
 * here use funtions
 * coz size warnings with functions  are
 * more clear in avr-gcc
 */
void FD_ZERO(fd_set* s);
int FD_ISSET(sock_t fd, fd_set* set);
void FD_SET(sock_t fd, fd_set* set);

uint16_t htons(uint16_t hostshort);
uint32_t htonl(uint32_t hostlong);
uint16_t ntohs(uint16_t netshort);
uint32_t ntohl(uint32_t netlong);

sock_t socket(int af, int type, int protocol);
int closesocket(sock_t s);
/* fossa uses BSD-style, so define close() */
#define close(x) closesocket(x)

int sendto(sock_t s, const void* buf, size_t len, int flags,
           const struct sockaddr* addr, socklen_t addr_len);
int recvfrom(sock_t s, char* buf, int len, int flags, struct sockaddr* from,
             int* fromlen);
int bind(sock_t s, const struct sockaddr* name, int namelen);
int getsockname(sock_t s, struct sockaddr* name, int* namelen);
struct hostent* gethostbyname(const char* name);
char* inet_ntoa(struct in_addr in);
const char* inet_ntop(int af, const void* src, char* dst, socklen_t size);
int listen(sock_t s, int backlog);
sock_t accept(sock_t s, struct sockaddr* addr, int* addrlen);
int recv(sock_t s, char* buf, int len, int flags);
int send(sock_t s, const char* buf, int len, int flags);
int connect(sock_t s, const struct sockaddr* name, int namelen);
int getpeername(sock_t s, struct sockaddr* name, int* namelen);
int select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds,
           const struct timeval* timeout);
int getsockopt(sock_t s, int level, int optname, char* optval, int* optlen);
int fcntl(sock_t s, int cmd, ...);
int setsockopt(sock_t s, int level, int optname, void* optval, int optlen);

int ns_avr_get_dns_name(char* name, size_t namelen);
int avr_netinit(uint8_t* mac, uint8_t* ip);

#ifdef __cplusplus
}
#endif

#endif /* W5100_SOCKETS_HEADER_INCLUDED */
