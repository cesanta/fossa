// Copyright (c) 2014 Cesanta Software Limited
// All rights reserved
//
// This library is dual-licensed: you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation. For the terms of this
// license, see <http://www.gnu.org/licenses/>.
//
// You are free to use this library under the terms of the GNU General
// Public License, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// Alternatively, you can license this library under a commercial
// license, as set out in <http://cesanta.com/>.

#ifndef NS_SKELETON_HEADER_INCLUDED
#define NS_SKELETON_HEADER_INCLUDED

#define NS_SKELETON_VERSION "1.0"

#undef UNICODE                  // Use ANSI WinAPI functions
#undef _UNICODE                 // Use multibyte encoding on Windows
#define _MBCS                   // Use multibyte encoding on Windows
#define _INTEGRAL_MAX_BITS 64   // Enable _stati64() on Windows
#define _CRT_SECURE_NO_WARNINGS // Disable deprecation warning in VS2005+
#undef WIN32_LEAN_AND_MEAN      // Let windows.h always include winsock2.h
#define _XOPEN_SOURCE 600       // For flockfile() on Linux
#define __STDC_FORMAT_MACROS    // <inttypes.h> wants this for C++
#define __STDC_LIMIT_MACROS     // C++ wants that for INT64_MAX
#define _LARGEFILE_SOURCE       // Enable fseeko() and ftello() functions
#define _FILE_OFFSET_BITS 64    // Enable 64-bit file offsets

#ifdef _MSC_VER
#pragma warning (disable : 4127)  // FD_SET() emits warning, disable it
#pragma warning (disable : 4204)  // missing c99 support
#endif

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")    // Linking with winsock library
#include <windows.h>
#include <process.h>
#ifndef EINPROGRESS
#define EINPROGRESS WSAEINPROGRESS
#endif
#ifndef EWOULDBLOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif
#ifndef __func__
#define STRX(x) #x
#define STR(x) STRX(x)
#define __func__ __FILE__ ":" STR(__LINE__)
#endif
#ifndef va_copy
#define va_copy(x,y) x = y
#endif // MINGW #defines va_copy
#define snprintf _snprintf
#define vsnprintf _vsnprintf
typedef int socklen_t;
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned __int64 uint64_t;
typedef __int64   int64_t;
typedef SOCKET sock_t;
#else
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdarg.h>
#include <unistd.h>
#include <arpa/inet.h>  // For inet_pton() when NS_ENABLE_IPV6 is defined
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#define closesocket(x) close(x)
#define __cdecl
#define INVALID_SOCKET (-1)
typedef int sock_t;
#endif

#ifdef NS_ENABLE_DEBUG
#define DBG(x) do { printf("%-20s ", __func__); printf x; putchar('\n'); \
  fflush(stdout); } while(0)
#else
#define DBG(x)
#endif

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

#ifdef NS_ENABLE_SSL
#ifdef __APPLE__
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
#include <openssl/ssl.h>
#else
typedef void *SSL;
typedef void *SSL_CTX;
#endif

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

union socket_address {
  struct sockaddr sa;
  struct sockaddr_in sin;
#ifdef NS_ENABLE_IPV6
  struct sockaddr_in6 sin6;
#endif
};

struct iobuf {
  char *buf;
  int len;
  int size;
};

void iobuf_init(struct iobuf *, int initial_size);
void iobuf_free(struct iobuf *);
int iobuf_append(struct iobuf *, const void *data, int data_size);
void iobuf_remove(struct iobuf *, int data_size);

struct ns_connection;
enum ns_event {NS_POLL, NS_ACCEPT, NS_CONNECT, NS_RECV, NS_SEND, NS_CLOSE};
typedef void (*ns_callback_t)(struct ns_connection *, enum ns_event);

struct ns_server {
  void *server_data;
  sock_t listening_sock;
  struct ns_connection *active_connections;
  ns_callback_t callback;
  SSL_CTX *ssl_ctx;
  SSL_CTX *client_ssl_ctx;
};

struct ns_connection {
  struct ns_connection *prev, *next;
  struct ns_server *server;
  void *connection_data;
  void *callback_param;
  time_t last_io_time;
  sock_t sock;
  struct iobuf recv_iobuf;
  struct iobuf send_iobuf;
  SSL *ssl;
  unsigned int flags;
#define NSF_FINISHED_SENDING_DATA   1
#define NSF_BUFFER_BUT_DONT_SEND    2
#define NSF_SSL_HANDSHAKE_DONE      4
#define NSF_CONNECTING              8
#define NSF_CLOSE_IMMEDIATELY       16
#define NSF_ACCEPTED                32
#define NSF_USER_1                  64
#define NSF_USER_2                  128
};

void ns_server_init(struct ns_server *, void *server_data, ns_callback_t);
void ns_server_free(struct ns_server *);
int ns_server_poll(struct ns_server *, int milli);
void ns_server_wakeup(struct ns_server *, void *conn_param);
void ns_iterate(struct ns_server *, ns_callback_t cb, void *param);
struct ns_connection *ns_add_sock(struct ns_server *, sock_t sock, void *p);

int ns_bind_to(struct ns_server *, const char *port, const char *ssl_cert);
struct ns_connection *ns_connect(struct ns_server *, const char *host,
                                 int port, int ssl, void *connection_param);

int ns_send(struct ns_connection *, const void *buf, int len);
int ns_printf(struct ns_connection *, const char *fmt, ...);

// Utility functions
void *ns_start_thread(void *(*f)(void *), void *p);
sock_t ns_socketpair(sock_t [2]);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // NS_SKELETON_HEADER_INCLUDED
