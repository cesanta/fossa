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

#ifndef TS_SKELETON_HEADER_INCLUDED
#define TS_SKELETON_HEADER_INCLUDED

#define TS_SKELETON_VERSION "1.0"

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
#else
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdarg.h>
#include <unistd.h>
#include <arpa/inet.h>  // For inet_pton() when TS_ENABLE_IPV6 is defined
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#define INVALID_SOCKET (-1)
#define closesocket(x) close(x)
#define __cdecl
#endif

#ifdef TS_ENABLE_SSL
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

struct iobuf {
  char *buf;
  int len;
  int size;
};

void iobuf_init(struct iobuf *, int initial_size);
void iobuf_free(struct iobuf *);
int iobuf_append(struct iobuf *, const void *data, int data_size);
void iobuf_remove(struct iobuf *, int data_size);

struct ts_connection;
enum ts_event {TS_POLL, TS_ACCEPT, TS_CONNECT, TS_RECV, TS_SEND, TS_CLOSE};
typedef void (*ts_callback_t)(struct ts_connection *, enum ts_event);

struct ts_server {
  void *server_data;
  int listening_sock;
  struct ts_connection *active_connections;
  ts_callback_t callback;
  void *ssl_ctx;
  void *client_ssl_ctx;
};

struct ts_connection {
  struct ts_connection *prev, *next;
  struct ts_server *server;
  void *connection_data;
  void *callback_param;
  time_t last_io_time;
  int sock;
  struct iobuf recv_iobuf;
  struct iobuf send_iobuf;
  void *ssl;
  unsigned int flags;
#define TSF_FINISHED_SENDING_DATA   1
#define TSF_BUFFER_BUT_DONT_SEND    2
#define TSF_SSL_HANDSHAKE_DONE      4
#define TSF_CONNECTING              8
#define TSF_CLOSE_IMMEDIATELY       16
#define TSF_ACCEPTED                32
#define TSF_USER_1                  64
#define TSF_USER_2                  128
};

void ts_server_init(struct ts_server *, void *server_data, ts_callback_t);
void ts_server_free(struct ts_server *);
int ts_server_poll(struct ts_server *, int milli);
void ts_server_wakeup(struct ts_server *, void *conn_param);
void ts_iterate(struct ts_server *, ts_callback_t cb, void *param);
struct ts_connection *ts_add_sock(struct ts_server *, int sock, void *p);

int ts_bind_to(struct ts_server *, const char *port, const char *ssl_cert);
struct ts_connection *ts_connect(struct ts_server *, const char *host,
                                 int port, int ssl, void *connection_param);

int ts_send(struct ts_connection *, const void *buf, int len);
int ts_printf(struct ts_connection *, const char *fmt, ...);

// Utility functions
void *ts_start_thread(void *(*f)(void *), void *p);
int ts_socketpair(int [2]);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // TS_SKELETON_HEADER_INCLUDED
