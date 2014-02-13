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

#include <time.h>      // required for time_t

#ifdef _WIN32
#include <winsock.h>
typedef SOCKET sock_t;
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
  sock_t listening_sock;
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
  sock_t sock;
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
struct ts_connection *ts_add_sock(struct ts_server *, sock_t sock, void *p);

int ts_bind_to(struct ts_server *, const char *port, const char *ssl_cert);
struct ts_connection *ts_connect(struct ts_server *, const char *host,
                                 int port, int ssl, void *connection_param);

int ts_send(struct ts_connection *, const void *buf, int len);
int ts_printf(struct ts_connection *, const char *fmt, ...);

// Utility functions
void *ts_start_thread(void *(*f)(void *), void *p);
int ts_socketpair(sock_t [2]);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // TS_SKELETON_HEADER_INCLUDED
