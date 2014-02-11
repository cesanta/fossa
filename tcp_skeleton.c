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

#define _CRT_SECURE_NO_WARNINGS // Disable deprecation warning in VS2005+
#undef WIN32_LEAN_AND_MEAN      // Let windows.h always include winsock2.h

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
#include <windows.h>
typedef int socklen_t;
#ifndef EINPROGRESS
#define EINPROGRESS WSAEINPROGRESS
#endif
#ifndef EWOULDBLOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif
#else
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>  // For inet_pton() when TS_ENABLE_IPV6 is defined
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#define INVALID_SOCKET (-1)
#define closesocket(x) close(x)
#endif

#ifdef TS_ENABLE_SSL
#ifdef __APPLE__
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
#include <openssl/ssl.h>
#endif

#include "tcp_skeleton.h"

#ifndef TS_MALLOC
#define TS_MALLOC malloc
#endif

#ifndef TS_REALLOC
#define TS_REALLOC realloc
#endif

#ifndef TS_FREE
#define TS_FREE free
#endif

#ifdef TS_DEBUG
#define DBG(x) do { printf("%-20s ", __func__); printf x; putchar('\n'); \
  fflush(stdout); } while(0)
#else
#define DBG(x)
#endif

#ifndef IOBUF_RESIZE_MULTIPLIER
#define IOBUF_RESIZE_MULTIPLIER 2.0
#endif

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

union socket_address {
  struct sockaddr sa;
  struct sockaddr_in sin;
#ifdef TS_ENABLE_IPV6
  struct sockaddr_in6 sin6;
#endif
};

void iobuf_init(struct iobuf *iobuf, int size) {
  iobuf->len = iobuf->size = 0;
  iobuf->buf = NULL;

  if (size > 0 && (iobuf->buf = (char *) TS_MALLOC(size)) != NULL) {
    iobuf->size = size;
  }
}

void iobuf_free(struct iobuf *iobuf) {
  if (iobuf != NULL) {
    if (iobuf->buf != NULL) TS_FREE(iobuf->buf);
    iobuf_init(iobuf, 0);
  }
}

int iobuf_append(struct iobuf *io, const void *buf, int len) {
  static const double mult = IOBUF_RESIZE_MULTIPLIER;
  char *p = NULL;
  int new_len = 0;

  assert(io->len >= 0);
  assert(io->len <= io->size);

  //DBG(("1. %d %d %d", len, io->len, io->size));
  if (len <= 0) {
  } else if ((new_len = io->len + len) < io->size) {
    memcpy(io->buf + io->len, buf, len);
    io->len = new_len;
  } else if ((p = (char *)
              TS_REALLOC(io->buf, (int) (new_len * mult))) != NULL) {
    io->buf = p;
    memcpy(io->buf + io->len, buf, len);
    io->len = new_len;
    io->size = (int) (new_len * mult);
  } else {
    len = 0;
  }
  //DBG(("%d %d %d", len, io->len, io->size));

  return len;
}

void iobuf_remove(struct iobuf *io, int n) {
  if (n >= 0 && n <= io->len) {
    memmove(io->buf, io->buf + n, io->len - n);
    io->len -= n;
  }
}


static void close_conn(struct ts_connection *conn, ts_callback_t cb) {
  if (cb != NULL) cb(conn, TS_CLOSE, NULL);
  conn->prev->next = conn->next;
  conn->next->prev = conn->prev;
  closesocket(conn->sock);
  DBG(("%p %d %d", conn, conn->flags, conn->endpoint_type));
  iobuf_free(&conn->recv_iobuf);
  iobuf_free(&conn->send_iobuf);
  TS_FREE(conn);
}

static void set_close_on_exec(int fd) {
#ifdef _WIN32
  (void) SetHandleInformation((HANDLE) fd, HANDLE_FLAG_INHERIT, 0);
#else
  fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
}

static void set_non_blocking_mode(int sock) {
#ifdef _WIN32
  unsigned long on = 1;
  ioctlsocket(sock, FIONBIO, &on);
#else
  int flags = fcntl(sock, F_GETFL, 0);
  fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif
}

// Valid listening port spec is: [ip_address:]port, e.g. "80", "127.0.0.1:3128"
static int parse_port_string(const char *str, union socket_address *sa) {
  unsigned int a, b, c, d, port;
  int len = 0;
#ifdef TS_ENABLE_IPV6
  char buf[100];
#endif

  // MacOS needs that. If we do not zero it, subsequent bind() will fail.
  // Also, all-zeroes in the socket address means binding to all addresses
  // for both IPv4 and IPv6 (INADDR_ANY and IN6ADDR_ANY_INIT).
  memset(sa, 0, sizeof(*sa));
  sa->sin.sin_family = AF_INET;

  if (sscanf(str, "%u.%u.%u.%u:%u%n", &a, &b, &c, &d, &port, &len) == 5) {
    // Bind to a specific IPv4 address, e.g. 192.168.1.5:8080
    sa->sin.sin_addr.s_addr = htonl((a << 24) | (b << 16) | (c << 8) | d);
    sa->sin.sin_port = htons((uint16_t) port);
#ifdef TS_ENABLE_IPV6
  } else if (sscanf(str, "[%49[^]]]:%u%n", buf, &port, &len) == 2 &&
             inet_pton(AF_INET6, buf, &sa->sin6.sin6_addr)) {
    // IPv6 address, e.g. [3ffe:2a00:100:7031::1]:8080
    sa->sin6.sin6_family = AF_INET6;
    sa->sin6.sin6_port = htons((uint16_t) port);
#endif
  } else if (sscanf(str, "%u%n", &port, &len) == 1) {
    // If only port is specified, bind to IPv4, INADDR_ANY
    sa->sin.sin_port = htons((uint16_t) port);
  } else {
    port = 0;   // Parsing failure. Make port invalid.
  }

  return port <= 0xffff && str[len] == '\0';
}

// 'sa' must be an initialized address to bind to
static int open_listening_socket(union socket_address *sa) {
  socklen_t len = sizeof(*sa);
  int on = 1, sock = INVALID_SOCKET;

  if ((sock = socket(sa->sa.sa_family, SOCK_STREAM, 6)) != INVALID_SOCKET &&
      !setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on)) &&
      !bind(sock, &sa->sa, sa->sa.sa_family == AF_INET ?
            sizeof(sa->sin) : sizeof(sa->sa)) &&
      !listen(sock, SOMAXCONN)) {
    set_non_blocking_mode(sock);
    // In case port was set to 0, get the real port number
    (void) getsockname(sock, &sa->sa, &len);
  } else if (sock != INVALID_SOCKET) {
    closesocket(sock);
    sock = INVALID_SOCKET;
  }

  return sock;
}

int ts_open_listening_sock(const char *str) {
  union socket_address sa;
  parse_port_string(str, &sa);
  return open_listening_socket(&sa);
}

static struct ts_connection *accept_new_connection(struct ts_server *server) {
  struct ts_connection *c = NULL;
  union socket_address sa;
  socklen_t len = sizeof(sa);
  int sock = INVALID_SOCKET;

  // NOTE(lsm): on Windows, sock is always > FD_SETSIZE
  if ((sock = accept(server->listening_sock, &sa.sa, &len)) == INVALID_SOCKET) {
    closesocket(sock);
  } else if ((c = (struct ts_connection *) calloc(1, sizeof(*c))) == NULL) {
    closesocket(sock);
  } else {
    set_close_on_exec(sock);
    set_non_blocking_mode(sock);
    c->sock = sock;
#if 0
    sockaddr_to_string(c->mg_conn.remote_ip,
                       sizeof(conn->mg_conn.remote_ip), &sa);
    c->mg_conn.remote_port = ntohs(sa.sin.sin_port);
    c->mg_conn.server_param = server->server_data;
    c->mg_conn.local_ip = server->local_ip;
    conn->mg_conn.local_port = ntohs(server->lsa.sin.sin_port);
#endif
    //LINKED_LIST_ADD_TO_FRONT(&server->active_connections, &conn->link);
    DBG(("added conn %p", c));
  }

  return c;
}

static int is_error(int n) {
  return n == 0 ||
    (n < 0 && errno != EINTR && errno != EINPROGRESS &&
     errno != EAGAIN && errno != EWOULDBLOCK
#ifdef _WIN32
     && WSAGetLastError() != WSAEINTR && WSAGetLastError() != WSAEWOULDBLOCK
#endif
    );
}

static void read_from_socket(struct ts_connection *conn, ts_callback_t cb) {
  char buf[2048];
  int n = 0;

#if 0
  if (conn->endpoint_type == EP_CLIENT && conn->flags & CONN_CONNECTING) {
    callback_http_client_on_connect(conn);
    return;
  }
#endif

#ifdef TS_ENABLE_SSL
  if (conn->ssl != NULL) {
    if (conn->flags & TSF_SSL_HANDS_SHAKEN) {
      n = SSL_read((SSL *) conn->ssl, buf, sizeof(buf));
    } else {
      if (SSL_accept((SSL *) conn->ssl) == 1) {
        conn->flags |= TSF_SSL_HANDS_SHAKEN;
      }
      return;
    }
  } else
#endif
  {
    n = recv(conn->sock, buf, sizeof(buf), 0);
  }

  DBG(("%p %d %d (1)", conn, n, conn->flags));

#ifdef TS_HEXDUMP
  hexdump(conn, buf, n, "<-");
#endif

  if (is_error(n)) {
#if 0
    if (conn->endpoint_type == EP_CLIENT && conn->local_iobuf.len > 0) {
      call_http_client_handler(conn, MG_DOWNLOAD_SUCCESS);
    }
#endif
    conn->flags |= TSF_CLOSE;
  } else if (n > 0) {
    iobuf_append(&conn->recv_iobuf, buf, n);
    if (cb != NULL) cb(conn, TS_RECV, NULL);
  }
  DBG(("%p %d %d (2)", conn, n, conn->flags));
}

static void add_to_set(int sock, fd_set *set, int *max_fd) {
  FD_SET(sock, set);
  if (sock > *max_fd) {
    *max_fd = sock;
  }
}

int ts_server_poll(struct ts_server *server, int milli, ts_callback_t cb) {
  struct ts_connection *conn, *tmp_conn;
  struct timeval tv;
  fd_set read_set, write_set;
  int num_active_connections = 0, max_fd = -1;
  time_t current_time = time(NULL);

  if (server->listening_sock == INVALID_SOCKET) return 0;

  FD_ZERO(&read_set);
  FD_ZERO(&write_set);
  add_to_set(server->listening_sock, &read_set, &max_fd);

  for (conn = server->active_connections; conn != NULL; conn = conn->next) {
    add_to_set(conn->sock, &read_set, &max_fd);
#if 0
    if (conn->endpoint_type == EP_CLIENT && (conn->flags & CONN_CONNECTING)) {
      add_to_set(conn->client_sock, &write_set, &max_fd);
    }
    if (conn->endpoint_type == EP_FILE) {
      transfer_file_data(conn);
    } else if (conn->endpoint_type == EP_CGI) {
      add_to_set(conn->endpoint.cgi_sock, &read_set, &max_fd);
    }
#endif
    if (conn->send_iobuf.len > 0 && !(conn->flags & TSF_HOLD)) {
      add_to_set(conn->sock, &write_set, &max_fd);
    } else if (conn->flags & TSF_CLOSE) {
      close_conn(conn, cb);
    }
  }

  tv.tv_sec = milli / 1000;
  tv.tv_usec = (milli % 1000) * 1000;

  if (select(max_fd + 1, &read_set, &write_set, NULL, &tv) > 0) {
    // Accept new connections
    if (FD_ISSET(server->listening_sock, &read_set)) {
      // We're not looping here, and accepting just one connection at
      // a time. The reason is that eCos does not respect non-blocking
      // flag on a listening socket and hangs in a loop.
      if ((conn = accept_new_connection(server)) != NULL) {
        conn->last_io_time = current_time;
      }
    }

    for (conn = server->active_connections; conn != NULL; conn = tmp_conn) {
      tmp_conn = conn->next;
      if (cb) cb(conn, TS_POLL, NULL);
      if (FD_ISSET(conn->sock, &read_set)) {
        conn->last_io_time = current_time;
        read_from_socket(conn, cb);
      }
      num_active_connections++;
#if 0
#ifndef MONGOOSE_NO_CGI
      if (conn->endpoint_type == EP_CGI &&
          FD_ISSET(conn->endpoint.cgi_sock, &read_set)) {
        read_from_cgi(conn);
      }
#endif
      if (FD_ISSET(conn->client_sock, &write_set)) {
        if (conn->endpoint_type == EP_CLIENT &&
            (conn->flags & CONN_CONNECTING)) {
          read_from_socket(conn);
        } else if (!(conn->flags & CONN_BUFFER)) {
          conn->last_activity_time = current_time;
          write_to_socket(conn);
        }
      }
    }
#endif
  }

#if 0
  // Close expired connections and those that need to be closed
  LINKED_LIST_FOREACH(&server->active_connections, lp, tmp) {
    conn = LINKED_LIST_ENTRY(lp, struct connection, link);
    if (conn->mg_conn.is_websocket) {
      ping_idle_websocket_connection(conn, current_time);
    }
    if (conn->flags & CONN_LONG_RUNNING) {
      conn->mg_conn.wsbits = conn->flags & CONN_CLOSE ? 1 : 0;
      if (call_request_handler(conn) == MG_REQUEST_PROCESSED) {
        conn->flags |= conn->remote_iobuf.len == 0 ? CONN_CLOSE : CONN_SPOOL_DONE;
      }
    }
    if (conn->flags & CONN_CLOSE || conn->last_activity_time < expire_time) {
      close_conn(conn);
    }
#endif
  }

  return num_active_connections;
}

void ts_server_init(struct ts_server *server, void *server_data) {
  memset(server, 0, sizeof(*server));
  server->listening_sock = INVALID_SOCKET;
  server->server_data = server_data;
}

void ts_server_free(struct ts_server *s) {
  struct ts_connection *conn, *tmp_conn;

  if (s == NULL) return;

#if 0
  ts_server_poll(s, 0);
  closesocket(s->listening_sock);
#ifndef TS_DISABLE_SOCKETPAIR
  closesocket(s->ctl[0]);
  closesocket(s->ctl[1]);
#endif
  for(conn = s->active_connections; conn != NULL; conn = tmp_conn) {
    tmp_conn = conn->next;
    close_conn(conn);
  }
#ifdef TS_ENABLE_SSL
  if (s->ssl_ctx != NULL) SSL_CTX_free((*server)->ssl_ctx);
  if (s->client_ssl_ctx != NULL) SSL_CTX_free(s->client_ssl_ctx);
#endif
#endif
}
