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

#include "net_skeleton.h"

#ifndef NS_MALLOC
#define NS_MALLOC malloc
#endif

#ifndef NS_REALLOC
#define NS_REALLOC realloc
#endif

#ifndef NS_FREE
#define NS_FREE free
#endif

#ifndef IOBUF_RESIZE_MULTIPLIER
#define IOBUF_RESIZE_MULTIPLIER 2.0
#endif

void iobuf_init(struct iobuf *iobuf, int size) {
  iobuf->len = iobuf->size = 0;
  iobuf->buf = NULL;

  if (size > 0 && (iobuf->buf = (char *) NS_MALLOC(size)) != NULL) {
    iobuf->size = size;
  }
}

void iobuf_free(struct iobuf *iobuf) {
  if (iobuf != NULL) {
    if (iobuf->buf != NULL) NS_FREE(iobuf->buf);
    iobuf_init(iobuf, 0);
  }
}

int iobuf_append(struct iobuf *io, const void *buf, int len) {
  static const double mult = IOBUF_RESIZE_MULTIPLIER;
  char *p = NULL;
  int new_len = 0;

  assert(io->len >= 0);
  assert(io->len <= io->size);

  if (len <= 0) {
  } else if ((new_len = io->len + len) < io->size) {
    memcpy(io->buf + io->len, buf, len);
    io->len = new_len;
  } else if ((p = (char *)
              NS_REALLOC(io->buf, (int) (new_len * mult))) != NULL) {
    io->buf = p;
    memcpy(io->buf + io->len, buf, len);
    io->len = new_len;
    io->size = (int) (new_len * mult);
  } else {
    len = 0;
  }

  return len;
}

void iobuf_remove(struct iobuf *io, int n) {
  if (n >= 0 && n <= io->len) {
    memmove(io->buf, io->buf + n, io->len - n);
    io->len -= n;
  }
}

#ifndef NS_DISABLE_THREADS
void *ns_start_thread(void *(*f)(void *), void *p) {
#ifdef _WIN32
  return (void *) _beginthread((void (__cdecl *)(void *)) f, 0, p);
#else
  pthread_t thread_id = (pthread_t) 0;
  pthread_attr_t attr;

  (void) pthread_attr_init(&attr);
  (void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

#if NS_STACK_SIZE > 1
  (void) pthread_attr_setstacksize(&attr, NS_STACK_SIZE);
#endif

  pthread_create(&thread_id, &attr, f, p);
  pthread_attr_destroy(&attr);

  return (void *) thread_id;
#endif
}
#endif  // NS_DISABLE_THREADS

static void add_connection(struct ns_server *server, struct ns_connection *c) {
  c->next = server->active_connections;
  server->active_connections = c;
  c->prev = NULL;
  if (c->next != NULL) c->next->prev = c;
}

static void remove_connection(struct ns_connection *conn) {
  if (conn->prev == NULL) conn->server->active_connections = conn->next;
  if (conn->prev) conn->prev->next = conn->next;
  if (conn->next) conn->next->prev = conn->prev;
}

// Print message to buffer. If buffer is large enough to hold the message,
// return buffer. If buffer is to small, allocate large enough buffer on heap,
// and return allocated buffer.
static int alloc_vprintf(char **buf, size_t size, const char *fmt, va_list ap) {
  va_list ap_copy;
  int len;

  va_copy(ap_copy, ap);
  len = vsnprintf(*buf, size, fmt, ap_copy);
  va_end(ap_copy);

  if (len < 0) {
    // eCos and Windows are not standard-compliant and return -1 when
    // the buffer is too small. Keep allocating larger buffers until we
    // succeed or out of memory.
    *buf = NULL;
    while (len < 0) {
      if (*buf) free(*buf);
      size *= 2;
      if ((*buf = (char *) NS_MALLOC(size)) == NULL) break;
      va_copy(ap_copy, ap);
      len = vsnprintf(*buf, size, fmt, ap_copy);
      va_end(ap_copy);
    }
  } else if (len > (int) size) {
    // Standard-compliant code path. Allocate a buffer that is large enough.
    if ((*buf = (char *) NS_MALLOC(len + 1)) == NULL) {
      len = -1;
    } else {
      va_copy(ap_copy, ap);
      len = vsnprintf(*buf, len + 1, fmt, ap_copy);
      va_end(ap_copy);
    }
  }

  return len;
}

int ns_vprintf(struct ns_connection *conn, const char *fmt, va_list ap) {
  char mem[2000], *buf = mem;
  int len;

  if ((len = alloc_vprintf(&buf, sizeof(mem), fmt, ap)) > 0) {
    iobuf_append(&conn->send_iobuf, buf, len);
  }
  if (buf != mem && buf != NULL) {
    free(buf);
  }

  return len;
}

int ns_printf(struct ns_connection *conn, const char *fmt, ...) {
  int len;
  va_list ap;
  va_start(ap, fmt);
  len = ns_vprintf(conn, fmt, ap);
  va_end(ap);
  return len;
}

static void call_user(struct ns_connection *conn, enum ns_event ev, void *p) {
  if (conn->server->callback) conn->server->callback(conn, ev, p);
}

static void close_conn(struct ns_connection *conn) {
  DBG(("%p %d", conn, conn->flags));
  call_user(conn, NS_CLOSE, NULL);
  remove_connection(conn);
  closesocket(conn->sock);
  iobuf_free(&conn->recv_iobuf);
  iobuf_free(&conn->send_iobuf);
  NS_FREE(conn);
}

void ns_set_close_on_exec(sock_t sock) {
#ifdef _WIN32
  (void) SetHandleInformation((HANDLE) sock, HANDLE_FLAG_INHERIT, 0);
#else
  fcntl(sock, F_SETFD, FD_CLOEXEC);
#endif
}

static void set_non_blocking_mode(sock_t sock) {
#ifdef _WIN32
  unsigned long on = 1;
  ioctlsocket(sock, FIONBIO, &on);
#else
  int flags = fcntl(sock, F_GETFL, 0);
  fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif
}

#ifndef NS_DISABLE_SOCKETPAIR
int ns_socketpair(sock_t sp[2]) {
  struct sockaddr_in sa;
  sock_t sock;
  socklen_t len = sizeof(sa);
  int ret = 0;

  sp[0] = sp[1] = INVALID_SOCKET;

  (void) memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(0);
  sa.sin_addr.s_addr = htonl(0x7f000001);

  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) != INVALID_SOCKET &&
      !bind(sock, (struct sockaddr *) &sa, len) &&
      !listen(sock, 1) &&
      !getsockname(sock, (struct sockaddr *) &sa, &len) &&
      (sp[0] = socket(AF_INET, SOCK_STREAM, 6)) != -1 &&
      !connect(sp[0], (struct sockaddr *) &sa, len) &&
      (sp[1] = accept(sock,(struct sockaddr *) &sa, &len)) != INVALID_SOCKET) {
    ns_set_close_on_exec(sp[0]);
    ns_set_close_on_exec(sp[1]);
    ret = 1;
  } else {
    if (sp[0] != INVALID_SOCKET) closesocket(sp[0]);
    if (sp[1] != INVALID_SOCKET) closesocket(sp[1]);
    sp[0] = sp[1] = INVALID_SOCKET;
  }
  closesocket(sock);

  return ret;
}
#endif  // NS_DISABLE_SOCKETPAIR

// Valid listening port spec is: [ip_address:]port, e.g. "80", "127.0.0.1:3128"
static int parse_port_string(const char *str, union socket_address *sa) {
  unsigned int a, b, c, d, port;
  int len = 0;
#ifdef NS_ENABLE_IPV6
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
#ifdef NS_ENABLE_IPV6
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
static sock_t open_listening_socket(union socket_address *sa) {
  socklen_t len = sizeof(*sa);
  sock_t on = 1, sock = INVALID_SOCKET;

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


int ns_set_ssl_cert(struct ns_server *server, const char *cert) {
#ifdef NS_ENABLE_SSL
  if (cert != NULL &&
      (server->ssl_ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
    return -1;
  } else if (SSL_CTX_use_certificate_file(server->ssl_ctx, cert, 1) == 0 ||
             SSL_CTX_use_PrivateKey_file(server->ssl_ctx, cert, 1) == 0) {
    return -2;
  } else {
    SSL_CTX_use_certificate_chain_file(server->ssl_ctx, cert);
  }
  return 0;
#else
  return server != NULL && cert == NULL ? 0 : -3;
#endif
}

int ns_bind(struct ns_server *server, const char *str) {
  parse_port_string(str, &server->listening_sa);
  if (server->listening_sock != INVALID_SOCKET) {
    closesocket(server->listening_sock);
  }
  server->listening_sock = open_listening_socket(&server->listening_sa);
  return server->listening_sock == INVALID_SOCKET ? -1 :
    (int) ntohs(server->listening_sa.sin.sin_port);
}


static struct ns_connection *accept_conn(struct ns_server *server) {
  struct ns_connection *c = NULL;
  union socket_address sa;
  socklen_t len = sizeof(sa);
  sock_t sock = INVALID_SOCKET;

  // NOTE(lsm): on Windows, sock is always > FD_SETSIZE
  if ((sock = accept(server->listening_sock, &sa.sa, &len)) == INVALID_SOCKET) {
    closesocket(sock);
  } else if ((c = (struct ns_connection *) NS_MALLOC(sizeof(*c))) == NULL ||
             memset(c, 0, sizeof(*c)) == NULL) {
    closesocket(sock);
#ifdef NS_ENABLE_SSL
  } else if (server->ssl_ctx != NULL &&
             ((c->ssl = SSL_new(server->ssl_ctx)) == NULL ||
              SSL_set_fd(c->ssl, sock) != 1)) {
    DBG(("SSL error"));
    closesocket(sock);
    free(c);
    c = NULL;
#endif
  } else {
    ns_set_close_on_exec(sock);
    set_non_blocking_mode(sock);
    c->server = server;
    c->sock = sock;
    c->flags |= NSF_ACCEPTED;

    add_connection(server, c);
    call_user(c, NS_ACCEPT, &sa);
    DBG(("%p %d %p %p", c, c->sock, c->ssl, server->ssl_ctx));
  }

  return c;
}

static int ns_is_error(int n) {
  return n == 0 ||
    (n < 0 && errno != EINTR && errno != EINPROGRESS &&
     errno != EAGAIN && errno != EWOULDBLOCK
#ifdef _WIN32
     && WSAGetLastError() != WSAEINTR && WSAGetLastError() != WSAEWOULDBLOCK
#endif
    );
}

#ifdef NS_ENABLE_HEXDUMP
static void hexdump(const struct ns_connection *conn, const void *buf,
                    int len, const char *marker) {
  const unsigned char *p = (const unsigned char *) buf;
  char path[500], date[100], ascii[17];
  FILE *fp;

#if 0
  if (!match_prefix(NS_ENABLE_HEXDUMP, strlen(NS_ENABLE_HEXDUMP),
                    conn->remote_ip)) {
    return;
  }

  snprintf(path, sizeof(path), "%s.%hu.txt",
           conn->mg_conn.remote_ip, conn->mg_conn.remote_port);
#endif
  snprintf(path, sizeof(path), "%p.txt", conn);

  if ((fp = fopen(path, "a")) != NULL) {
    time_t cur_time = time(NULL);
    int i, idx;

    strftime(date, sizeof(date), "%d/%b/%Y %H:%M:%S", localtime(&cur_time));
    fprintf(fp, "%s %s %d bytes\n", marker, date, len);

    for (i = 0; i < len; i++) {
      idx = i % 16;
      if (idx == 0) {
        if (i > 0) fprintf(fp, "  %s\n", ascii);
        fprintf(fp, "%04x ", i);
      }
      fprintf(fp, " %02x", p[i]);
      ascii[idx] = p[i] < 0x20 || p[i] > 0x7e ? '.' : p[i];
      ascii[idx + 1] = '\0';
    }

    while (i++ % 16) fprintf(fp, "%s", "   ");
    fprintf(fp, "  %s\n\n", ascii);

    fclose(fp);
  }
}
#endif

static void read_from_socket(struct ns_connection *conn) {
  char buf[2048];
  int n = 0;

  if (conn->flags & NSF_CONNECTING) {
    int ok = 1, ret;
    socklen_t len = sizeof(ok);

    conn->flags &= ~NSF_CONNECTING;
    ret = getsockopt(conn->sock, SOL_SOCKET, SO_ERROR, (char *) &ok, &len);
    (void) ret;
#ifdef NS_ENABLE_SSL
    if (ret == 0 && ok == 0 && conn->ssl != NULL) {
      int res = SSL_connect(conn->ssl);
      int ssl_err = SSL_get_error(conn->ssl, res);
      DBG(("%p res %d %d", conn, res, ssl_err));
      if (res == 1) {
        conn->flags = NSF_SSL_HANDSHAKE_DONE;
      } else if (res == 0 || ssl_err == 2 || ssl_err == 3) {
        conn->flags |= NSF_CONNECTING;
        return; // Call us again
      } else {
        ok = 1;
      }
    }
#endif
    DBG(("%p ok=%d", conn, ok));
    if (ok != 0) {
      conn->flags |= NSF_CLOSE_IMMEDIATELY;
    }
    call_user(conn, NS_CONNECT, &ok);
    return;
  }

#ifdef NS_ENABLE_SSL
  if (conn->ssl != NULL) {
    if (conn->flags & NSF_SSL_HANDSHAKE_DONE) {
      n = SSL_read(conn->ssl, buf, sizeof(buf));
    } else {
      if (SSL_accept(conn->ssl) == 1) {
        conn->flags |= NSF_SSL_HANDSHAKE_DONE;
      }
      return;
    }
  } else
#endif
  {
    n = recv(conn->sock, buf, sizeof(buf), 0);
  }

#ifdef NS_ENABLE_HEXDUMP
  hexdump(conn, buf, n, "<-");
#endif

  DBG(("%p <- %d bytes [%.*s%s]",
       conn, n, n < 40 ? n : 40, buf, n < 40 ? "" : "..."));

  if (ns_is_error(n)) {
    conn->flags |= NSF_CLOSE_IMMEDIATELY;
  } else if (n > 0) {
    iobuf_append(&conn->recv_iobuf, buf, n);
    call_user(conn, NS_RECV, &n);
  }
}

static void write_to_socket(struct ns_connection *conn) {
  struct iobuf *io = &conn->send_iobuf;
  int n = 0;

#ifdef NS_ENABLE_SSL
  if (conn->ssl != NULL) {
    n = SSL_write(conn->ssl, io->buf, io->len);
  } else
#endif
  { n = send(conn->sock, io->buf, io->len, 0); }


#ifdef NS_ENABLE_HEXDUMP
  hexdump(conn, io->buf, n, "->");
#endif

  DBG(("%p -> %d bytes [%.*s%s]", conn, n, io->len < 40 ? io->len : 40,
       io->buf, io->len < 40 ? "" : "..."));

  if (ns_is_error(n)) {
    conn->flags |= NSF_CLOSE_IMMEDIATELY;
  } else if (n > 0) {
    iobuf_remove(io, n);
    //conn->num_bytes_sent += n;
  }

  if (io->len == 0 && conn->flags & NSF_FINISHED_SENDING_DATA) {
    conn->flags |= NSF_CLOSE_IMMEDIATELY;
  }

  call_user(conn, NS_SEND, NULL);
}

int ns_send(struct ns_connection *conn, const void *buf, int len) {
  return iobuf_append(&conn->send_iobuf, buf, len);
}

static void add_to_set(sock_t sock, fd_set *set, sock_t *max_fd) {
  if (sock != INVALID_SOCKET) {
    FD_SET(sock, set);
    if (*max_fd == INVALID_SOCKET || sock > *max_fd) {
      *max_fd = sock;
    }
  }
}

int ns_server_poll(struct ns_server *server, int milli) {
  struct ns_connection *conn, *tmp_conn;
  struct timeval tv;
  fd_set read_set, write_set;
  int num_active_connections = 0;
  sock_t max_fd = INVALID_SOCKET;
  time_t current_time = time(NULL);

  if (server->listening_sock == INVALID_SOCKET &&
      server->active_connections == NULL) return 0;

  FD_ZERO(&read_set);
  FD_ZERO(&write_set);
  add_to_set(server->listening_sock, &read_set, &max_fd);

  for (conn = server->active_connections; conn != NULL; conn = tmp_conn) {
    tmp_conn = conn->next;
    call_user(conn, NS_POLL, &current_time);
    add_to_set(conn->sock, &read_set, &max_fd);
    if (conn->flags & NSF_CONNECTING) {
      add_to_set(conn->sock, &write_set, &max_fd);
    }
    if (conn->send_iobuf.len > 0 && !(conn->flags & NSF_BUFFER_BUT_DONT_SEND)) {
      add_to_set(conn->sock, &write_set, &max_fd);
    } else if (conn->flags & NSF_CLOSE_IMMEDIATELY) {
      close_conn(conn);
    }
  }

  tv.tv_sec = milli / 1000;
  tv.tv_usec = (milli % 1000) * 1000;

  if (select((int) max_fd + 1, &read_set, &write_set, NULL, &tv) > 0) {
    // Accept new connections
    if (server->listening_sock >= 0 &&
        FD_ISSET(server->listening_sock, &read_set)) {
      // We're not looping here, and accepting just one connection at
      // a time. The reason is that eCos does not respect non-blocking
      // flag on a listening socket and hangs in a loop.
      if ((conn = accept_conn(server)) != NULL) {
        conn->last_io_time = current_time;
      }
    }

    for (conn = server->active_connections; conn != NULL; conn = tmp_conn) {
      tmp_conn = conn->next;
      if (FD_ISSET(conn->sock, &read_set)) {
        conn->last_io_time = current_time;
        read_from_socket(conn);
      }
      if (FD_ISSET(conn->sock, &write_set)) {
        if (conn->flags & NSF_CONNECTING) {
          read_from_socket(conn);
        } else if (!(conn->flags & NSF_BUFFER_BUT_DONT_SEND)) {
          conn->last_io_time = current_time;
          write_to_socket(conn);
        }
      }
    }
  }

  for (conn = server->active_connections; conn != NULL; conn = tmp_conn) {
    tmp_conn = conn->next;
    num_active_connections++;
    if (conn->flags & NSF_CLOSE_IMMEDIATELY) {
      close_conn(conn);
    }
  }
  //DBG(("%d active connections", num_active_connections));

  return num_active_connections;
}

struct ns_connection *ns_connect(struct ns_server *server, const char *host,
                                 int port, int use_ssl, void *param) {
  sock_t sock = INVALID_SOCKET;
  struct sockaddr_in sin;
  struct hostent *he = NULL;
  struct ns_connection *conn = NULL;
  int connect_ret_val;

#ifndef NS_ENABLE_SSL
  if (use_ssl) return 0;
#endif

  if (host == NULL || (he = gethostbyname(host)) == NULL ||
      (sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
    DBG(("gethostbyname(%s) failed: %s", host, strerror(errno)));
    return NULL;
  }

  sin.sin_family = AF_INET;
  sin.sin_port = htons((uint16_t) port);
  sin.sin_addr = * (struct in_addr *) he->h_addr_list[0];
  set_non_blocking_mode(sock);

  connect_ret_val = connect(sock, (struct sockaddr *) &sin, sizeof(sin));
  if (ns_is_error(connect_ret_val)) {
    return NULL;
  } else if ((conn = (struct ns_connection *)
              NS_MALLOC(sizeof(*conn))) == NULL) {
    closesocket(sock);
    return NULL;
  }

  memset(conn, 0, sizeof(*conn));
  conn->server = server;
  conn->sock = sock;
  conn->connection_data = param;
  conn->flags = NSF_CONNECTING;
  conn->last_io_time = time(NULL);

#ifdef NS_ENABLE_SSL
  if (use_ssl &&
      (conn->ssl = SSL_new(server->client_ssl_ctx)) != NULL) {
    SSL_set_fd(conn->ssl, sock);
  }
#endif

  add_connection(server, conn);
  DBG(("%p %s:%d %d %p", conn, host, port, conn->sock, conn->ssl));

  return conn;
}

struct ns_connection *ns_add_sock(struct ns_server *s, sock_t sock, void *p) {
  struct ns_connection *conn;
  if ((conn = (struct ns_connection *) NS_MALLOC(sizeof(*conn))) != NULL) {
    memset(conn, 0, sizeof(*conn));
    set_non_blocking_mode(sock);
    conn->sock = sock;
    conn->connection_data = p;
    conn->server = s;
    conn->last_io_time = time(NULL);
    add_connection(s, conn);
    DBG(("%p %d", conn, sock));
  }
  return conn;
}

void ns_iterate(struct ns_server *server, ns_callback_t cb, void *param) {
  struct ns_connection *conn, *tmp_conn;

  for (conn = server->active_connections; conn != NULL; conn = tmp_conn) {
    tmp_conn = conn->next;
    cb(conn, NS_POLL, param);
  }
}

void ns_server_init(struct ns_server *s, void *server_data, ns_callback_t cb) {
  memset(s, 0, sizeof(*s));
  s->listening_sock = INVALID_SOCKET;
  s->server_data = server_data;
  s->callback = cb;

#ifdef _WIN32
  { WSADATA data; WSAStartup(MAKEWORD(2, 2), &data); }
#else
  // Ignore SIGPIPE signal, so if client cancels the request, it
  // won't kill the whole process.
  signal(SIGPIPE, SIG_IGN);
#endif

#ifdef NS_ENABLE_SSL
  SSL_library_init();
  s->client_ssl_ctx = SSL_CTX_new(SSLv23_client_method());
#endif
}

void ns_server_free(struct ns_server *s) {
  struct ns_connection *conn, *tmp_conn;

  DBG(("%p", s));
  if (s == NULL) return;
  // Do one last poll, see https://github.com/cesanta/mongoose/issues/286
  ns_server_poll(s, 0);

  if (s->listening_sock != INVALID_SOCKET) {
    closesocket(s->listening_sock);
  }

  for (conn = s->active_connections; conn != NULL; conn = tmp_conn) {
    tmp_conn = conn->next;
    close_conn(conn);
  }

#ifndef NS_DISABLE_SOCKETPAIR
  //closesocket(s->ctl[0]);
  //closesocket(s->ctl[1]);
#endif

#ifdef NS_ENABLE_SSL
  if (s->ssl_ctx != NULL) SSL_CTX_free(s->ssl_ctx);
  if (s->client_ssl_ctx != NULL) SSL_CTX_free(s->client_ssl_ctx);
#endif
}
