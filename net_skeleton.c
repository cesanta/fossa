// Copyright (c) 2014 Cesanta Software Limited
// All rights reserved
//
// This software is dual-licensed: you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation. For the terms of this
// license, see <http://www.gnu.org/licenses/>.
//
// You are free to use this software under the terms of the GNU General
// Public License, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// Alternatively, you can license this software under a commercial
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

struct ctl_msg {
  ns_callback_t callback;
  char message[1024 * 8];
};

void iobuf_init(struct iobuf *iobuf, size_t size) {
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

size_t iobuf_append(struct iobuf *io, const void *buf, size_t len) {
  char *p = NULL;

  assert(io != NULL);
  assert(io->len <= io->size);

  if (len <= 0) {
  } else if (io->len + len <= io->size) {
    memcpy(io->buf + io->len, buf, len);
    io->len += len;
  } else if ((p = (char *) NS_REALLOC(io->buf, io->len + len)) != NULL) {
    io->buf = p;
    memcpy(io->buf + io->len, buf, len);
    io->len += len;
    io->size = io->len;
  } else {
    len = 0;
  }

  return len;
}

void iobuf_remove(struct iobuf *io, size_t n) {
  if (n > 0 && n <= io->len) {
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

static void ns_add_conn(struct ns_server *server, struct ns_connection *c) {
  c->next = server->active_connections;
  server->active_connections = c;
  c->prev = NULL;
  if (c->next != NULL) c->next->prev = c;
}

static void ns_remove_conn(struct ns_connection *conn) {
  if (conn->prev == NULL) conn->server->active_connections = conn->next;
  if (conn->prev) conn->prev->next = conn->next;
  if (conn->next) conn->next->prev = conn->prev;
}

// Print message to buffer. If buffer is large enough to hold the message,
// return buffer. If buffer is to small, allocate large enough buffer on heap,
// and return allocated buffer.
static int ns_avprintf(char **buf, size_t size, const char *fmt, va_list ap) {
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

  if ((len = ns_avprintf(&buf, sizeof(mem), fmt, ap)) > 0) {
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

static void ns_call(struct ns_connection *conn, enum ns_event ev, void *p) {
  if (conn->server->callback) conn->server->callback(conn, ev, p);
}

static void ns_close_conn(struct ns_connection *conn) {
  DBG(("%p %d", conn, conn->flags));
  ns_call(conn, NS_CLOSE, NULL);
  ns_remove_conn(conn);
  closesocket(conn->sock);
  iobuf_free(&conn->recv_iobuf);
  iobuf_free(&conn->send_iobuf);
#ifdef NS_ENABLE_SSL
  if (conn->ssl != NULL) {
    SSL_free(conn->ssl);
  }
#endif
  NS_FREE(conn);
}

void ns_set_close_on_exec(sock_t sock) {
#ifdef _WIN32
  (void) SetHandleInformation((HANDLE) sock, HANDLE_FLAG_INHERIT, 0);
#else
  fcntl(sock, F_SETFD, FD_CLOEXEC);
#endif
}

static void ns_set_non_blocking_mode(sock_t sock) {
#ifdef _WIN32
  unsigned long on = 1;
  ioctlsocket(sock, FIONBIO, &on);
#else
  int flags = fcntl(sock, F_GETFL, 0);
  fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif
}

#ifndef NS_DISABLE_SOCKETPAIR
int ns_socketpair2(sock_t sp[2], int sock_type) {
  union socket_address sa;
  sock_t sock;
  socklen_t len = sizeof(sa.sin);
  int ret = 0;

  sp[0] = sp[1] = INVALID_SOCKET;

  (void) memset(&sa, 0, sizeof(sa));
  sa.sin.sin_family = AF_INET;
  sa.sin.sin_port = htons(0);
  sa.sin.sin_addr.s_addr = htonl(0x7f000001);

  if ((sock = socket(AF_INET, sock_type, 0)) != INVALID_SOCKET &&
      !bind(sock, &sa.sa, len) &&
      (sock_type == SOCK_DGRAM || !listen(sock, 1)) &&
      !getsockname(sock, &sa.sa, &len) &&
      (sp[0] = socket(AF_INET, sock_type, 0)) != INVALID_SOCKET &&
      !connect(sp[0], &sa.sa, len) &&
      (sock_type == SOCK_STREAM ||
       (!getsockname(sp[0], &sa.sa, &len) && !connect(sock, &sa.sa, len))) &&
      (sp[1] = (sock_type == SOCK_DGRAM ? sock :
                accept(sock, &sa.sa, &len))) != INVALID_SOCKET) {
    ns_set_close_on_exec(sp[0]);
    ns_set_close_on_exec(sp[1]);
    ret = 1;
  } else {
    if (sp[0] != INVALID_SOCKET) closesocket(sp[0]);
    if (sp[1] != INVALID_SOCKET) closesocket(sp[1]);
    sp[0] = sp[1] = INVALID_SOCKET;
  }
  if (sock_type != SOCK_DGRAM) closesocket(sock);

  return ret;
}

int ns_socketpair(sock_t sp[2]) {
  return ns_socketpair2(sp, SOCK_STREAM);
}
#endif  // NS_DISABLE_SOCKETPAIR

// Valid listening port spec is: [ip_address:]port, e.g. "80", "127.0.0.1:3128"
static int ns_parse_port_string(const char *str, union socket_address *sa) {
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
static sock_t ns_open_listening_socket(union socket_address *sa) {
  socklen_t len = sizeof(*sa);
  sock_t sock = INVALID_SOCKET;
#ifndef _WIN32
  int on = 1;
#endif

  if ((sock = socket(sa->sa.sa_family, SOCK_STREAM, 6)) != INVALID_SOCKET &&
#ifndef _WIN32
      !setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on)) &&
#endif
      !bind(sock, &sa->sa, sa->sa.sa_family == AF_INET ?
            sizeof(sa->sin) : sizeof(sa->sa)) &&
      !listen(sock, SOMAXCONN)) {
    ns_set_non_blocking_mode(sock);
    // In case port was set to 0, get the real port number
    (void) getsockname(sock, &sa->sa, &len);
  } else if (sock != INVALID_SOCKET) {
    closesocket(sock);
    sock = INVALID_SOCKET;
  }

  return sock;
}

// Certificate generation script is at
// https://github.com/cesanta/net_skeleton/blob/master/examples/gen_certs.sh
int ns_set_ssl_ca_cert(struct ns_server *server, const char *cert) {
#ifdef NS_ENABLE_SSL
  STACK_OF(X509_NAME) *list = SSL_load_client_CA_file(cert);
  if (cert != NULL && server->ssl_ctx != NULL && list != NULL) {
    SSL_CTX_set_client_CA_list(server->ssl_ctx, list);
    SSL_CTX_set_verify(server->ssl_ctx, SSL_VERIFY_PEER |
                       SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    return 0;
  }
#endif
  return server != NULL && cert == NULL ? 0 : -1;
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
    return 0;
  }
#endif
  return server != NULL && cert == NULL ? 0 : -3;
}

int ns_bind(struct ns_server *server, const char *str) {
  union socket_address sa;
  ns_parse_port_string(str, &sa);
  if (server->listening_sock != INVALID_SOCKET) {
    closesocket(server->listening_sock);
  }
  server->listening_sock = ns_open_listening_socket(&sa);
  return server->listening_sock == INVALID_SOCKET ? -1 :
  (int) ntohs(sa.sin.sin_port);
}


static struct ns_connection *accept_conn(struct ns_server *server) {
  struct ns_connection *c = NULL;
  union socket_address sa;
  socklen_t len = sizeof(sa);
  sock_t sock = INVALID_SOCKET;

  // NOTE(lsm): on Windows, sock is always > FD_SETSIZE
  if ((sock = accept(server->listening_sock, &sa.sa, &len)) == INVALID_SOCKET) {
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
    ns_set_non_blocking_mode(sock);
    c->server = server;
    c->sock = sock;
    c->flags |= NSF_ACCEPTED;

    ns_add_conn(server, c);
    ns_call(c, NS_ACCEPT, &sa);
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

void ns_sock_to_str(sock_t sock, char *buf, size_t len, int flags) {
  union socket_address sa;
  socklen_t slen = sizeof(sa);

  if (buf != NULL && len > 0) {
    buf[0] = '\0';
    memset(&sa, 0, sizeof(sa));
    if (flags & 4) {
      getpeername(sock, &sa.sa, &slen);
    } else {
      getsockname(sock, &sa.sa, &slen);
    }
    if (flags & 1) {
#if defined(NS_ENABLE_IPV6)
      inet_ntop(sa.sa.sa_family, sa.sa.sa_family == AF_INET ?
                (void *) &sa.sin.sin_addr :
                (void *) &sa.sin6.sin6_addr, buf, len);
#elif defined(_WIN32)
      // Only Windoze Vista (and newer) have inet_ntop()
      strncpy(buf, inet_ntoa(sa.sin.sin_addr), len);
#else
      inet_ntop(sa.sa.sa_family, (void *) &sa.sin.sin_addr, buf, len);
#endif
    }
    if (flags & 2) {
      snprintf(buf + strlen(buf), len - (strlen(buf) + 1), "%s%d",
               flags & 1 ? ":" : "", (int) ntohs(sa.sin.sin_port));
    }
  }
}

int ns_hexdump(const void *buf, int len, char *dst, int dst_len) {
  const unsigned char *p = (const unsigned char *) buf;
  char ascii[17] = "";
  int i, idx, n = 0;

  for (i = 0; i < len; i++) {
    idx = i % 16;
    if (idx == 0) {
      if (i > 0) n += snprintf(dst + n, dst_len - n, "  %s\n", ascii);
      n += snprintf(dst + n, dst_len - n, "%04x ", i);
    }
    n += snprintf(dst + n, dst_len - n, " %02x", p[i]);
    ascii[idx] = p[i] < 0x20 || p[i] > 0x7e ? '.' : p[i];
    ascii[idx + 1] = '\0';
  }

  while (i++ % 16) n += snprintf(dst + n, dst_len - n, "%s", "   ");
  n += snprintf(dst + n, dst_len - n, "  %s\n\n", ascii);

  return n;
}

static void ns_read_from_socket(struct ns_connection *conn) {
  char buf[2048];
  int n = 0;

  if (conn->flags & NSF_CONNECTING) {
    int ok = 1, ret;
    socklen_t len = sizeof(ok);

    ret = getsockopt(conn->sock, SOL_SOCKET, SO_ERROR, (char *) &ok, &len);
    (void) ret;
#ifdef NS_ENABLE_SSL
    if (ret == 0 && ok == 0 && conn->ssl != NULL) {
      int res = SSL_connect(conn->ssl);
      int ssl_err = SSL_get_error(conn->ssl, res);
      DBG(("%p %d wres %d %d", conn, conn->flags, res, ssl_err));
      if (ssl_err == SSL_ERROR_WANT_READ) conn->flags |= NSF_WANT_READ;
      if (ssl_err == SSL_ERROR_WANT_WRITE) conn->flags |= NSF_WANT_WRITE;
      if (res == 1) {
        conn->flags |= NSF_SSL_HANDSHAKE_DONE;
      } else if (ssl_err == SSL_ERROR_WANT_READ ||
                 ssl_err == SSL_ERROR_WANT_WRITE) {
        return; // Call us again
      } else {
        ok = 1;
      }
    }
#endif
    conn->flags &= ~NSF_CONNECTING;
    DBG(("%p ok=%d", conn, ok));
    if (ok != 0) {
      conn->flags |= NSF_CLOSE_IMMEDIATELY;
    }
    ns_call(conn, NS_CONNECT, &ok);
    return;
  }

#ifdef NS_ENABLE_SSL
  if (conn->ssl != NULL) {
    if (conn->flags & NSF_SSL_HANDSHAKE_DONE) {
      n = SSL_read(conn->ssl, buf, sizeof(buf));
    } else {
      int res = SSL_accept(conn->ssl);
      int ssl_err = SSL_get_error(conn->ssl, res);
      DBG(("%p %d rres %d %d", conn, conn->flags, res, ssl_err));
      if (ssl_err == SSL_ERROR_WANT_READ) conn->flags |= NSF_WANT_READ;
      if (ssl_err == SSL_ERROR_WANT_WRITE) conn->flags |= NSF_WANT_WRITE;
      if (res == 1) {
        conn->flags |= NSF_SSL_HANDSHAKE_DONE;
      } else if (ssl_err == SSL_ERROR_WANT_READ ||
                 ssl_err == SSL_ERROR_WANT_WRITE) {
        return; // Call us again
      } else {
        conn->flags |= NSF_CLOSE_IMMEDIATELY;
      }
      return;
    }
  } else
#endif
  {
    n = recv(conn->sock, buf, sizeof(buf), 0);
  }

  DBG(("%p %d <- %d bytes", conn, conn->flags, n));

  if (ns_is_error(n)) {
    conn->flags |= NSF_CLOSE_IMMEDIATELY;
  } else if (n > 0) {
    iobuf_append(&conn->recv_iobuf, buf, n);
    ns_call(conn, NS_RECV, &n);
  }
}

static void ns_write_to_socket(struct ns_connection *conn) {
  struct iobuf *io = &conn->send_iobuf;
  int n = 0;

#ifdef NS_ENABLE_SSL
  if (conn->ssl != NULL) {
    n = SSL_write(conn->ssl, io->buf, io->len);
    if (n < 0) {
      int ssl_err = SSL_get_error(conn->ssl, n);
      DBG(("%p %d %d", conn, n, ssl_err));
      if (ssl_err == 2 || ssl_err == 3) {
        return; // Call us again
      } else {
        conn->flags |= NSF_CLOSE_IMMEDIATELY;
      }
    }
  } else
#endif
  { n = send(conn->sock, io->buf, io->len, 0); }

  DBG(("%p %d -> %d bytes", conn, conn->flags, n));

  ns_call(conn, NS_SEND, &n);
  if (ns_is_error(n)) {
    conn->flags |= NSF_CLOSE_IMMEDIATELY;
  } else if (n > 0) {
    iobuf_remove(io, n);
  }

  if (io->len == 0 && (conn->flags & NSF_FINISHED_SENDING_DATA)) {
    conn->flags |= NSF_CLOSE_IMMEDIATELY;
  }
}

int ns_send(struct ns_connection *conn, const void *buf, int len) {
  return iobuf_append(&conn->send_iobuf, buf, len);
}

static void ns_add_to_set(sock_t sock, fd_set *set, sock_t *max_fd) {
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
  ns_add_to_set(server->listening_sock, &read_set, &max_fd);
  ns_add_to_set(server->ctl[1], &read_set, &max_fd);

  for (conn = server->active_connections; conn != NULL; conn = tmp_conn) {
    tmp_conn = conn->next;
    ns_call(conn, NS_POLL, &current_time);
    if (!(conn->flags & NSF_WANT_WRITE)) {
      //DBG(("%p read_set", conn));
      ns_add_to_set(conn->sock, &read_set, &max_fd);
    }
    if (((conn->flags & NSF_CONNECTING) && !(conn->flags & NSF_WANT_READ)) ||
        (conn->send_iobuf.len > 0 && !(conn->flags & NSF_CONNECTING) &&
         !(conn->flags & NSF_BUFFER_BUT_DONT_SEND))) {
      //DBG(("%p write_set", conn));
      ns_add_to_set(conn->sock, &write_set, &max_fd);
    }
    if (conn->flags & NSF_CLOSE_IMMEDIATELY) {
      ns_close_conn(conn);
    }
  }

  tv.tv_sec = milli / 1000;
  tv.tv_usec = (milli % 1000) * 1000;

  if (select((int) max_fd + 1, &read_set, &write_set, NULL, &tv) > 0) {
    // select() might have been waiting for a long time, reset current_time
    // now to prevent last_io_time being set to the past.
    current_time = time(NULL);
    
    // Accept new connections
    if (server->listening_sock != INVALID_SOCKET &&
        FD_ISSET(server->listening_sock, &read_set)) {
      // We're not looping here, and accepting just one connection at
      // a time. The reason is that eCos does not respect non-blocking
      // flag on a listening socket and hangs in a loop.
      if ((conn = accept_conn(server)) != NULL) {
        conn->last_io_time = current_time;
      }
    }

    // Read wakeup messages
    if (server->ctl[1] != INVALID_SOCKET &&
        FD_ISSET(server->ctl[1], &read_set)) {
      struct ctl_msg ctl_msg;
      int len = recv(server->ctl[1], (void *) &ctl_msg, sizeof(ctl_msg), 0);
      send(server->ctl[1], ctl_msg.message, 1, 0);
      if (len >= (int) sizeof(ctl_msg.callback) && ctl_msg.callback != NULL) {
        ns_iterate(server, ctl_msg.callback, ctl_msg.message);
      }
    }

    for (conn = server->active_connections; conn != NULL; conn = tmp_conn) {
      tmp_conn = conn->next;
      if (FD_ISSET(conn->sock, &read_set)) {
        conn->last_io_time = current_time;
        ns_read_from_socket(conn);
      }
      if (FD_ISSET(conn->sock, &write_set)) {
        if (conn->flags & NSF_CONNECTING) {
          ns_read_from_socket(conn);
        } else if (!(conn->flags & NSF_BUFFER_BUT_DONT_SEND)) {
          conn->last_io_time = current_time;
          ns_write_to_socket(conn);
        }
      }
    }
  }

  for (conn = server->active_connections; conn != NULL; conn = tmp_conn) {
    tmp_conn = conn->next;
    num_active_connections++;
    if (conn->flags & NSF_CLOSE_IMMEDIATELY) {
      ns_close_conn(conn);
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

  (void) use_ssl;

  if (host == NULL || (he = gethostbyname(host)) == NULL ||
      (sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
    DBG(("gethostbyname(%s) failed: %s", host, strerror(errno)));
    return NULL;
  }

  sin.sin_family = AF_INET;
  sin.sin_port = htons((uint16_t) port);
  sin.sin_addr = * (struct in_addr *) he->h_addr_list[0];
  ns_set_non_blocking_mode(sock);

  connect_ret_val = connect(sock, (struct sockaddr *) &sin, sizeof(sin));
  if (ns_is_error(connect_ret_val)) {
    closesocket(sock);
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

  ns_add_conn(server, conn);
  DBG(("%p %s:%d %d %p", conn, host, port, conn->sock, conn->ssl));

  return conn;
}

struct ns_connection *ns_add_sock(struct ns_server *s, sock_t sock, void *p) {
  struct ns_connection *conn;
  if ((conn = (struct ns_connection *) NS_MALLOC(sizeof(*conn))) != NULL) {
    memset(conn, 0, sizeof(*conn));
    ns_set_non_blocking_mode(sock);
    conn->sock = sock;
    conn->connection_data = p;
    conn->server = s;
    conn->last_io_time = time(NULL);
    ns_add_conn(s, conn);
    DBG(("%p %d", conn, sock));
  }
  return conn;
}

struct ns_connection *ns_next(struct ns_server *s, struct ns_connection *conn) {
  return conn == NULL ? s->active_connections : conn->next;
}

void ns_iterate(struct ns_server *server, ns_callback_t cb, void *param) {
  struct ns_connection *conn, *tmp_conn;

  for (conn = server->active_connections; conn != NULL; conn = tmp_conn) {
    tmp_conn = conn->next;
    cb(conn, NS_POLL, param);
  }
}

void ns_server_wakeup_ex(struct ns_server *server, ns_callback_t cb,
                         void *data, size_t len) {
  struct ctl_msg ctl_msg;
  if (server->ctl[0] != INVALID_SOCKET && data != NULL &&
      len < sizeof(ctl_msg.message)) {
    ctl_msg.callback = cb;
    memcpy(ctl_msg.message, data, len);
    send(server->ctl[0], (void *) &ctl_msg,
         offsetof(struct ctl_msg, message) + len, 0);
    recv(server->ctl[0], (void *) &len, 1, 0);
  }
}

void ns_server_wakeup(struct ns_server *server) {
  ns_server_wakeup_ex(server, NULL, (void *) "", 0);
}

void ns_server_init(struct ns_server *s, void *server_data, ns_callback_t cb) {
  memset(s, 0, sizeof(*s));
  s->listening_sock = s->ctl[0] = s->ctl[1] = INVALID_SOCKET;
  s->server_data = server_data;
  s->callback = cb;

#ifdef _WIN32
  { WSADATA data; WSAStartup(MAKEWORD(2, 2), &data); }
#else
  // Ignore SIGPIPE signal, so if client cancels the request, it
  // won't kill the whole process.
  signal(SIGPIPE, SIG_IGN);
#endif

#ifndef NS_DISABLE_SOCKETPAIR
  do {
    ns_socketpair2(s->ctl, SOCK_DGRAM);
  } while (s->ctl[0] == INVALID_SOCKET);
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

  if (s->listening_sock != INVALID_SOCKET) closesocket(s->listening_sock);
  if (s->ctl[0] != INVALID_SOCKET) closesocket(s->ctl[0]);
  if (s->ctl[1] != INVALID_SOCKET) closesocket(s->ctl[1]);
  s->listening_sock = s->ctl[0] = s->ctl[1] = INVALID_SOCKET;

  for (conn = s->active_connections; conn != NULL; conn = tmp_conn) {
    tmp_conn = conn->next;
    ns_close_conn(conn);
  }

#ifdef NS_ENABLE_SSL
  if (s->ssl_ctx != NULL) SSL_CTX_free(s->ssl_ctx);
  if (s->client_ssl_ctx != NULL) SSL_CTX_free(s->client_ssl_ctx);
  s->ssl_ctx = s->client_ssl_ctx = NULL;
#endif
}
