#include "fossa.h"
#ifdef NS_MODULE_LINES
#line 1 "modules/internal.h"
/**/
#endif
/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#ifndef NS_INTERNAL_HEADER_INCLUDED
#define NS_INTERNAL_HEADER_INCLUDED

#ifndef NS_MALLOC
#define NS_MALLOC malloc
#endif

#ifndef NS_CALLOC
#define NS_CALLOC calloc
#endif

#ifndef NS_REALLOC
#define NS_REALLOC realloc
#endif

#ifndef NS_FREE
#define NS_FREE free
#endif

#define NS_SET_PTRPTR(_ptr, _v) do { if (_ptr) *(_ptr) = _v; } while (0)

#ifndef NS_INTERNAL
#define NS_INTERNAL static
#endif

/* internals that need to be accessible in unit tests */
NS_INTERNAL struct ns_connection *ns_finish_connect(struct ns_connection *nc,
                                                    int proto,
                                                    union socket_address *sa,
                                                    struct ns_add_sock_opts);

NS_INTERNAL int ns_parse_address(const char *str, union socket_address *sa,
                                 int *proto, char *host, size_t host_len);


#endif  /* NS_INTERNAL_HEADER_INCLUDED */
#ifdef NS_MODULE_LINES
#line 1 "modules/iobuf.c"
/**/
#endif
/* Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 *
 * This software is dual-licensed: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. For the terms of this
 * license, see <http://www.gnu.org/licenses/>.
 *
 * You are free to use this software under the terms of the GNU General
 * Public License, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * Alternatively, you can license this software under a commercial
 * license, as set out in <http://cesanta.com/>.
 */

/*
 * == IO Buffers
 */


/* Initializes an IO buffer. */
void iobuf_init(struct iobuf *iobuf, size_t initial_size) {
  iobuf->len = iobuf->size = 0;
  iobuf->buf = NULL;
  iobuf_resize(iobuf, initial_size);
}

/* Frees the space allocated for the iobuffer and resets the iobuf structure. */
void iobuf_free(struct iobuf *iobuf) {
  if (iobuf != NULL) {
    NS_FREE(iobuf->buf);
    iobuf_init(iobuf, 0);
  }
}

/*
 * Appends data to the IO buffer.
 *
 * It returns the amount of bytes appended.
 */
size_t iobuf_append(struct iobuf *io, const void *buf, size_t len) {
  return iobuf_insert(io, io->len, buf, len);
}

/*
 * Inserts data at a specified offset in the IO buffer.
 *
 * Existing data will be shifted forwards and the buffer will
 * be grown if necessary.
 * It returns the amount of bytes inserted.
 */
size_t iobuf_insert(struct iobuf *io, size_t off, const void *buf, size_t len) {
  char *p = NULL;

  assert(io != NULL);
  assert(io->len <= io->size);
  assert(off <= io->len);

  /* check overflow */
  if (~(size_t)0 - (size_t)io->buf < len)
    return 0;

  if (io->len + len <= io->size) {
    memmove(io->buf + off + len, io->buf + off, io->len - off);
    memcpy(io->buf + off, buf, len);
    io->len += len;
  } else if ((p = (char *) NS_REALLOC(io->buf, io->len + len)) != NULL) {
    io->buf = p;
    memmove(io->buf + off + len, io->buf + off, io->len - off);
    memcpy(io->buf + off, buf, len);
    io->len += len;
    io->size = io->len;
  } else {
    len = 0;
  }

  return len;
}

/* Removes `n` bytes from the beginning of the buffer. */
void iobuf_remove(struct iobuf *io, size_t n) {
  if (n > 0 && n <= io->len) {
    memmove(io->buf, io->buf + n, io->len - n);
    io->len -= n;
  }
}

/*
 * Resize an IO buffer.
 *
 * If `new_size` is smaller than buffer's `len`, the
 * resize is not performed.
 */
void iobuf_resize(struct iobuf *io, size_t new_size) {
  char *p;
  if ((new_size > io->size || (new_size < io->size && new_size >= io->len)) &&
      (p = (char *) NS_REALLOC(io->buf, new_size)) != NULL) {
    io->size = new_size;
    io->buf = p;
  }
}
#ifdef NS_MODULE_LINES
#line 1 "modules/net.c"
/**/
#endif
/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 *
 * This software is dual-licensed: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. For the terms of this
 * license, see <http://www.gnu.org/licenses/>.
 *
 * You are free to use this software under the terms of the GNU General
 * Public License, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * Alternatively, you can license this software under a commercial
 * license, as set out in <http://cesanta.com/>.
 */

/*
 * == Core API: TCP/UDP/SSL
 *
 * CAUTION: Fossa manager is single threaded. It does not protect
 * it's data structures by mutexes, therefore all functions that are dealing
 * with particular event manager should be called from the same thread,
 * with exception of `mg_broadcast()` function. It is fine to have different
 * event managers handled by different threads.
 */


#define NS_CTL_MSG_MESSAGE_SIZE     8192
#define NS_READ_BUFFER_SIZE         2048
#define NS_UDP_RECEIVE_BUFFER_SIZE  2000
#define NS_VPRINTF_BUFFER_SIZE      500
#define NS_MAX_HOST_LEN             200

struct ctl_msg {
  ns_event_handler_t callback;
  char message[NS_CTL_MSG_MESSAGE_SIZE];
};

static void ns_add_conn(struct ns_mgr *mgr, struct ns_connection *c) {
  c->next = mgr->active_connections;
  mgr->active_connections = c;
  c->prev = NULL;
  if (c->next != NULL) c->next->prev = c;
}

static void ns_remove_conn(struct ns_connection *conn) {
  if (conn->prev == NULL) conn->mgr->active_connections = conn->next;
  if (conn->prev) conn->prev->next = conn->next;
  if (conn->next) conn->next->prev = conn->prev;
}

static void ns_call(struct ns_connection *nc, int ev, void *ev_data) {
  ns_event_handler_t ev_handler;

  /* LCOV_EXCL_START */
  if (nc->mgr->hexdump_file != NULL && ev != NS_POLL) {
    int len = (ev == NS_RECV || ev == NS_SEND) ? * (int *) ev_data : 0;
    ns_hexdump_connection(nc, nc->mgr->hexdump_file, len, ev);
  }
  /* LCOV_EXCL_STOP */

  /*
   * If protocol handler is specified, call it. Otherwise, call user-specified
   * event handler.
   */
  ev_handler = nc->proto_handler ?  nc->proto_handler : nc->handler;
  if (ev_handler != NULL) {
    ev_handler(nc, ev, ev_data);
  }
}

static size_t ns_out(struct ns_connection *nc, const void *buf, size_t len) {
  if (nc->flags & NSF_UDP) {
    int n = sendto(nc->sock, buf, len, 0, &nc->sa.sa, sizeof(nc->sa.sin));
    DBG(("%p %d %d %d %s:%hu", nc, nc->sock, n, errno,
         inet_ntoa(nc->sa.sin.sin_addr), ntohs(nc->sa.sin.sin_port)));
    return n < 0 ? 0 : n;
  } else {
    return iobuf_append(&nc->send_iobuf, buf, len);
  }
}

static void ns_destroy_conn(struct ns_connection *conn) {
  if (conn->sock != INVALID_SOCKET) {
    closesocket(conn->sock);
    /*
     * avoid users accidentally double close a socket
     * because it can lead to difficult to debug situations.
     * It would happen only if reusing a destroyed ns_connection
     * but it's not always possible to run the code through an
     * address sanitizer.
     */
    conn->sock = INVALID_SOCKET;
  }
  iobuf_free(&conn->recv_iobuf);
  iobuf_free(&conn->send_iobuf);
#ifdef NS_ENABLE_SSL
  if (conn->ssl != NULL) {
    SSL_free(conn->ssl);
  }
  if (conn->ssl_ctx != NULL) {
    SSL_CTX_free(conn->ssl_ctx);
  }
#endif
  NS_FREE(conn);
}

static void ns_close_conn(struct ns_connection *conn) {
  DBG(("%p %lu", conn, conn->flags));
  ns_call(conn, NS_CLOSE, NULL);
  ns_remove_conn(conn);
  ns_destroy_conn(conn);
}

/* Initializes Fossa manager. */
void ns_mgr_init(struct ns_mgr *s, void *user_data) {
  memset(s, 0, sizeof(*s));
  s->ctl[0] = s->ctl[1] = INVALID_SOCKET;
  s->user_data = user_data;

#ifdef _WIN32
  {
    WSADATA data;
    WSAStartup(MAKEWORD(2, 2), &data);
  }
#else
  /* Ignore SIGPIPE signal, so if client cancels the request, it
   * won't kill the whole process. */
  signal(SIGPIPE, SIG_IGN);
#endif

#ifndef NS_DISABLE_SOCKETPAIR
  do {
    ns_socketpair(s->ctl, SOCK_DGRAM);
  } while (s->ctl[0] == INVALID_SOCKET);
#endif

#ifdef NS_ENABLE_SSL
  {
    static int init_done;
    if (!init_done) {
      SSL_library_init();
      init_done++;
    }
  }
#endif
}

/*
 * De-initializes fossa manager.
 *
 * Closes and deallocates all active connections.
 */
void ns_mgr_free(struct ns_mgr *s) {
  struct ns_connection *conn, *tmp_conn;

  DBG(("%p", s));
  if (s == NULL) return;
  /* Do one last poll, see https://github.com/cesanta/mongoose/issues/286 */
  ns_mgr_poll(s, 0);

  if (s->ctl[0] != INVALID_SOCKET) closesocket(s->ctl[0]);
  if (s->ctl[1] != INVALID_SOCKET) closesocket(s->ctl[1]);
  s->ctl[0] = s->ctl[1] = INVALID_SOCKET;

  for (conn = s->active_connections; conn != NULL; conn = tmp_conn) {
    tmp_conn = conn->next;
    ns_close_conn(conn);
  }
}

/*
 * Send `printf`-style formatted data to the connection.
 *
 * See `ns_send` for more details on send semantics.
 */
int ns_vprintf(struct ns_connection *nc, const char *fmt, va_list ap) {
  char mem[NS_VPRINTF_BUFFER_SIZE], *buf = mem;
  int len;

  if ((len = ns_avprintf(&buf, sizeof(mem), fmt, ap)) > 0) {
    ns_out(nc, buf, len);
  }
  if (buf != mem && buf != NULL) {
    NS_FREE(buf);  /* LCOV_EXCL_LINE */
  }                /* LCOV_EXCL_LINE */

  return len;
}

/*
 * Send `printf`-style formatted data to the connection.
 *
 * See `ns_send` for more details on send semantics.
 */
int ns_printf(struct ns_connection *conn, const char *fmt, ...) {
  int len;
  va_list ap;
  va_start(ap, fmt);
  len = ns_vprintf(conn, fmt, ap);
  va_end(ap);
  return len;
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
/*
 * Create a socket pair.
 * `proto` can be either `SOCK_STREAM` or `SOCK_DGRAM`.
 * Return 0 on failure, 1 on success.
 */
int ns_socketpair(sock_t sp[2], int sock_type) {
  union socket_address sa;
  sock_t sock;
  socklen_t len = sizeof(sa.sin);
  int ret = 0;

  sock = sp[0] = sp[1] = INVALID_SOCKET;

  (void) memset(&sa, 0, sizeof(sa));
  sa.sin.sin_family = AF_INET;
  sa.sin.sin_port = htons(0);
  sa.sin.sin_addr.s_addr = htonl(0x7f000001);

  if ((sock = socket(AF_INET, sock_type, 0)) == INVALID_SOCKET) {
  } else if (bind(sock, &sa.sa, len) != 0) {
  } else if (sock_type == SOCK_STREAM && listen(sock, 1) != 0) {
  } else if (getsockname(sock, &sa.sa, &len) != 0) {
  } else if ((sp[0] = socket(AF_INET, sock_type, 0)) == INVALID_SOCKET) {
  } else if (connect(sp[0], &sa.sa, len) != 0) {
  } else if (sock_type == SOCK_DGRAM &&
             (getsockname(sp[0], &sa.sa, &len) != 0 ||
              connect(sock, &sa.sa, len) != 0)) {
  } else if ((sp[1] = (sock_type == SOCK_DGRAM ? sock :
                       accept(sock, &sa.sa, &len))) == INVALID_SOCKET) {
  } else {
    ns_set_close_on_exec(sp[0]);
    ns_set_close_on_exec(sp[1]);
    if (sock_type == SOCK_STREAM) closesocket(sock);
    ret = 1;
  }

  if (!ret) {
    if (sp[0] != INVALID_SOCKET) closesocket(sp[0]);
    if (sp[1] != INVALID_SOCKET) closesocket(sp[1]);
    if (sock  != INVALID_SOCKET) closesocket(sock);
    sock = sp[0] = sp[1] = INVALID_SOCKET;
  }

  return ret;
}
#endif  /* NS_DISABLE_SOCKETPAIR */

/* TODO(lsm): use non-blocking resolver */
static int ns_resolve2(const char *host, struct in_addr *ina) {
  struct hostent *he;
  if ((he = gethostbyname(host)) == NULL) {
    DBG(("gethostbyname(%s) failed: %s", host, strerror(errno)));
  } else {
    memcpy(ina, he->h_addr_list[0], sizeof(*ina));
    return 1;
  }
  return 0;
}

/*
 * Converts domain name into IP address.
 *
 * This is a blocking call. Returns 1 on success, 0 on failure.
 */
int ns_resolve(const char *host, char *buf, size_t n) {
  struct in_addr ad;
  return ns_resolve2(host, &ad) ? snprintf(buf, n, "%s", inet_ntoa(ad)) : 0;
}

NS_INTERNAL struct ns_connection *ns_create_connection(
    struct ns_mgr *mgr, ns_event_handler_t callback,
    struct ns_add_sock_opts opts) {
  struct ns_connection *conn;

  if ((conn = (struct ns_connection *) NS_MALLOC(sizeof(*conn))) != NULL) {
    memset(conn, 0, sizeof(*conn));
    conn->sock = INVALID_SOCKET;
    conn->handler = callback;
    conn->mgr = mgr;
    conn->last_io_time = time(NULL);
    conn->flags = opts.flags;
    conn->user_data = opts.user_data;
  }

  return conn;
}

/* Associate a socket to a connection and and add to the manager. */
NS_INTERNAL void ns_set_sock(struct ns_connection *nc, sock_t sock) {
  ns_set_non_blocking_mode(sock);
  ns_set_close_on_exec(sock);
  nc->sock = sock;
  ns_add_conn(nc->mgr, nc);
  DBG(("%p %d", nc, sock));
}

/*
 * Address format: [PROTO://][HOST]:PORT
 *
 * HOST could be IPv4/IPv6 address or a host name.
 * `host` is a destination buffer to hold parsed HOST part. Shoud be at least
 * NS_MAX_HOST_LEN bytes long.
 * `proto` is a returned socket type, either SOCK_STREAM or SOCK_DGRAM
 *
 * Return:
 *   -1   on parse error
 *    0   if HOST needs DNS lookup
 *   >0   length of the address string
 */
NS_INTERNAL int ns_parse_address(const char *str, union socket_address *sa,
                                 int *proto, char *host, size_t host_len) {
  unsigned int a, b, c, d, port = 0;
  int len = 0;
#ifdef NS_ENABLE_IPV6
  char buf[100];
#endif

  /*
   * MacOS needs that. If we do not zero it, subsequent bind() will fail.
   * Also, all-zeroes in the socket address means binding to all addresses
   * for both IPv4 and IPv6 (INADDR_ANY and IN6ADDR_ANY_INIT).
   */
  memset(sa, 0, sizeof(*sa));
  sa->sin.sin_family = AF_INET;

  *proto = SOCK_STREAM;

  if (strncmp(str, "udp://", 6) == 0) {
    str += 6;
    *proto = SOCK_DGRAM;
  } else if (strncmp(str, "tcp://", 6) == 0) {
    str += 6;
  }

  if (sscanf(str, "%u.%u.%u.%u:%u%n", &a, &b, &c, &d, &port, &len) == 5) {
    /* Bind to a specific IPv4 address, e.g. 192.168.1.5:8080 */
    sa->sin.sin_addr.s_addr = htonl((a << 24) | (b << 16) | (c << 8) | d);
    sa->sin.sin_port = htons((uint16_t) port);
#ifdef NS_ENABLE_IPV6
  } else if (sscanf(str, "[%99[^]]]:%u%n", buf, &port, &len) == 2 &&
             inet_pton(AF_INET6, buf, &sa->sin6.sin6_addr)) {
    /* IPv6 address, e.g. [3ffe:2a00:100:7031::1]:8080 */
    sa->sin6.sin6_family = AF_INET6;
    sa->sin.sin_port = htons((uint16_t) port);
#endif
  } else if (strlen(str) < host_len &&
             sscanf(str, "%[^ :]:%u%n", host, &port, &len) == 2) {
    sa->sin.sin_port = htons((uint16_t) port);
    if (ns_resolve_from_hosts_file(host, sa) != 0) {
      return 0;
    }
  } else if (sscanf(str, ":%u%n", &port, &len) == 1 ||
             sscanf(str, "%u%n", &port, &len) == 1) {
    /* If only port is specified, bind to IPv4, INADDR_ANY */
    sa->sin.sin_port = htons((uint16_t) port);
  } else {
    return -1;
  }

  return port < 0xffffUL && str[len] == '\0' ? len : -1;
}

/* 'sa' must be an initialized address to bind to */
static sock_t ns_open_listening_socket(union socket_address *sa, int proto) {
  socklen_t sa_len = (sa->sa.sa_family == AF_INET) ?
                     sizeof(sa->sin) : sizeof(sa->sin6);
  sock_t sock = INVALID_SOCKET;
  int on = 1;

  if ((sock = socket(sa->sa.sa_family, proto, 0)) != INVALID_SOCKET &&

#if defined(_WIN32) && defined(SO_EXCLUSIVEADDRUSE)
      /* "Using SO_REUSEADDR and SO_EXCLUSIVEADDRUSE" http://goo.gl/RmrFTm */
      !setsockopt(sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                  (void *) &on, sizeof(on)) &&
#endif

#if 1 || !defined(_WIN32) || defined(SO_EXCLUSIVEADDRUSE)
      /*
       * SO_RESUSEADDR is not enabled on Windows because the semantics of
       * SO_REUSEADDR on UNIX and Windows is different. On Windows,
       * SO_REUSEADDR allows to bind a socket to a port without error even if
       * the port is already open by another program. This is not the behavior
       * SO_REUSEADDR was designed for, and leads to hard-to-track failure
       * scenarios. Therefore, SO_REUSEADDR was disabled on Windows unless
       * SO_EXCLUSIVEADDRUSE is supported and set on a socket.
       */
      !setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on)) &&
#endif

      !bind(sock, &sa->sa, sa_len) &&
      (proto == SOCK_DGRAM || listen(sock, SOMAXCONN) == 0)) {
    ns_set_non_blocking_mode(sock);
    /* In case port was set to 0, get the real port number */
    (void) getsockname(sock, &sa->sa, &sa_len);
  } else if (sock != INVALID_SOCKET) {
    closesocket(sock);
    sock = INVALID_SOCKET;
  }

  return sock;
}

#ifdef NS_ENABLE_SSL
/* Certificate generation script is at */
/* https://github.com/cesanta/fossa/blob/master/scripts/gen_certs.sh */

static int ns_use_ca_cert(SSL_CTX *ctx, const char *cert) {
  if (ctx == NULL) {
    return -1;
  } else if (cert == NULL || cert[0] == '\0') {
    return 0;
  }
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
  return SSL_CTX_load_verify_locations(ctx, cert, NULL) == 1 ? 0 : -2;
}

static int ns_use_cert(SSL_CTX *ctx, const char *pem_file) {
  if (ctx == NULL) {
    return -1;
  } else if (pem_file == NULL || pem_file[0] == '\0') {
    return 0;
  } else if (SSL_CTX_use_certificate_file(ctx, pem_file, 1) == 0 ||
             SSL_CTX_use_PrivateKey_file(ctx, pem_file, 1) == 0) {
    return -2;
  } else {
    SSL_CTX_set_mode(ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_use_certificate_chain_file(ctx, pem_file);
    return 0;
  }
}

const char *ns_set_ssl(struct ns_connection *nc, const char *cert,
                       const char *ca_cert) {
  const char *result = NULL;

  if ((nc->flags & NSF_LISTENING) &&
      (nc->ssl_ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
    result = "SSL_CTX_new() failed";
  } else if (!(nc->flags & NSF_LISTENING) &&
             (nc->ssl_ctx = SSL_CTX_new(SSLv23_client_method())) == NULL) {
    result = "SSL_CTX_new() failed";
  } else if (ns_use_cert(nc->ssl_ctx, cert) != 0) {
    result = "Invalid ssl cert";
  } else if (ns_use_ca_cert(nc->ssl_ctx, ca_cert) != 0) {
    result = "Invalid CA cert";
  } else if (!(nc->flags & NSF_LISTENING) &&
             (nc->ssl = SSL_new(nc->ssl_ctx)) == NULL) {
    result = "SSL_new() failed";
  } else if (!(nc->flags & NSF_LISTENING)) {
    SSL_set_fd(nc->ssl, nc->sock);
  }
  return result;
}

static int ns_ssl_err(struct ns_connection *conn, int res) {
  int ssl_err = SSL_get_error(conn->ssl, res);
  if (ssl_err == SSL_ERROR_WANT_READ) conn->flags |= NSF_WANT_READ;
  if (ssl_err == SSL_ERROR_WANT_WRITE) conn->flags |= NSF_WANT_WRITE;
  return ssl_err;
}
#endif  /* NS_ENABLE_SSL */

static struct ns_connection *accept_conn(struct ns_connection *ls) {
  struct ns_connection *c = NULL;
  union socket_address sa;
  socklen_t len = sizeof(sa);
  sock_t sock = INVALID_SOCKET;

  /* NOTE(lsm): on Windows, sock is always > FD_SETSIZE */
  if ((sock = accept(ls->sock, &sa.sa, &len)) == INVALID_SOCKET) {
  } else if ((c = ns_add_sock(ls->mgr, sock, ls->handler)) == NULL) {
    closesocket(sock);
#ifdef NS_ENABLE_SSL
  } else if (ls->ssl_ctx != NULL &&
             ((c->ssl = SSL_new(ls->ssl_ctx)) == NULL ||
              SSL_set_fd(c->ssl, sock) != 1)) {
    DBG(("SSL error"));
    ns_close_conn(c);
    c = NULL;
#endif
  } else {
    c->listener = ls;
    c->proto_data = ls->proto_data;
    c->proto_handler = ls->proto_handler;
    c->user_data = ls->user_data;
    ns_call(c, NS_ACCEPT, &sa);
    DBG(("%p %d %p %p", c, c->sock, c->ssl_ctx, c->ssl));
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

static void ns_read_from_socket(struct ns_connection *conn) {
  char buf[NS_READ_BUFFER_SIZE];
  int n = 0;

  if (conn->flags & NSF_CONNECTING) {
    int ok = 1, ret;
    socklen_t len = sizeof(ok);

    ret = getsockopt(conn->sock, SOL_SOCKET, SO_ERROR, (char *) &ok, &len);
#ifdef NS_ENABLE_SSL
    if (ret == 0 && ok == 0 && conn->ssl != NULL) {
      int res = SSL_connect(conn->ssl);
      int ssl_err = ns_ssl_err(conn, res);
      if (res == 1) {
        conn->flags |= NSF_SSL_HANDSHAKE_DONE;
      } else if (ssl_err == SSL_ERROR_WANT_READ ||
                 ssl_err == SSL_ERROR_WANT_WRITE) {
        return; /* Call us again */
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
      /* SSL library may have more bytes ready to read then we ask to read.
       * Therefore, read in a loop until we read everything. Without the loop,
       * we skip to the next select() cycle which can just timeout. */
      while ((n = SSL_read(conn->ssl, buf, sizeof(buf))) > 0) {
        DBG(("%p %lu <- %d bytes (SSL)", conn, conn->flags, n));
        iobuf_append(&conn->recv_iobuf, buf, n);
        ns_call(conn, NS_RECV, &n);
      }
      ns_ssl_err(conn, n);
    } else {
      int res = SSL_accept(conn->ssl);
      int ssl_err = ns_ssl_err(conn, res);
      if (res == 1) {
        conn->flags |= NSF_SSL_HANDSHAKE_DONE;
      } else if (ssl_err == SSL_ERROR_WANT_READ ||
                 ssl_err == SSL_ERROR_WANT_WRITE) {
        return; /* Call us again */
      } else {
        conn->flags |= NSF_CLOSE_IMMEDIATELY;
      }
      return;
    }
  } else
#endif
  {
    while ((n = (int) recv(conn->sock, buf, sizeof(buf), 0)) > 0) {
      DBG(("%p %lu <- %d bytes (PLAIN)", conn, conn->flags, n));
      iobuf_append(&conn->recv_iobuf, buf, n);
      ns_call(conn, NS_RECV, &n);
    }
  }

  if (ns_is_error(n)) {
    conn->flags |= NSF_CLOSE_IMMEDIATELY;
  }
}

static void ns_write_to_socket(struct ns_connection *conn) {
  struct iobuf *io = &conn->send_iobuf;
  int n = 0;

#ifdef NS_ENABLE_SSL
  if (conn->ssl != NULL) {
    n = SSL_write(conn->ssl, io->buf, io->len);
    if (n <= 0) {
      int ssl_err = ns_ssl_err(conn, n);
      if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
        return; /* Call us again */
      } else {
        conn->flags |= NSF_CLOSE_IMMEDIATELY;
      }
    }
  } else
#endif
  { n = (int) send(conn->sock, io->buf, io->len, 0); }

  DBG(("%p %lu -> %d bytes", conn, conn->flags, n));

  ns_call(conn, NS_SEND, &n);
  if (ns_is_error(n)) {
    conn->flags |= NSF_CLOSE_IMMEDIATELY;
  } else if (n > 0) {
    iobuf_remove(io, n);
  }
}

/*
 * Send data to the connection.
 *
 * Number of written bytes is returned. Note that these sending
 * functions do not actually push data to the sockets, they just append data
 * to the output buffer. The exception is UDP connections. For UDP, data is
 * sent immediately, and returned value indicates an actual number of bytes
 * sent to the socket.
 */
int ns_send(struct ns_connection *conn, const void *buf, int len) {
  return (int) ns_out(conn, buf, len);
}

static void ns_handle_udp(struct ns_connection *ls) {
  struct ns_connection nc;
  char buf[NS_UDP_RECEIVE_BUFFER_SIZE];
  int n;
  socklen_t s_len = sizeof(nc.sa);

  memset(&nc, 0, sizeof(nc));
  n = recvfrom(ls->sock, buf, sizeof(buf), 0, &nc.sa.sa, &s_len);
  if (n <= 0) {
    DBG(("%p recvfrom: %s", ls, strerror(errno)));
  } else {
    nc.mgr = ls->mgr;
    nc.recv_iobuf.buf = buf;
    nc.recv_iobuf.len = nc.recv_iobuf.size = n;
    nc.sock = ls->sock;
    nc.handler = ls->handler;
    nc.user_data = ls->user_data;
    nc.proto_data = ls->proto_data;
    nc.proto_handler = ls->proto_handler;
    nc.mgr = ls->mgr;
    nc.listener = ls;
    nc.flags = NSF_UDP;
    DBG(("%p %d bytes received", ls, n));
    ns_call(&nc, NS_RECV, &n);
  }
}

static void ns_add_to_set(sock_t sock, fd_set *set, sock_t *max_fd) {
  if (sock != INVALID_SOCKET) {
    FD_SET(sock, set);
    if (*max_fd == INVALID_SOCKET || sock > *max_fd) {
      *max_fd = sock;
    }
  }
}

/*
 * This function performs the actual IO, and must be called in a loop
 * (an event loop). Returns the current timestamp.
 */
time_t ns_mgr_poll(struct ns_mgr *mgr, int milli) {
  struct ns_connection *nc, *tmp;
  struct timeval tv;
  fd_set read_set, write_set, err_set;
  sock_t max_fd = INVALID_SOCKET;
  time_t current_time = time(NULL);

  FD_ZERO(&read_set);
  FD_ZERO(&write_set);
  FD_ZERO(&err_set);
  ns_add_to_set(mgr->ctl[1], &read_set, &max_fd);

  for (nc = mgr->active_connections; nc != NULL; nc = tmp) {
    tmp = nc->next;
    if (!(nc->flags & (NSF_LISTENING | NSF_CONNECTING))) {
      ns_call(nc, NS_POLL, &current_time);
    }

    /*
     * NS_POLL handler could have signaled us to close the connection
     * by setting NSF_CLOSE_IMMEDIATELY flag. In this case, we don't want to
     * trigger any other events on that connection, but close it right away.
     */
    if (nc->flags & NSF_CLOSE_IMMEDIATELY) {
      /* NOTE(lsm): this call removes nc from the mgr->active_connections */
      ns_close_conn(nc);
      continue;
    }

    if (!(nc->flags & NSF_WANT_WRITE)) {
      /*DBG(("%p read_set", nc)); */
      ns_add_to_set(nc->sock, &read_set, &max_fd);
    }

    if (((nc->flags & NSF_CONNECTING) && !(nc->flags & NSF_WANT_READ)) ||
        (nc->send_iobuf.len > 0 && !(nc->flags & NSF_CONNECTING) &&
         !(nc->flags & NSF_DONT_SEND))) {
      /*DBG(("%p write_set", nc)); */
      ns_add_to_set(nc->sock, &write_set, &max_fd);
      ns_add_to_set(nc->sock, &err_set, &max_fd);
    }
  }

  tv.tv_sec = milli / 1000;
  tv.tv_usec = (milli % 1000) * 1000;

  if (select((int) max_fd + 1, &read_set, &write_set, &err_set, &tv) > 0) {
    /* select() might have been waiting for a long time, reset current_time
     *  now to prevent last_io_time being set to the past. */
    current_time = time(NULL);

    /* Read wakeup messages */
    if (mgr->ctl[1] != INVALID_SOCKET &&
        FD_ISSET(mgr->ctl[1], &read_set)) {
      struct ctl_msg ctl_msg;
      int len = (int) recv(mgr->ctl[1], (char *) &ctl_msg, sizeof(ctl_msg), 0);
      send(mgr->ctl[1], ctl_msg.message, 1, 0);
      if (len >= (int) sizeof(ctl_msg.callback) && ctl_msg.callback != NULL) {
        struct ns_connection *c;
        for (c = ns_next(mgr, NULL); c != NULL; c = ns_next(mgr, c)) {
          ctl_msg.callback(c, NS_POLL, ctl_msg.message);
        }
      }
    }

    for (nc = mgr->active_connections; nc != NULL; nc = tmp) {
      tmp = nc->next;

      /* Windows reports failed connect() requests in err_set */
      if (FD_ISSET(nc->sock, &err_set) && (nc->flags & NSF_CONNECTING)) {
        nc->last_io_time = current_time;
        ns_read_from_socket(nc);
      }

      if (FD_ISSET(nc->sock, &read_set)) {
        nc->last_io_time = current_time;
        if (nc->flags & NSF_UDP) {
          ns_handle_udp(nc);
        } else if (nc->flags & NSF_LISTENING) {
          /*
           * We're not looping here, and accepting just one connection at
           * a time. The reason is that eCos does not respect non-blocking
           * flag on a listening socket and hangs in a loop.
           */
          accept_conn(nc);
        } else {
          ns_read_from_socket(nc);
        }
      }

      if (FD_ISSET(nc->sock, &write_set)) {
        nc->last_io_time = current_time;
        if (nc->flags & NSF_CONNECTING) {
          ns_read_from_socket(nc);
        } else if (!(nc->flags & NSF_DONT_SEND) &&
                   !(nc->flags & NSF_CLOSE_IMMEDIATELY)) {
          ns_write_to_socket(nc);
        }
      }
    }
  }

  for (nc = mgr->active_connections; nc != NULL; nc = tmp) {
    tmp = nc->next;
    if ((nc->flags & NSF_CLOSE_IMMEDIATELY) ||
        (nc->send_iobuf.len == 0 &&
         (nc->flags & NSF_SEND_AND_CLOSE))) {
      ns_close_conn(nc);
    }
  }

  return current_time;
}

/*
 * Schedules an async connect for a resolved address and proto.
 * Called from two places: `ns_connect_opt()` and from async resolver.
 * When called from the async resolver, it must trigger `NS_CONNECT` event
 * with a failure flag to indicate connection failure.
 */
NS_INTERNAL struct ns_connection *ns_finish_connect(struct ns_connection *nc,
                                                    int proto,
                                                    union socket_address *sa,
                                                    struct ns_add_sock_opts o) {
  sock_t sock = INVALID_SOCKET;
  int rc;

  DBG(("%p %s://%s:%hu", nc, proto == SOCK_DGRAM ? "udp" : "tcp",
       inet_ntoa(nc->sa.sin.sin_addr), ntohs(nc->sa.sin.sin_port)));

  if ((sock = socket(AF_INET, proto, 0)) == INVALID_SOCKET) {
    int failure = errno;
    NS_SET_PTRPTR(o.error_string, "cannot create socket");
    ns_call(nc, NS_CONNECT, &failure);
    ns_call(nc, NS_CLOSE, NULL);
    ns_destroy_conn(nc);
    return NULL;
  }

  ns_set_non_blocking_mode(sock);
  rc = (proto == SOCK_DGRAM) ? 0 : connect(sock, &sa->sa, sizeof(sa->sin));

  if (rc != 0 && ns_is_error(rc)) {
    NS_SET_PTRPTR(o.error_string, "cannot connect to socket");
    ns_call(nc, NS_CONNECT, &rc);
    ns_call(nc, NS_CLOSE, NULL);
    ns_destroy_conn(nc);
    close(sock);
    return NULL;
  }

  /* No ns_destroy_conn() call after this! */
  ns_set_sock(nc, sock);

  if (rc == 0) {
    /* connect() succeeded. Trigger successful NS_CONNECT event */
    ns_call(nc, NS_CONNECT, &rc);
  } else {
    nc->flags |= NSF_CONNECTING;
  }

  return nc;
}

/*
 * Callback for the async resolver on ns_connect_opt() call.
 * Main task of this function is to trigger NS_CONNECT event with
 *    either failure (and dealloc the connection)
 *    or success (and proceed with connect()
 */
static void resolve_cb(struct ns_dns_message *msg, void *data) {
  struct ns_connection *nc = (struct ns_connection *) data;

  if (msg == NULL || msg->answers[0].rtype != NS_DNS_A_RECORD) {
    int failure = -1;
    ns_call(nc, NS_CONNECT, &failure);
    ns_call(nc, NS_CLOSE, NULL);
    ns_destroy_conn(nc);
  } else {
    static struct ns_add_sock_opts opts;
    /*
     * Async resolver guarantees that there is at least one answer.
     * TODO(lsm): handle IPv6 answers too
     */

    ns_dns_parse_record_data(msg, &msg->answers[0], &nc->sa.sin.sin_addr, 4);
    /* ns_finish_connect() triggers NS_CONNECT on failure */
    ns_finish_connect(nc, nc->flags & NSF_UDP ? SOCK_DGRAM : SOCK_STREAM,
                      &nc->sa, opts);
  }
}

/*
 * Connect to a remote host.
 *
 * See `ns_connect_opt` for full documentation.
 */
struct ns_connection *ns_connect(struct ns_mgr *mgr, const char *address,
                                 ns_event_handler_t callback) {
  static struct ns_connect_opts opts;
  return ns_connect_opt(mgr, address, callback, opts);
}

/*
 * Connect to a remote host.
 *
 * `address` format is `[PROTO://]HOST:PORT`. `PROTO` could be `tcp` or `udp`.
 * `HOST` could be an IP address,
 * IPv6 address (if Fossa is compiled with `-DNS_ENABLE_IPV6`), or a host name.
 * If `HOST` is a name, Fossa will resolve it asynchronously. Examples of
 * valid addresses: `google.com:80`, `udp://1.2.3.4:53`, `10.0.0.1:443`.
 *
 * See the `ns_connect_opts` structure for a description of the optional
 * parameters.
 *
 * Returns a new outbound connection, or `NULL` on error.
 *
 * NOTE: New connection will receive `NS_CONNECT` as it's first event
 * which will report connect success status.
 * If asynchronous resolution fail, or `connect()` syscall fail for whatever
 * reason (e.g. with `ECONNREFUSED` or `ENETUNREACH`), then `NS_CONNECT`
 * event report failure. Code example below:
 *
 * [source,c]
 * ----
 * static void ev_handler(struct ns_connection *nc, int ev, void *ev_data) {
 *   int connect_status;
 *
 *   switch (ev) {
 *     case NS_CONNECT:
 *       connect_status = * (int *) ev_data;
 *       if (connect_status == 0) {
 *         // Success
 *       } else  {
 *         // Error
 *         printf("connect() error: %s\n", strerror(connect_status));
 *       }
 *       break;
 *     ...
 *   }
 * }
 *
 *   ...
 *   ns_connect(mgr, "my_site.com:80", ev_handler);
 * ----
 */
struct ns_connection *ns_connect_opt(struct ns_mgr *mgr, const char *address,
                                     ns_event_handler_t callback,
                                     struct ns_connect_opts opts) {
  struct ns_connection *nc = NULL;
  int proto, rc;
  struct ns_add_sock_opts add_sock_opts;
  char host[NS_MAX_HOST_LEN];

  NS_COPY_COMMON_CONNECTION_OPTIONS(&add_sock_opts, &opts);

  if ((nc = ns_create_connection(mgr, callback, add_sock_opts)) == NULL) {
    return NULL;
  } else if ((rc = ns_parse_address(address, &nc->sa, &proto, host,
                                    sizeof(host))) < 0) {
    /* Address is malformed */
    NS_SET_PTRPTR(opts.error_string, "cannot parse address");
    ns_destroy_conn(nc);
    return NULL;
  }

  nc->flags |= opts.flags;
  nc->flags |= (proto == SOCK_DGRAM) ? NSF_UDP : 0;
  nc->user_data = opts.user_data;

  if (rc == 0) {
    /*
     * DNS resolution is required for host.
     * ns_parse_address() fills port in nc->sa, which we pass to resolve_cb()
     */

    if (ns_resolve_async(nc->mgr, host, NS_DNS_A_RECORD, resolve_cb, nc) != 0) {
      NS_SET_PTRPTR(opts.error_string, "cannot schedule DNS lookup");
      ns_destroy_conn(nc);
      return NULL;
    }
    return nc;
  } else {
    /* Address is parsed and resolved to IP. proceed with connect() */
    return ns_finish_connect(nc, proto, &nc->sa, add_sock_opts);
  }
}

/*
 * Create listening connection.
 *
 * See `ns_bind_opt` for full documentation.
 */
struct ns_connection *ns_bind(struct ns_mgr *srv, const char *address,
                              ns_event_handler_t event_handler) {
  static struct ns_bind_opts opts;
  return ns_bind_opt(srv, address, event_handler, opts);
}

/*
 * Create listening connection.
 *
 * `address` parameter tells which address to bind to. It's format is the same
 * as for the `ns_connect()` call, where `HOST` part is optional. `address`
 * can be just a port number, e.g. `:8000`. To bind to a specific interface,
 * an IP address can be specified, e.g. `1.2.3.4:8000`. By default, a TCP
 * connection is created. To create UDP connection, prepend `udp://` prefix,
 * e.g. `udp://:8000`. To summarize, `address` paramer has following format:
 * `[PROTO://][IP_ADDRESS]:PORT`, where `PROTO` could be `tcp` or `udp`.
 *
 * See the `ns_bind_opts` structure for a description of the optional
 * parameters.
 *
 * Returns a new listening connection, or `NULL` on error.
 */
struct ns_connection *ns_bind_opt(struct ns_mgr *mgr, const char *address,
                              ns_event_handler_t callback,
                              struct ns_bind_opts opts) {
  union socket_address sa;
  struct ns_connection *nc = NULL;
  int proto;
  sock_t sock;
  struct ns_add_sock_opts add_sock_opts;
  char host[NS_MAX_HOST_LEN];

  NS_COPY_COMMON_CONNECTION_OPTIONS(&add_sock_opts, &opts);

  if (ns_parse_address(address, &sa, &proto, host, sizeof(host)) <= 0) {
    NS_SET_PTRPTR(opts.error_string, "cannot parse address");
  } else if ((sock = ns_open_listening_socket(&sa, proto)) == INVALID_SOCKET) {
    DBG(("Failed to open listener: %d", errno));
    NS_SET_PTRPTR(opts.error_string, "failed to open listener");
  } else if ((nc = ns_add_sock_opt(mgr, sock, callback,
                                   add_sock_opts)) == NULL) {
    /* opts.error_string set by ns_add_sock_opt */
    DBG(("Failed to ns_add_sock"));
    closesocket(sock);
  } else {
    nc->sa = sa;
    nc->flags |= NSF_LISTENING;
    nc->handler = callback;

    if (proto == SOCK_DGRAM) {
      nc->flags |= NSF_UDP;
    }

    DBG(("%p sock %d/%d", nc, sock, proto));
  }

  return nc;
}

/*
 * Create a connection, associate it with the given socket and event handler,
 * and add it to the manager.
 *
 * For more options see the `ns_add_sock_opt` variant.
 */
struct ns_connection *ns_add_sock(struct ns_mgr *s, sock_t sock,
                                  ns_event_handler_t callback) {
  static struct ns_add_sock_opts opts;
  return ns_add_sock_opt(s, sock, callback, opts);
}

/*
 * Create a connection, associate it with the given socket and event handler,
 * and add to the manager.
 *
 * See the `ns_add_sock_opts` structure for a description of the options.
 */
struct ns_connection *ns_add_sock_opt(struct ns_mgr *s, sock_t sock,
                                      ns_event_handler_t callback,
                                      struct ns_add_sock_opts opts) {
  struct ns_connection *nc = ns_create_connection(s, callback, opts);
  if (nc != NULL) {
    ns_set_sock(nc, sock);
  }
  return nc;
}

/*
 * Iterates over all active connections.
 *
 * Returns next connection from the list
 * of active connections, or `NULL` if there is no more connections. Below
 * is the iteration idiom:
 *
 * [source,c]
 * ----
 * for (c = ns_next(srv, NULL); c != NULL; c = ns_next(srv, c)) {
 *   // Do something with connection `c`
 * }
 * ----
 */
struct ns_connection *ns_next(struct ns_mgr *s, struct ns_connection *conn) {
  return conn == NULL ? s->active_connections : conn->next;
}

/*
 * Passes a message of a given length to all connections.
 *
 * Must be called from a different thread.
 *
 * Fossa manager has a socketpair, `struct ns_mgr::ctl`,
 * where `ns_broadcast()` pushes the message.
 * `ns_mgr_poll()` wakes up, reads a message from the socket pair, and calls
 * specified callback for each connection. Thus the callback function executes
 * in event manager thread. Note that `ns_broadcast()` is the only function
 * that can be, and must be, called from a different thread.
 */
void ns_broadcast(struct ns_mgr *mgr, ns_event_handler_t cb,
                  void *data, size_t len) {
  struct ctl_msg ctl_msg;
  if (mgr->ctl[0] != INVALID_SOCKET && data != NULL &&
      len < sizeof(ctl_msg.message)) {
    ctl_msg.callback = cb;
    memcpy(ctl_msg.message, data, len);
    send(mgr->ctl[0], (char *) &ctl_msg,
         offsetof(struct ctl_msg, message) + len, 0);
    recv(mgr->ctl[0], (char *) &len, 1, 0);
  }
}
#ifdef NS_MODULE_LINES
#line 1 "modules/../deps/frozen/frozen.c"
/**/
#endif
/*
 * Copyright (c) 2004-2013 Sergey Lyubka <valenok@gmail.com>
 * Copyright (c) 2013 Cesanta Software Limited
 * All rights reserved
 *
 * This library is dual-licensed: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. For the terms of this
 * license, see <http: *www.gnu.org/licenses/>.
 *
 * You are free to use this library under the terms of the GNU General
 * Public License, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * Alternatively, you can license this library under a commercial
 * license, as set out in <http://cesanta.com/products.html>.
 */

#define _CRT_SECURE_NO_WARNINGS /* Disable deprecation warning in VS2005+ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#ifdef _WIN32
#define snprintf _snprintf
#endif

#ifndef FROZEN_REALLOC
#define FROZEN_REALLOC realloc
#endif

#ifndef FROZEN_FREE
#define FROZEN_FREE free
#endif

struct frozen {
  const char *end;
  const char *cur;
  struct json_token *tokens;
  int max_tokens;
  int num_tokens;
  int do_realloc;
};

static int parse_object(struct frozen *f);
static int parse_value(struct frozen *f);

#define EXPECT(cond, err_code) do { if (!(cond)) return (err_code); } while (0)
#define TRY(expr) do { int _n = expr; if (_n < 0) return _n; } while (0)
#define END_OF_STRING (-1)

static int left(const struct frozen *f) {
  return f->end - f->cur;
}

static int is_space(int ch) {
  return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

static void skip_whitespaces(struct frozen *f) {
  while (f->cur < f->end && is_space(*f->cur)) f->cur++;
}

static int cur(struct frozen *f) {
  skip_whitespaces(f);
  return f->cur >= f->end ? END_OF_STRING : * (unsigned char *) f->cur;
}

static int test_and_skip(struct frozen *f, int expected) {
  int ch = cur(f);
  if (ch == expected) { f->cur++; return 0; }
  return ch == END_OF_STRING ? JSON_STRING_INCOMPLETE : JSON_STRING_INVALID;
}

static int is_alpha(int ch) {
  return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z');
}

static int is_digit(int ch) {
  return ch >= '0' && ch <= '9';
}

static int is_hex_digit(int ch) {
  return is_digit(ch) || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
}

static int get_escape_len(const char *s, int len) {
  switch (*s) {
    case 'u':
      return len < 6 ? JSON_STRING_INCOMPLETE :
        is_hex_digit(s[1]) && is_hex_digit(s[2]) &&
        is_hex_digit(s[3]) && is_hex_digit(s[4]) ? 5 : JSON_STRING_INVALID;
    case '"': case '\\': case '/': case 'b':
    case 'f': case 'n': case 'r': case 't':
      return len < 2 ? JSON_STRING_INCOMPLETE : 1;
    default:
      return JSON_STRING_INVALID;
  }
}

static int capture_ptr(struct frozen *f, const char *ptr, enum json_type type) {
  if (f->do_realloc && f->num_tokens >= f->max_tokens) {
    int new_size = f->max_tokens == 0 ? 100 : f->max_tokens * 2;
    void *p = FROZEN_REALLOC(f->tokens, new_size * sizeof(f->tokens[0]));
    if (p == NULL) return JSON_TOKEN_ARRAY_TOO_SMALL;
    f->max_tokens = new_size;
    f->tokens = (struct json_token *) p;
  }
  if (f->tokens == NULL || f->max_tokens == 0) return 0;
  if (f->num_tokens >= f->max_tokens) return JSON_TOKEN_ARRAY_TOO_SMALL;
  f->tokens[f->num_tokens].ptr = ptr;
  f->tokens[f->num_tokens].type = type;
  f->num_tokens++;
  return 0;
}

static int capture_len(struct frozen *f, int token_index, const char *ptr) {
  if (f->tokens == 0 || f->max_tokens == 0) return 0;
  EXPECT(token_index >= 0 && token_index < f->max_tokens, JSON_STRING_INVALID);
  f->tokens[token_index].len = ptr - f->tokens[token_index].ptr;
  f->tokens[token_index].num_desc = (f->num_tokens - 1) - token_index;
  return 0;
}

/* identifier = letter { letter | digit | '_' } */
static int parse_identifier(struct frozen *f) {
  EXPECT(is_alpha(cur(f)), JSON_STRING_INVALID);
  TRY(capture_ptr(f, f->cur, JSON_TYPE_STRING));
  while (f->cur < f->end &&
         (*f->cur == '_' || is_alpha(*f->cur) || is_digit(*f->cur))) {
    f->cur++;
  }
  capture_len(f, f->num_tokens - 1, f->cur);
  return 0;
}

static int get_utf8_char_len(unsigned char ch) {
  if ((ch & 0x80) == 0) return 1;
  switch (ch & 0xf0) {
    case 0xf0: return 4;
    case 0xe0: return 3;
    default: return 2;
  }
}

/* string = '"' { quoted_printable_chars } '"' */
static int parse_string(struct frozen *f) {
  int n, ch = 0, len = 0;
  TRY(test_and_skip(f, '"'));
  TRY(capture_ptr(f, f->cur, JSON_TYPE_STRING));
  for (; f->cur < f->end; f->cur += len) {
    ch = * (unsigned char *) f->cur;
    len = get_utf8_char_len((unsigned char) ch);
    EXPECT(ch >= 32 && len > 0, JSON_STRING_INVALID);  /* No control chars */
    EXPECT(len < left(f), JSON_STRING_INCOMPLETE);
    if (ch == '\\') {
      EXPECT((n = get_escape_len(f->cur + 1, left(f))) > 0, n);
      len += n;
    } else if (ch == '"') {
      capture_len(f, f->num_tokens - 1, f->cur);
      f->cur++;
      break;
    };
  }
  return ch == '"' ? 0 : JSON_STRING_INCOMPLETE;
}

/* number = [ '-' ] digit+ [ '.' digit+ ] [ ['e'|'E'] ['+'|'-'] digit+ ] */
static int parse_number(struct frozen *f) {
  int ch = cur(f);
  TRY(capture_ptr(f, f->cur, JSON_TYPE_NUMBER));
  if (ch == '-') f->cur++;
  EXPECT(f->cur < f->end, JSON_STRING_INCOMPLETE);
  EXPECT(is_digit(f->cur[0]), JSON_STRING_INVALID);
  while (f->cur < f->end && is_digit(f->cur[0])) f->cur++;
  if (f->cur < f->end && f->cur[0] == '.') {
    f->cur++;
    EXPECT(f->cur < f->end, JSON_STRING_INCOMPLETE);
    EXPECT(is_digit(f->cur[0]), JSON_STRING_INVALID);
    while (f->cur < f->end && is_digit(f->cur[0])) f->cur++;
  }
  if (f->cur < f->end && (f->cur[0] == 'e' || f->cur[0] == 'E')) {
    f->cur++;
    EXPECT(f->cur < f->end, JSON_STRING_INCOMPLETE);
    if ((f->cur[0] == '+' || f->cur[0] == '-')) f->cur++;
    EXPECT(f->cur < f->end, JSON_STRING_INCOMPLETE);
    EXPECT(is_digit(f->cur[0]), JSON_STRING_INVALID);
    while (f->cur < f->end && is_digit(f->cur[0])) f->cur++;
  }
  capture_len(f, f->num_tokens - 1, f->cur);
  return 0;
}

/* array = '[' [ value { ',' value } ] ']' */
static int parse_array(struct frozen *f) {
  int ind;
  TRY(test_and_skip(f, '['));
  TRY(capture_ptr(f, f->cur - 1, JSON_TYPE_ARRAY));
  ind = f->num_tokens - 1;
  while (cur(f) != ']') {
    TRY(parse_value(f));
    if (cur(f) == ',') f->cur++;
  }
  TRY(test_and_skip(f, ']'));
  capture_len(f, ind, f->cur);
  return 0;
}

static int compare(const char *s, const char *str, int len) {
  int i = 0;
  while (i < len && s[i] == str[i]) i++;
  return i == len ? 1 : 0;
}

static int expect(struct frozen *f, const char *s, int len, enum json_type t) {
  int i, n = left(f);

  TRY(capture_ptr(f, f->cur, t));
  for (i = 0; i < len; i++) {
    if (i >= n) return JSON_STRING_INCOMPLETE;
    if (f->cur[i] != s[i]) return JSON_STRING_INVALID;
  }
  f->cur += len;
  TRY(capture_len(f, f->num_tokens - 1, f->cur));

  return 0;
}

/* value = 'null' | 'true' | 'false' | number | string | array | object */
static int parse_value(struct frozen *f) {
  int ch = cur(f);

  switch (ch) {
    case '"': TRY(parse_string(f)); break;
    case '{': TRY(parse_object(f)); break;
    case '[': TRY(parse_array(f)); break;
    case 'n': TRY(expect(f, "null", 4, JSON_TYPE_NULL)); break;
    case 't': TRY(expect(f, "true", 4, JSON_TYPE_TRUE)); break;
    case 'f': TRY(expect(f, "false", 5, JSON_TYPE_FALSE)); break;
    case '-': case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
      TRY(parse_number(f));
      break;
    default:
      return ch == END_OF_STRING ? JSON_STRING_INCOMPLETE : JSON_STRING_INVALID;
  }

  return 0;
}

/* key = identifier | string */
static int parse_key(struct frozen *f) {
  int ch = cur(f);
#if 0
  printf("%s 1 [%.*s]\n", __func__, (int) (f->end - f->cur), f->cur);
#endif
  if (is_alpha(ch)) {
    TRY(parse_identifier(f));
  } else if (ch == '"') {
    TRY(parse_string(f));
  } else {
    return ch == END_OF_STRING ? JSON_STRING_INCOMPLETE : JSON_STRING_INVALID;
  }
  return 0;
}

/* pair = key ':' value */
static int parse_pair(struct frozen *f) {
  TRY(parse_key(f));
  TRY(test_and_skip(f, ':'));
  TRY(parse_value(f));
  return 0;
}

/* object = '{' pair { ',' pair } '}' */
static int parse_object(struct frozen *f) {
  int ind;
  TRY(test_and_skip(f, '{'));
  TRY(capture_ptr(f, f->cur - 1, JSON_TYPE_OBJECT));
  ind = f->num_tokens - 1;
  while (cur(f) != '}') {
    TRY(parse_pair(f));
    if (cur(f) == ',') f->cur++;
  }
  TRY(test_and_skip(f, '}'));
  capture_len(f, ind, f->cur);
  return 0;
}

static int doit(struct frozen *f) {
  if (f->cur == 0 || f->end < f->cur) return JSON_STRING_INVALID;
  if (f->end == f->cur) return JSON_STRING_INCOMPLETE;
  TRY(parse_object(f));
  TRY(capture_ptr(f, f->cur, JSON_TYPE_EOF));
  capture_len(f, f->num_tokens, f->cur);
  return 0;
}

/* json = object */
int parse_json(const char *s, int s_len, struct json_token *arr, int arr_len) {
  struct frozen frozen;

  memset(&frozen, 0, sizeof(frozen));
  frozen.end = s + s_len;
  frozen.cur = s;
  frozen.tokens = arr;
  frozen.max_tokens = arr_len;

  TRY(doit(&frozen));

  return frozen.cur - s;
}

struct json_token *parse_json2(const char *s, int s_len) {
  struct frozen frozen;

  memset(&frozen, 0, sizeof(frozen));
  frozen.end = s + s_len;
  frozen.cur = s;
  frozen.do_realloc = 1;

  if (doit(&frozen) < 0) {
    FROZEN_FREE((void *) frozen.tokens);
    frozen.tokens = NULL;
  }
  return frozen.tokens;
}

static int path_part_len(const char *p) {
  int i = 0;
  while (p[i] != '\0' && p[i] != '[' && p[i] != '.') i++;
  return i;
}

struct json_token *find_json_token(struct json_token *toks, const char *path) {
  while (path != 0 && path[0] != '\0') {
    int i, ind2 = 0, ind = -1, skip = 2, n = path_part_len(path);
    if (path[0] == '[') {
      if (toks->type != JSON_TYPE_ARRAY || !is_digit(path[1])) return 0;
      for (ind = 0, n = 1; path[n] != ']' && path[n] != '\0'; n++) {
        if (!is_digit(path[n])) return 0;
        ind *= 10;
        ind += path[n] - '0';
      }
      if (path[n++] != ']') return 0;
      skip = 1;  /* In objects, we skip 2 elems while iterating, in arrays 1. */
    } else if (toks->type != JSON_TYPE_OBJECT) return 0;
    toks++;
    for (i = 0; i < toks[-1].num_desc; i += skip, ind2++) {
      /* ind == -1 indicated that we're iterating an array, not object */
      if (ind == -1 && toks[i].type != JSON_TYPE_STRING) return 0;
      if (ind2 == ind ||
          (ind == -1 && toks[i].len == n && compare(path, toks[i].ptr, n))) {
        i += skip - 1;
        break;
      };
      if (toks[i - 1 + skip].type == JSON_TYPE_ARRAY ||
          toks[i - 1 + skip].type == JSON_TYPE_OBJECT) {
        i += toks[i - 1 + skip].num_desc;
      }
    }
    if (i == toks[-1].num_desc) return 0;
    path += n;
    if (path[0] == '.') path++;
    if (path[0] == '\0') return &toks[i];
    toks += i;
  }
  return 0;
}

int json_emit_long(char *buf, int buf_len, long int value) {
  char tmp[20];
  int n = snprintf(tmp, sizeof(tmp), "%ld", value);
  strncpy(buf, tmp, buf_len > 0 ? buf_len : 0);
  return n;
}

int json_emit_double(char *buf, int buf_len, double value) {
  char tmp[20];
  int n = snprintf(tmp, sizeof(tmp), "%g", value);
  strncpy(buf, tmp, buf_len > 0 ? buf_len : 0);
  return n;
}

int json_emit_quoted_str(char *s, int s_len, const char *str, int len) {
  const char *begin = s, *end = s + s_len, *str_end = str + len;
  char ch;

#define EMIT(x) do { if (s < end) *s = x; s++; } while (0)

  EMIT('"');
  while (str < str_end) {
    ch = *str++;
    switch (ch) {
      case '"':  EMIT('\\'); EMIT('"'); break;
      case '\\': EMIT('\\'); EMIT('\\'); break;
      case '\b': EMIT('\\'); EMIT('b'); break;
      case '\f': EMIT('\\'); EMIT('f'); break;
      case '\n': EMIT('\\'); EMIT('n'); break;
      case '\r': EMIT('\\'); EMIT('r'); break;
      case '\t': EMIT('\\'); EMIT('t'); break;
      default: EMIT(ch);
    }
  }
  EMIT('"');
  if (s < end) {
    *s = '\0';
  }

  return s - begin;
}

int json_emit_unquoted_str(char *buf, int buf_len, const char *str, int len) {
  if (buf_len > 0 && len > 0) {
    int n = len < buf_len ? len : buf_len;
    memcpy(buf, str, n);
    if (n < buf_len) {
      buf[n] = '\0';
    }
  }
  return len;
}

int json_emit_va(char *s, int s_len, const char *fmt, va_list ap) {
  const char *end = s + s_len, *str, *orig = s;
  size_t len;

  while (*fmt != '\0') {
    switch (*fmt) {
      case '[': case ']': case '{': case '}': case ',': case ':':
      case ' ': case '\r': case '\n': case '\t':
        if (s < end) {
          *s = *fmt;
        }
        s++;
        break;
      case 'i':
        s += json_emit_long(s, end - s, va_arg(ap, long));
        break;
      case 'f':
        s += json_emit_double(s, end - s, va_arg(ap, double));
        break;
      case 'v':
        str = va_arg(ap, char *);
        len = va_arg(ap, size_t);
        s += json_emit_quoted_str(s, end - s, str, len);
        break;
      case 'V':
        str = va_arg(ap, char *);
        len = va_arg(ap, size_t);
        s += json_emit_unquoted_str(s, end - s, str, len);
        break;
      case 's':
        str = va_arg(ap, char *);
        s += json_emit_quoted_str(s, end - s, str, strlen(str));
        break;
      case 'S':
        str = va_arg(ap, char *);
        s += json_emit_unquoted_str(s, end - s, str, strlen(str));
        break;
      case 'T':
        s += json_emit_unquoted_str(s, end - s, "true", 4);
        break;
      case 'F':
        s += json_emit_unquoted_str(s, end - s, "false", 5);
        break;
      case 'N':
        s += json_emit_unquoted_str(s, end - s, "null", 4);
        break;
      default:
        return 0;
    }
    fmt++;
  }

  /* Best-effort to 0-terminate generated string */
  if (s < end) {
    *s = '\0';
  }

  return s - orig;
}

int json_emit(char *buf, int buf_len, const char *fmt, ...) {
  int len;
  va_list ap;

  va_start(ap, fmt);
  len = json_emit_va(buf, buf_len, fmt, ap);
  va_end(ap);

  return len;
}
#ifdef NS_MODULE_LINES
#line 1 "modules/http.c"
/**/
#endif
/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

/*
 * == HTTP/Websocket API
 */

#ifndef NS_DISABLE_HTTP_WEBSOCKET


struct proto_data_http {
  FILE *fp;   /* Opened file */
};

#define MIME_ENTRY(_ext, _type) { _ext, sizeof(_ext) - 1, _type }
static const struct {
  const char *extension;
  size_t ext_len;
  const char *mime_type;
} static_builtin_mime_types[] = {
  MIME_ENTRY("html", "text/html"),
  MIME_ENTRY("html", "text/html"),
  MIME_ENTRY("htm", "text/html"),
  MIME_ENTRY("shtm", "text/html"),
  MIME_ENTRY("shtml", "text/html"),
  MIME_ENTRY("css", "text/css"),
  MIME_ENTRY("js", "application/x-javascript"),
  MIME_ENTRY("ico", "image/x-icon"),
  MIME_ENTRY("gif", "image/gif"),
  MIME_ENTRY("jpg", "image/jpeg"),
  MIME_ENTRY("jpeg", "image/jpeg"),
  MIME_ENTRY("png", "image/png"),
  MIME_ENTRY("svg", "image/svg+xml"),
  MIME_ENTRY("txt", "text/plain"),
  MIME_ENTRY("torrent", "application/x-bittorrent"),
  MIME_ENTRY("wav", "audio/x-wav"),
  MIME_ENTRY("mp3", "audio/x-mp3"),
  MIME_ENTRY("mid", "audio/mid"),
  MIME_ENTRY("m3u", "audio/x-mpegurl"),
  MIME_ENTRY("ogg", "application/ogg"),
  MIME_ENTRY("ram", "audio/x-pn-realaudio"),
  MIME_ENTRY("xml", "text/xml"),
  MIME_ENTRY("ttf", "application/x-font-ttf"),
  MIME_ENTRY("json", "application/json"),
  MIME_ENTRY("xslt", "application/xml"),
  MIME_ENTRY("xsl", "application/xml"),
  MIME_ENTRY("ra", "audio/x-pn-realaudio"),
  MIME_ENTRY("doc", "application/msword"),
  MIME_ENTRY("exe", "application/octet-stream"),
  MIME_ENTRY("zip", "application/x-zip-compressed"),
  MIME_ENTRY("xls", "application/excel"),
  MIME_ENTRY("tgz", "application/x-tar-gz"),
  MIME_ENTRY("tar", "application/x-tar"),
  MIME_ENTRY("gz", "application/x-gunzip"),
  MIME_ENTRY("arj", "application/x-arj-compressed"),
  MIME_ENTRY("rar", "application/x-rar-compressed"),
  MIME_ENTRY("rtf", "application/rtf"),
  MIME_ENTRY("pdf", "application/pdf"),
  MIME_ENTRY("swf", "application/x-shockwave-flash"),
  MIME_ENTRY("mpg", "video/mpeg"),
  MIME_ENTRY("webm", "video/webm"),
  MIME_ENTRY("mpeg", "video/mpeg"),
  MIME_ENTRY("mov", "video/quicktime"),
  MIME_ENTRY("mp4", "video/mp4"),
  MIME_ENTRY("m4v", "video/x-m4v"),
  MIME_ENTRY("asf", "video/x-ms-asf"),
  MIME_ENTRY("avi", "video/x-msvideo"),
  MIME_ENTRY("bmp", "image/bmp"),
  {NULL, 0, NULL}
};

static const char *get_mime_type(const char *path, const char *dflt) {
  const char *ext;
  size_t i, path_len;

  path_len = strlen(path);

  for (i = 0; static_builtin_mime_types[i].extension != NULL; i++) {
    ext = path + (path_len - static_builtin_mime_types[i].ext_len);
    if (path_len > static_builtin_mime_types[i].ext_len &&
        ext[-1] == '.' &&
        ns_casecmp(ext, static_builtin_mime_types[i].extension) == 0) {
      return static_builtin_mime_types[i].mime_type;
    }
  }

  return dflt;
}

/*
 * Check whether full request is buffered. Return:
 *   -1  if request is malformed
 *    0  if request is not yet fully buffered
 *   >0  actual request length, including last \r\n\r\n
 */
static int get_request_len(const char *s, int buf_len) {
  const unsigned char *buf = (unsigned char *) s;
  int i;

  for (i = 0; i < buf_len; i++) {
    if (!isprint(buf[i]) && buf[i] != '\r' && buf[i] != '\n' && buf[i] < 128) {
      return -1;
    } else if (buf[i] == '\n' && i + 1 < buf_len && buf[i + 1] == '\n') {
      return i + 2;
    } else if (buf[i] == '\n' && i + 2 < buf_len && buf[i + 1] == '\r' &&
               buf[i + 2] == '\n') {
      return i + 3;
    }
  }

  return 0;
}

/* Parses a HTTP message.
 *
 * Return number of bytes parsed. If HTTP message is
 * incomplete, `0` is returned. On parse error, negative number is returned.
 */
int ns_parse_http(const char *s, int n, struct http_message *req) {
  const char *end, *qs;
  int len, i;

  if ((len = get_request_len(s, n)) <= 0) return len;

  memset(req, 0, sizeof(*req));
  req->message.p = s;
  req->body.p = s + len;
  req->message.len = req->body.len = (size_t) ~0;
  end = s + len;

  /* Request is fully buffered. Skip leading whitespaces. */
  while (s < end && isspace(* (unsigned char *) s)) s++;

  /* Parse request line: method, URI, proto */
  s = ns_skip(s, end, " ", &req->method);
  s = ns_skip(s, end, " ", &req->uri);
  s = ns_skip(s, end, "\r\n", &req->proto);
  if (req->uri.p <= req->method.p || req->proto.p <= req->uri.p) return -1;

  for (i = 0; i < (int) ARRAY_SIZE(req->header_names); i++) {
    struct ns_str *k = &req->header_names[i], *v = &req->header_values[i];

    s = ns_skip(s, end, ": ", k);
    s = ns_skip(s, end, "\r\n", v);

    while (v->len > 0 && v->p[v->len - 1] == ' ') {
      v->len--;  /* Trim trailing spaces in header value */
    }

    if (k->len == 0 || v->len == 0) {
      k->p = v->p = NULL;
      break;
    }

    if (!ns_ncasecmp(k->p, "Content-Length", 14)) {
      req->body.len = to64(v->p);
      req->message.len = len + req->body.len;
    }
  }

  /* If URI contains '?' character, initialize query_string */
  if ((qs = (char *) memchr(req->uri.p, '?', req->uri.len)) != NULL) {
    req->query_string.p = qs + 1;
    req->query_string.len = &req->uri.p[req->uri.len] - (qs + 1);
    req->uri.len = qs - req->uri.p;
  }

  /*
   * ns_parse_http() is used to parse both HTTP requests and HTTP
   * responses. If HTTP response does not have Content-Length set, then
   * body is read until socket is closed, i.e. body.len is infinite (~0).
   *
   * For HTTP requests though, according to
   * http://tools.ietf.org/html/rfc7231#section-8.1.3,
   * only POST and PUT methods have defined body semantics.
   * Therefore, if Content-Length is not specified and methods are
   * not one of PUT or POST, set body length to 0.
   *
   * So,
   * if it is HTTP request, and Content-Length is not set,
   * and method is not (PUT or POST) then reset body length to zero.
   */
  if (req->body.len == (size_t) ~0 &&
      !(req->method.len > 5 && !memcmp(req->method.p, "HTTP/", 5)) &&
      ns_vcasecmp(&req->method, "PUT") != 0 &&
      ns_vcasecmp(&req->method, "POST") != 0) {
    req->body.len = 0;
    req->message.len = len;
  }

  return len;
}

/* Returns HTTP header if it is present in the HTTP message, or `NULL`. */
struct ns_str *ns_get_http_header(struct http_message *hm, const char *name) {
  size_t i, len = strlen(name);

  for (i = 0; i < ARRAY_SIZE(hm->header_names); i++) {
    struct ns_str *h = &hm->header_names[i], *v = &hm->header_values[i];
    if (h->p != NULL && h->len == len && !ns_ncasecmp(h->p, name, len))
      return v;
  }

  return NULL;
}

static int is_ws_fragment(unsigned char flags) {
  return (flags & 0x80) == 0 || (flags & 0x0f) == 0;
}

static int is_ws_first_fragment(unsigned char flags) {
  return (flags & 0x80) == 0 && (flags & 0x0f) != 0;
}

static void handle_incoming_websocket_frame(struct ns_connection *nc,
                                            struct websocket_message *wsm) {
  if (wsm->flags & 0x8) {
    nc->handler(nc, NS_WEBSOCKET_CONTROL_FRAME, wsm);
  } else {
    nc->handler(nc, NS_WEBSOCKET_FRAME, wsm);
  }
}

static int deliver_websocket_data(struct ns_connection *nc) {
  /* Using unsigned char *, cause of integer arithmetic below */
  uint64_t i, data_len = 0, frame_len = 0, buf_len = nc->recv_iobuf.len,
         len, mask_len = 0, header_len = 0;
  unsigned char *p = (unsigned char *) nc->recv_iobuf.buf,
              *buf = p, *e = p + buf_len;
  unsigned *sizep = (unsigned *) &p[1];  /* Size ptr for defragmented frames */
  int ok, reass = buf_len > 0 && is_ws_fragment(p[0]) &&
                  !(nc->flags & NSF_WEBSOCKET_NO_DEFRAG);

  /* If that's a continuation frame that must be reassembled, handle it */
  if (reass && !is_ws_first_fragment(p[0]) && buf_len >= 1 + sizeof(*sizep) &&
      buf_len >= 1 + sizeof(*sizep) + *sizep) {
    buf += 1 + sizeof(*sizep) + *sizep;
    buf_len -= 1 + sizeof(*sizep) + *sizep;
  }

  if (buf_len >= 2) {
    len = buf[1] & 127;
    mask_len = buf[1] & 128 ? 4 : 0;
    if (len < 126 && buf_len >= mask_len) {
      data_len = len;
      header_len = 2 + mask_len;
    } else if (len == 126 && buf_len >= 4 + mask_len) {
      header_len = 4 + mask_len;
      data_len = ntohs(* (uint16_t *) &buf[2]);
    } else if (buf_len >= 10 + mask_len) {
      header_len = 10 + mask_len;
      data_len = (((uint64_t) ntohl(* (uint32_t *) &buf[2])) << 32) +
                 ntohl(* (uint32_t *) &buf[6]);
    }
  }

  frame_len = header_len + data_len;
  ok = frame_len > 0 && frame_len <= buf_len;

  if (ok) {
    struct websocket_message wsm;

    wsm.size = (size_t) data_len;
    wsm.data = buf + header_len;
    wsm.flags = buf[0];

    /* Apply mask if necessary */
    if (mask_len > 0) {
      for (i = 0; i < data_len; i++) {
        buf[i + header_len] ^= (buf + header_len - mask_len)[i % 4];
      }
    }

    if (reass) {
      /* On first fragmented frame, nullify size */
      if (is_ws_first_fragment(wsm.flags)) {
        iobuf_resize(&nc->recv_iobuf, nc->recv_iobuf.size + sizeof(*sizep));
        p[0] &= ~0x0f;  /* Next frames will be treated as continuation */
        buf = p + 1 + sizeof(*sizep);
        *sizep = 0;  /* TODO(lsm): fix. this can stomp over frame data */
      }

      /* Append this frame to the reassembled buffer */
      memmove(buf, wsm.data, e - wsm.data);
      (*sizep) += wsm.size;
      nc->recv_iobuf.len -= wsm.data - buf;

      /* On last fragmented frame - call user handler and remove data */
      if (wsm.flags & 0x80) {
        wsm.data = p + 1 + sizeof(*sizep);
        wsm.size = *sizep;
        handle_incoming_websocket_frame(nc, &wsm);
        iobuf_remove(&nc->recv_iobuf, 1 + sizeof(*sizep) + *sizep);
      }
    } else {
      /* TODO(lsm): properly handle OOB control frames during defragmentation */
      handle_incoming_websocket_frame(nc, &wsm);
      iobuf_remove(&nc->recv_iobuf, (size_t) frame_len);  /* Cleanup frame */
    }
  }

  return ok;
}

static void ns_send_ws_header(struct ns_connection *nc, int op, size_t len) {
  int header_len;
  unsigned char header[10];

  header[0] = 0x80 + (op & 0x0f);
  if (len < 126) {
    header[1] = len;
    header_len = 2;
  } else if (len < 65535) {
    header[1] = 126;
    * (uint16_t *) &header[2] = htons((uint16_t) len);
    header_len = 4;
  } else {
    header[1] = 127;
    * (uint32_t *) &header[2] = htonl((uint32_t) ((uint64_t) len >> 32));
    * (uint32_t *) &header[6] = htonl((uint32_t) (len & 0xffffffff));
    header_len = 10;
  }
  ns_send(nc, header, header_len);
}

/*
 * Send websocket frame to the remote end.
 *
 * `op` specifies frame's type , one of:
 *
 * - WEBSOCKET_OP_CONTINUE
 * - WEBSOCKET_OP_TEXT
 * - WEBSOCKET_OP_BINARY
 * - WEBSOCKET_OP_CLOSE
 * - WEBSOCKET_OP_PING
 * - WEBSOCKET_OP_PONG
 * `data` and `data_len` contain frame data.
 */
void ns_send_websocket_frame(struct ns_connection *nc, int op,
                             const void *data, size_t len) {
  ns_send_ws_header(nc, op, len);
  ns_send(nc, data, len);

  if (op == WEBSOCKET_OP_CLOSE) {
    nc->flags |= NSF_SEND_AND_CLOSE;
  }
}

/*
 * Send multiple websocket frames.
 *
 * Like `ns_send_websocket_frame()`, but composes a frame from multiple buffers.
 */
void ns_send_websocket_framev(struct ns_connection *nc, int op,
                              const struct ns_str *strv, int strvcnt) {
  int i;
  int len = 0;
  for (i = 0; i < strvcnt; i++) {
    len += strv[i].len;
  }

  ns_send_ws_header(nc, op, len);

  for (i = 0; i < strvcnt; i++) {
    ns_send(nc, strv[i].p, strv[i].len);
  }

  if (op == WEBSOCKET_OP_CLOSE) {
    nc->flags |= NSF_SEND_AND_CLOSE;
  }
}

/*
 * Send websocket frame to the remote end.
 *
 * Like `ns_send_websocket_frame()`, but allows to create formatted message
 * with `printf()`-like semantics.
 */
void ns_printf_websocket_frame(struct ns_connection *nc, int op,
                               const char *fmt, ...) {
  char mem[4192], *buf = mem;
  va_list ap;
  int len;

  va_start(ap, fmt);
  if ((len = ns_avprintf(&buf, sizeof(mem), fmt, ap)) > 0) {
    ns_send_websocket_frame(nc, op, buf, len);
  }
  va_end(ap);

  if (buf != mem && buf != NULL) {
    NS_FREE(buf);
  }
}

static void websocket_handler(struct ns_connection *nc, int ev, void *ev_data) {
  nc->handler(nc, ev, ev_data);

  switch (ev) {
    case NS_RECV:
      do { } while (deliver_websocket_data(nc));
      break;
    case NS_POLL:
      /* Ping idle websocket connections */
      {
        time_t now = * (time_t *) ev_data;
        if (nc->flags & NSF_IS_WEBSOCKET &&
            now > nc->last_io_time + NS_WEBSOCKET_PING_INTERVAL_SECONDS) {
          ns_send_websocket_frame(nc, WEBSOCKET_OP_PING, "", 0);
        }
      }
      break;
    default:
      break;
  }
}

static void ws_handshake(struct ns_connection *nc, const struct ns_str *key) {
  static const char *magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  char buf[500], sha[20], b64_sha[sizeof(sha) * 2];
  SHA1_CTX sha_ctx;

  snprintf(buf, sizeof(buf), "%.*s%s", (int) key->len, key->p, magic);

  SHA1Init(&sha_ctx);
  SHA1Update(&sha_ctx, (unsigned char *) buf, strlen(buf));
  SHA1Final((unsigned char *) sha, &sha_ctx);

  ns_base64_encode((unsigned char *) sha, sizeof(sha), b64_sha);
  ns_printf(nc, "%s%s%s",
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: ", b64_sha, "\r\n\r\n");
}

static void transfer_file_data(struct ns_connection *nc) {
  struct proto_data_http *dp = (struct proto_data_http *) nc->proto_data;
  struct iobuf *io = &nc->send_iobuf;
  char buf[NS_MAX_HTTP_SEND_IOBUF];
  size_t n;

  if (nc->send_iobuf.len >= NS_MAX_HTTP_SEND_IOBUF) {
    /* If output buffer is too big, do nothing until it's drained */
  } else if ((n = fread(buf, 1, sizeof(buf) - io->len, dp->fp)) > 0) {
    ns_send(nc, buf, n);
  } else {
    fclose(dp->fp);
    NS_FREE(dp);
    nc->proto_data = NULL;
  }
}

static void http_handler(struct ns_connection *nc, int ev, void *ev_data) {
  struct iobuf *io = &nc->recv_iobuf;
  struct http_message hm;
  struct ns_str *vec;
  int req_len;

  /*
   * For HTTP messages without Content-Length, always send HTTP message
   * before NS_CLOSE message.
   */
  if (ev == NS_CLOSE && io->len > 0 &&
      ns_parse_http(io->buf, io->len, &hm) > 0) {
    hm.message.len = io->len;
    hm.body.len = io->buf + io->len - hm.body.p;
    nc->handler(nc, nc->listener ? NS_HTTP_REQUEST : NS_HTTP_REPLY, &hm);
  }

  if (nc->proto_data != NULL) {
    transfer_file_data(nc);
  }

  nc->handler(nc, ev, ev_data);

  if (ev == NS_RECV) {
    req_len = ns_parse_http(io->buf, io->len, &hm);
    if (req_len < 0 || (req_len == 0 && io->len >= NS_MAX_HTTP_REQUEST_SIZE)) {
      nc->flags |= NSF_CLOSE_IMMEDIATELY;
    } else if (req_len == 0) {
      /* Do nothing, request is not yet fully buffered */
    } else if (nc->listener == NULL &&
               ns_get_http_header(&hm, "Sec-WebSocket-Accept")) {
      /* We're websocket client, got handshake response from server. */
      /* TODO(lsm): check the validity of accept Sec-WebSocket-Accept */
      iobuf_remove(io, req_len);
      nc->proto_handler = websocket_handler;
      nc->flags |= NSF_IS_WEBSOCKET;
      nc->handler(nc, NS_WEBSOCKET_HANDSHAKE_DONE, NULL);
      websocket_handler(nc, NS_RECV, ev_data);
    } else if (nc->listener != NULL &&
               (vec = ns_get_http_header(&hm, "Sec-WebSocket-Key")) != NULL) {
      /* This is a websocket request. Switch protocol handlers. */
      iobuf_remove(io, req_len);
      nc->proto_handler = websocket_handler;
      nc->flags |= NSF_IS_WEBSOCKET;

      /* Send handshake */
      nc->handler(nc, NS_WEBSOCKET_HANDSHAKE_REQUEST, &hm);
      if (!(nc->flags & NSF_CLOSE_IMMEDIATELY)) {
        if (nc->send_iobuf.len == 0) {
          ws_handshake(nc, vec);
        }
        nc->handler(nc, NS_WEBSOCKET_HANDSHAKE_DONE, NULL);
        websocket_handler(nc, NS_RECV, ev_data);
      }
    } else if (hm.message.len <= io->len) {
      /* Whole HTTP message is fully buffered, call event handler */
      nc->handler(nc, nc->listener ? NS_HTTP_REQUEST : NS_HTTP_REPLY, &hm);
      iobuf_remove(io, hm.message.len);
    }
  }
}

/*
 * Attach built-in HTTP event handler to the given connection.
 * User-defined event handler will receive following extra events:
 *
 * - NS_HTTP_REQUEST: HTTP request has arrived. Parsed HTTP request is passed as
 *   `struct http_message` through the handler's `void *ev_data` pointer.
 * - NS_HTTP_REPLY: HTTP reply has arrived. Parsed HTTP reply is passed as
 *   `struct http_message` through the handler's `void *ev_data` pointer.
 * - NS_WEBSOCKET_HANDSHAKE_REQUEST: server has received websocket handshake
 *   request. `ev_data` contains parsed HTTP request.
 * - NS_WEBSOCKET_HANDSHAKE_DONE: server has completed Websocket handshake.
 *   `ev_data` is `NULL`.
 * - NS_WEBSOCKET_FRAME: new websocket frame has arrived. `ev_data` is
 *   `struct websocket_message *`
 */
void ns_set_protocol_http_websocket(struct ns_connection *nc) {
  nc->proto_handler = http_handler;
}

/*
 * Sends websocket handshake to the server.
 *
 * `nc` must be a valid connection, connected to a server `uri` is an URI
 * to fetch, extra_headers` is extra HTTP headers to send or `NULL`.
 *
 * This function is intended to be used by websocket client.
 */
void ns_send_websocket_handshake(struct ns_connection *nc, const char *uri,
                                 const char *extra_headers) {
  unsigned long random = (unsigned long) uri;
  char key[sizeof(random) * 2];

  ns_base64_encode((unsigned char *) &random, sizeof(random), key);
  ns_printf(nc, "GET %s HTTP/1.1\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "Sec-WebSocket-Key: %s\r\n"
            "%s\r\n",
            uri, key, extra_headers == NULL ? "" : extra_headers);
}

static void send_http_error(struct ns_connection *nc, int code,
                            const char *reason) {
  ns_printf(nc, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n", code, reason);
}

void ns_send_http_file(struct ns_connection *nc, const char *path,
                       ns_stat_t *st) {
  struct proto_data_http *dp;

  if ((dp = (struct proto_data_http *) NS_CALLOC(1, sizeof(*dp))) == NULL) {
    send_http_error(nc, 500, "Server Error");  /* LCOV_EXCL_LINE */
  } else if ((dp->fp = fopen(path, "rb")) == NULL) {
    NS_FREE(dp);
    send_http_error(nc, 500, "Server Error");
  } else {
    ns_printf(nc, "HTTP/1.1 200 OK\r\n"
              "Content-Type: %s\r\n"
              "Content-Length: %lu\r\n\r\n",
              get_mime_type(path, "text/plain"),
              (unsigned long) st->st_size);
    nc->proto_data = (void *) dp;
    transfer_file_data(nc);
  }
}

static void remove_double_dots(char *s) {
  char *p = s;

  while (*s != '\0') {
    *p++ = *s++;
    if (s[-1] == '/' || s[-1] == '\\') {
      while (s[0] != '\0') {
        if (s[0] == '/' || s[0] == '\\') {
          s++;
        } else if (s[0] == '.' && s[1] == '.') {
          s += 2;
        } else {
          break;
        }
      }
    }
  }
  *p = '\0';
}

static int ns_url_decode(const char *src, int src_len, char *dst,
                         int dst_len, int is_form_url_encoded) {
  int i, j, a, b;
#define HEXTOI(x) (isdigit(x) ? x - '0' : x - 'W')

  for (i = j = 0; i < src_len && j < dst_len - 1; i++, j++) {
    if (src[i] == '%') {
      if (i < src_len - 2 &&
          isxdigit(* (const unsigned char *) (src + i + 1)) &&
          isxdigit(* (const unsigned char *) (src + i + 2))) {
        a = tolower(* (const unsigned char *) (src + i + 1));
        b = tolower(* (const unsigned char *) (src + i + 2));
        dst[j] = (char) ((HEXTOI(a) << 4) | HEXTOI(b));
        i += 2;
      } else {
        return -1;
      }
    } else if (is_form_url_encoded && src[i] == '+') {
      dst[j] = ' ';
    } else {
      dst[j] = src[i];
    }
  }

  dst[j] = '\0'; /* Null-terminate the destination */

  return i >= src_len ? j : -1;
}

/*
 * Fetch an HTTP form variable.
 *
 * Fetch a variable `name` from a `buf` into a buffer specified by
 * `dst`, `dst_len`. Destination is always zero-terminated. Return length
 * of a fetched variable. If not found, 0 is returned. `buf` must be
 * valid url-encoded buffer. If destination is too small, `-1` is returned.
 */
int ns_get_http_var(const struct ns_str *buf, const char *name,
                    char *dst, size_t dst_len) {
  const char *p, *e, *s;
  size_t name_len;
  int len;

  if (dst == NULL || dst_len == 0) {
    len = -2;
  } else if (buf->p == NULL || name == NULL || buf->len == 0) {
    len = -1;
    dst[0] = '\0';
  } else {
    name_len = strlen(name);
    e = buf->p + buf->len;
    len = -1;
    dst[0] = '\0';

    for (p = buf->p; p + name_len < e; p++) {
      if ((p == buf->p || p[-1] == '&') && p[name_len] == '=' &&
          !ns_ncasecmp(name, p, name_len)) {
        p += name_len + 1;
        s = (const char *) memchr(p, '&', (size_t)(e - p));
        if (s == NULL) {
          s = e;
        }
        len = ns_url_decode(p, (size_t)(s - p), dst, dst_len, 1);
        if (len == -1) {
          len = -2;
        }
        break;
      }
    }
  }

  return len;
}

/*
 * Send buffer `buf` of size `len` to the client using chunked HTTP encoding.
 * This function first sends buffer size as hex number + newline, then
 * buffer itself, then newline. For example,
 *   `ns_send_http_chunk(nc, "foo", 3)` whill append `3\r\nfoo\r\n` string to
 * the `nc->send_iobuf` output IO buffer.
 *
 * NOTE: HTTP header "Transfer-Encoding: chunked" should be sent prior to
 * using this function.
 *
 * NOTE: do not forget to send empty chunk at the end of the response,
 * to tell the client that everything was sent. Example:
 *
 * ```
 *   ns_printf_http_chunk(nc, "%s", "my response!");
 *   ns_send_http_chunk(nc, "", 0); // Tell the client we're finished
 * ```
 */
void ns_send_http_chunk(struct ns_connection *nc, const char *buf, size_t len) {
  char chunk_size[50];
  int n;

  n = snprintf(chunk_size, sizeof(chunk_size), "%lX\r\n", len);
  ns_send(nc, chunk_size, n);
  ns_send(nc, buf, len);
  ns_send(nc, "\r\n", 2);
}

/*
 * Send printf-formatted HTTP chunk.
 * Functionality is similar to `ns_send_http_chunk()`.
 */
void ns_printf_http_chunk(struct ns_connection *nc, const char *fmt, ...) {
  char mem[500], *buf = mem;
  int len;
  va_list ap;

  va_start(ap, fmt);
  len = ns_avprintf(&buf, sizeof(mem), fmt, ap);
  va_end(ap);

  if (len >= 0) {
    ns_send_http_chunk(nc, buf, len);
  }

  /* LCOV_EXCL_START */
  if (buf != mem && buf != NULL) {
    NS_FREE(buf);
  }
  /* LCOV_EXCL_STOP */
}

int ns_http_parse_header(struct ns_str *hdr, const char *var_name,
                         char *buf, size_t buf_size) {
  int ch = ' ', ch1 = ',', len = 0, n = strlen(var_name);
  const char *p, *end = hdr->p + hdr->len, *s = NULL;

  if (buf != NULL && buf_size > 0) buf[0] = '\0';

  /* Find where variable starts */
  for (s = hdr->p; s != NULL && s + n < end; s++) {
    if ((s == hdr->p || s[-1] == ch || s[-1] == ch1) && s[n] == '=' &&
        !memcmp(s, var_name, n)) break;
  }

  if (s != NULL && &s[n + 1] < end) {
    s += n + 1;
    if (*s == '"' || *s == '\'') {
      ch = ch1 = *s++;
    }
    p = s;
    while (p < end && p[0] != ch && p[0] != ch1 && len < (int) buf_size) {
      if (ch != ' ' && p[0] == '\\' && p[1] == ch) p++;
      buf[len++] = *p++;
    }
    if (len >= (int) buf_size || (ch != ' ' && *p != ch)) {
      len = 0;
    } else {
      if (len > 0 && s[len - 1] == ',') len--;
      if (len > 0 && s[len - 1] == ';') len--;
      buf[len] = '\0';
    }
  }

  return len;
}

#ifndef NS_DISABLE_HTTP_DIGEST_AUTH
static FILE *open_auth_file(const char *path, int is_directory,
                            const struct ns_serve_http_opts *opts) {
  char buf[MAX_PATH_SIZE];
  const char *p;
  FILE *fp = NULL;

  if (opts->global_auth_file != NULL) {
    fp = fopen(opts->global_auth_file, "r");
  } else if (is_directory && opts->per_directory_auth_file) {
    snprintf(buf, sizeof(buf), "%s%c%s", path, DIRSEP,
             opts->per_directory_auth_file);
    fp = fopen(buf, "r");
  } else if (opts->per_directory_auth_file) {
    if ((p = strrchr(path, DIRSEP)) == NULL) {
      p = path;
    }
    snprintf(buf, sizeof(buf), "%.*s%c%s",
             (int) (p - path), path, DIRSEP, opts->per_directory_auth_file);
    fp = fopen(buf, "r");
  }

  return fp;
}

/*
 * Stringify binary data. Output buffer size must be 2 * size_of_input + 1
 * because each byte of input takes 2 bytes in string representation
 * plus 1 byte for the terminating \0 character.
 */
static void bin2str(char *to, const unsigned char *p, size_t len) {
  static const char *hex = "0123456789abcdef";

  for (; len--; p++) {
    *to++ = hex[p[0] >> 4];
    *to++ = hex[p[0] & 0x0f];
  }
  *to = '\0';
}

static char *ns_md5(char *buf, ...) {
  unsigned char hash[16];
  const unsigned char *p;
  va_list ap;
  MD5_CTX ctx;

  MD5_Init(&ctx);

  va_start(ap, buf);
  while ((p = va_arg(ap, const unsigned char *)) != NULL) {
    size_t len = va_arg(ap, size_t);
    MD5_Update(&ctx, p, len);
  }
  va_end(ap);

  MD5_Final(hash, &ctx);
  bin2str(buf, hash, sizeof(hash));

  return buf;
}

static void mkmd5resp(const char *method, size_t method_len,
                      const char *uri, size_t uri_len,
                      const char *ha1, size_t ha1_len,
                      const char *nonce, size_t nonce_len,
                      const char *nc, size_t nc_len,
                      const char *cnonce, size_t cnonce_len,
                      const char *qop, size_t qop_len,
                      char *resp) {
  static const char colon[] = ":";
  static const size_t one = 1;
  char ha2[33];

  ns_md5(ha2, method, method_len, colon, one, uri, uri_len, NULL);
  ns_md5(resp, ha1, ha1_len, colon, one, nonce, nonce_len, colon, one,
         nc, nc_len, colon, one, cnonce, cnonce_len, colon, one, qop, qop_len,
         colon, one, ha2, sizeof(ha2) - 1, NULL);
}

/*
 * Create Digest authentication header for client request.
 */
int ns_http_create_digest_auth_header(char *buf, size_t buf_len,
                                      const char *method, const char *uri,
                                      const char *auth_domain,
                                      const char *user, const char *passwd) {
  static const char colon[] = ":", qop[] = "auth";
  static const size_t one = 1;
  char ha1[33], resp[33], cnonce[40];

  snprintf(cnonce, sizeof(cnonce), "%x", (unsigned int) time(NULL));
  ns_md5(ha1, user, (size_t) strlen(user), colon, one,
         auth_domain, (size_t) strlen(auth_domain), colon, one,
         passwd, (size_t) strlen(passwd), NULL);
  mkmd5resp(method, strlen(method), uri, strlen(uri), ha1, sizeof(ha1) - 1,
            cnonce, strlen(cnonce),
            "1", one, cnonce, strlen(cnonce), qop, sizeof(qop) - 1, resp);
  return snprintf(buf, buf_len, "Authorization: Digest username=\"%s\","
                  "realm=\"%s\",uri=\"%s\",qop=%s,nc=1,cnonce=%s,"
                  "nonce=%s,response=%s\r\n",
                  user, auth_domain, uri, qop, cnonce, cnonce, resp);
}

/*
 * Check for authentication timeout.
 * Clients send time stamp encoded in nonce. Make sure it is not too old,
 * to prevent replay attacks.
 * Assumption: nonce is a hexadecimal number of seconds since 1970.
 */
static int check_nonce(const char *nonce) {
  unsigned long now = (unsigned long) time(NULL);
  unsigned long val = (unsigned long) strtoul(nonce, NULL, 16);
  return 1 || now < val || now - val < 3600;
}

/*
 * Authenticate HTTP request against opened passwords file.
 * Returns 1 if authenticated, 0 otherwise.
 */
static int ns_http_check_digest_auth(struct http_message *hm,
                                     const char *auth_domain,
                                     FILE *fp) {
  struct ns_str *hdr;
  char buf[128], f_user[sizeof(buf)], f_ha1[sizeof(buf)], f_domain[sizeof(buf)];
  char user[50], cnonce[20], response[40], uri[200], qop[20], nc[20], nonce[30];
  char expected_response[33];

  /* Parse "Authorization:" header, fail fast on parse error */
  if (hm == NULL ||
      fp == NULL ||
      (hdr = ns_get_http_header(hm, "Authorization")) == NULL ||
      ns_http_parse_header(hdr, "username", user, sizeof(user)) == 0 ||
      ns_http_parse_header(hdr, "cnonce", cnonce, sizeof(cnonce)) == 0 ||
      ns_http_parse_header(hdr, "response", response, sizeof(response)) == 0 ||
      ns_http_parse_header(hdr, "uri", uri, sizeof(uri)) == 0 ||
      ns_http_parse_header(hdr, "qop", qop, sizeof(qop)) == 0 ||
      ns_http_parse_header(hdr, "nc", nc, sizeof(nc)) == 0 ||
      ns_http_parse_header(hdr, "nonce", nonce, sizeof(nonce)) == 0 ||
      check_nonce(nonce) == 0) {
    return 0;
  }

  /*
   * Read passwords file line by line. If should have htdigest format,
   * i.e. each line should be a colon-separated sequence:
   * USER_NAME:DOMAIN_NAME:HA1_HASH_OF_USER_DOMAIN_AND_PASSWORD
   */
  while (fgets(buf, sizeof(buf), fp) != NULL) {
    if (sscanf(buf, "%[^:]:%[^:]:%s", f_user, f_domain, f_ha1) == 3 &&
        strcmp(user, f_user) == 0 &&
        /* NOTE(lsm): due to a bug in MSIE, we do not compare URIs */
        strcmp(auth_domain, f_domain) == 0) {
      /* User and domain matched, check the password */
      mkmd5resp(hm->method.p, hm->method.len, hm->uri.p, hm->uri.len,
             f_ha1, strlen(f_ha1), nonce, strlen(nonce), nc, strlen(nc),
             cnonce, strlen(cnonce), qop, strlen(qop), expected_response);
      return ns_casecmp(response, expected_response) == 0;
    }
  }

  /* None of the entries in the passwords file matched - return failure */
  return 0;
}

static int is_authorized(struct http_message *hm, const char *path,
                         int is_directory, struct ns_serve_http_opts *opts) {
  FILE *fp;
  int authorized = 1;

  if (opts->auth_domain != NULL &&
      (opts->per_directory_auth_file != NULL ||
       opts->global_auth_file != NULL) &&
      (fp = open_auth_file(path, is_directory, opts)) != NULL) {
    authorized = ns_http_check_digest_auth(hm, opts->auth_domain, fp);
    fclose(fp);
  }

  return authorized;
}
#else
static int is_authorized(struct http_message *hm, const char *path,
                         int is_directory, struct ns_serve_http_opts *opts) {
  (void) hm; (void) path; (void) is_directory; (void) opts;
  return 1;
}
#endif

/*
 * Serve given HTTP request according to the `options`.
 *
 * Example code snippet:
 *
 * [source,c]
 * .web_server.c
 * ----
 * static void ev_handler(struct ns_connection *nc, int ev, void *ev_data) {
 *   struct http_message *hm = (struct http_message *) ev_data;
 *   struct ns_serve_http_opts opts = { .document_root = "/var/www" };  // C99 syntax
 *
 *   switch (ev) {
 *     case NS_HTTP_REQUEST:
 *       ns_serve_http(nc, hm, opts);
 *       break;
 *     default:
 *       break;
 *   }
 * }
 * ----
 */
void ns_serve_http(struct ns_connection *nc, struct http_message *hm,
                   struct ns_serve_http_opts opts) {
  char path[NS_MAX_PATH];
  ns_stat_t st;
  int stat_result, is_directory;

  snprintf(path, sizeof(path), "%s/%.*s", opts.document_root,
           (int) hm->uri.len, hm->uri.p);
  remove_double_dots(path);
  stat_result = ns_stat(path, &st);
  is_directory = !stat_result && S_ISDIR(st.st_mode);

  if (!is_authorized(hm, path, is_directory, &opts)) {
    ns_printf(nc, "HTTP/1.1 401 Unauthorized\r\n"
              "WWW-Authenticate: Digest qop=\"auth\", "
              "realm=\"%s\", nonce=\"%lu\"\r\n"
              "Content-Length: 0\r\n\r\n",
              opts.auth_domain, (unsigned long) time(NULL));
  } else if (stat_result != 0) {
    ns_printf(nc, "%s", "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
  } else if (S_ISDIR(st.st_mode)) {
    strncat(path, "/index.html", sizeof(path) - (strlen(path) + 1));
    if (ns_stat(path, &st) == 0) {
      ns_send_http_file(nc, path, &st);
    } else {
      ns_printf(nc, "%s", "HTTP/1.1 403 Access Denied\r\n"
                "Content-Length: 0\r\n\r\n");
    }
  } else {
    ns_send_http_file(nc, path, &st);
  }
}

/*
 * Helper function that creates outbound HTTP connection.
 *
 * If `post_data` is NULL, then GET request is created. Otherwise, POST request
 * is created with the specified POST data. Examples:
 *
 * [source,c]
 * ----
 *   nc1 = ns_connect_http(mgr, ev_handler_1, "http://www.google.com", NULL);
 *   nc2 = ns_connect_http(mgr, ev_handler_1, "https://github.com", NULL);
 *   nc3 = ns_connect_http(mgr, ev_handler_1, "my_server:8000/form_submit/",
 *                         "var_1=value_1&var_2=value_2");
 * ----
 */
struct ns_connection *ns_connect_http(struct ns_mgr *mgr,
                                      ns_event_handler_t ev_handler,
                                      const char *url,
                                      const char *extra_headers,
                                      const char *post_data) {
  struct ns_connection *nc;
  char addr[1100], path[4096];  /* NOTE: keep sizes in sync with sscanf below */
  int use_ssl = 0;

  if (memcmp(url, "http://", 7) == 0) {
    url += 7;
  } else if (memcmp(url, "https://", 8) == 0) {
    url += 8;
    use_ssl = 1;
#ifndef NS_ENABLE_SSL
    return NULL;  /* SSL is not enabled, cannot do HTTPS URLs */
#endif
  }

  addr[0] = path[0] = '\0';

  /* addr buffer size made smaller to allow for port to be prepended */
  sscanf(url, "%1095[^/]/%4095s", addr, path);
  if (strchr(addr, ':') == NULL) {
    strncat(addr, use_ssl ? ":443" : ":80",
            sizeof(addr) - (strlen(addr) + 1));
  }

  if ((nc = ns_connect(mgr, addr, ev_handler)) != NULL) {
    ns_set_protocol_http_websocket(nc);

    if (use_ssl) {
  #ifdef NS_ENABLE_SSL
      ns_set_ssl(nc, NULL, NULL);
  #endif
    }

    ns_printf(nc, "%s /%s HTTP/1.1\r\nHost: %s\r\nContent-Length: %lu\r\n%s\r\n",
              post_data == NULL ? "GET" : "POST", path, addr,
              post_data == NULL ? 0 : strlen(post_data),
              extra_headers == NULL ? "" : extra_headers);
  }

  return nc;
}

#endif  /* NS_DISABLE_HTTP_WEBSOCKET */
#ifdef NS_MODULE_LINES
#line 1 "modules/sha1.c"
/**/
#endif
/* Copyright(c) By Steve Reid <steve@edmweb.com> */
/* 100% Public Domain */

#ifndef NS_DISABLE_SHA1


static int is_big_endian(void) {
  static const int n = 1;
  return ((char *) &n)[0] == 0;
}

#define SHA1HANDSOFF
#if defined(__sun)
#endif

union char64long16 { unsigned char c[64]; uint32_t l[16]; };

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

static uint32_t blk0(union char64long16 *block, int i) {
  /* Forrest: SHA expect BIG_ENDIAN, swap if LITTLE_ENDIAN */
  if (!is_big_endian()) {
    block->l[i] = (rol(block->l[i], 24) & 0xFF00FF00) |
      (rol(block->l[i], 8) & 0x00FF00FF);
  }
  return block->l[i];
}

/* Avoid redefine warning (ARM /usr/include/sys/ucontext.h define R0~R4) */
#undef blk
#undef R0
#undef R1
#undef R2
#undef R3
#undef R4

#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
    ^block->l[(i+2)&15]^block->l[i&15],1))
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(block, i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);

void SHA1Transform(uint32_t state[5], const unsigned char buffer[64]) {
  uint32_t a, b, c, d, e;
  union char64long16 block[1];

  memcpy(block, buffer, 64);
  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];
  R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
  R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
  R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
  R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
  R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
  R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
  R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
  R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
  R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
  R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
  R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
  R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
  R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
  R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
  R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
  R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
  R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
  R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
  R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
  R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  /* Erase working structures. The order of operations is important, 
   * used to ensure that compiler doesn't optimize those out. */
  memset(block, 0, sizeof(block));
  a = b = c = d = e = 0;
  (void) a; (void) b; (void) c; (void) d; (void) e;
}

void SHA1Init(SHA1_CTX *context) {
  context->state[0] = 0x67452301;
  context->state[1] = 0xEFCDAB89;
  context->state[2] = 0x98BADCFE;
  context->state[3] = 0x10325476;
  context->state[4] = 0xC3D2E1F0;
  context->count[0] = context->count[1] = 0;
}

void SHA1Update(SHA1_CTX *context, const unsigned char *data, uint32_t len) {
  uint32_t i, j;

  j = context->count[0];
  if ((context->count[0] += len << 3) < j)
    context->count[1]++;
  context->count[1] += (len>>29);
  j = (j >> 3) & 63;
  if ((j + len) > 63) {
    memcpy(&context->buffer[j], data, (i = 64-j));
    SHA1Transform(context->state, context->buffer);
    for ( ; i + 63 < len; i += 64) {
      SHA1Transform(context->state, &data[i]);
    }
    j = 0;
  }
  else i = 0;
  memcpy(&context->buffer[j], &data[i], len - i);
}

void SHA1Final(unsigned char digest[20], SHA1_CTX *context) {
  unsigned i;
  unsigned char finalcount[8], c;

  for (i = 0; i < 8; i++) {
    finalcount[i] = (unsigned char)((context->count[(i >= 4 ? 0 : 1)]
                                     >> ((3-(i & 3)) * 8) ) & 255);
  }
  c = 0200;
  SHA1Update(context, &c, 1);
  while ((context->count[0] & 504) != 448) {
    c = 0000;
    SHA1Update(context, &c, 1);
  }
  SHA1Update(context, finalcount, 8);
  for (i = 0; i < 20; i++) {
    digest[i] = (unsigned char)
      ((context->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
  }
  memset(context, '\0', sizeof(*context));
  memset(&finalcount, '\0', sizeof(finalcount));
}
#endif  /* NS_DISABLE_SHA1 */
#ifdef NS_MODULE_LINES
#line 1 "modules/util.c"
/**/
#endif
/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

/*
 * == Utilities
 */


/*
 * Fetches substring from input string `s`, `end` into `v`.
 * Skips initial delimiter characters. Records first non-delimiter character
 * as the beginning of substring `v`. Then scans the rest of the string
 * until a delimiter character or end-of-string is found.
 *
 * do_not_export_to_docs
 */
const char *ns_skip(const char *s, const char *end,
                    const char *delims, struct ns_str *v) {
  v->p = s;
  while (s < end && strchr(delims, * (unsigned char *) s) == NULL) s++;
  v->len = s - v->p;
  while (s < end && strchr(delims, * (unsigned char *) s) != NULL) s++;
  return s;
}

static int lowercase(const char *s) {
  return tolower(* (const unsigned char *) s);
}

/*
 * Cross-platform version of `strncasecmp()`.
 */
int ns_ncasecmp(const char *s1, const char *s2, size_t len) {
  int diff = 0;

  if (len > 0)
    do {
      diff = lowercase(s1++) - lowercase(s2++);
    } while (diff == 0 && s1[-1] != '\0' && --len > 0);

  return diff;
}

/*
 * Cross-platform version of `strcasecmp()`.
 */
int ns_casecmp(const char *s1, const char *s2) {
  return ns_ncasecmp(s1, s2, (size_t) ~0);
}

/*
 * Cross-platform version of `strncasecmp()` where first string is
 * specified by `struct ns_str`.
 */
int ns_vcasecmp(const struct ns_str *str2, const char *str1) {
  size_t n1 = strlen(str1), n2 = str2->len;
  return n1 == n2 ? ns_ncasecmp(str1, str2->p, n1) : n1 > n2 ? 1 : -1;
}

/*
 * Cross-platform version of `strcmp()` where where first string is
 * specified by `struct ns_str`.
 */
int ns_vcmp(const struct ns_str *str2, const char *str1) {
  size_t n1 = strlen(str1), n2 = str2->len;
  return n1 == n2 ? memcmp(str1, str2->p, n2) : n1 > n2 ? 1 : -1;
}

#ifdef _WIN32
static void to_wchar(const char *path, wchar_t *wbuf, size_t wbuf_len) {
  char buf[MAX_PATH_SIZE * 2], buf2[MAX_PATH_SIZE * 2], *p;

  strncpy(buf, path, sizeof(buf));
  buf[sizeof(buf) - 1] = '\0';

  /* Trim trailing slashes. Leave backslash for paths like "X:\" */
  p = buf + strlen(buf) - 1;
  while (p > buf && p[-1] != ':' && (p[0] == '\\' || p[0] == '/')) *p-- = '\0';

  /*
   * Convert to Unicode and back. If doubly-converted string does not
   * match the original, something is fishy, reject.
   */
  memset(wbuf, 0, wbuf_len * sizeof(wchar_t));
  MultiByteToWideChar(CP_UTF8, 0, buf, -1, wbuf, (int) wbuf_len);
  WideCharToMultiByte(CP_UTF8, 0, wbuf, (int) wbuf_len, buf2, sizeof(buf2),
                      NULL, NULL);
  if (strcmp(buf, buf2) != 0) {
    wbuf[0] = L'\0';
  }
}
#endif  /* _WIN32 */

/*
 * Perform a 64-bit `stat()` call against given file.
 *
 * `path` should be UTF8 encoded.
 *
 * Return value is the same as for `stat()` syscall.
 */
int ns_stat(const char *path, ns_stat_t *st) {
#ifdef _WIN32
  wchar_t wpath[MAX_PATH_SIZE];
  to_wchar(path, wpath, ARRAY_SIZE(wpath));
  DBG(("[%ls] -> %d", wpath, _wstati64(wpath, st)));
  return _wstati64(wpath, st);
#else
  return stat(path, st);
#endif
}

/*
 * Open the given file and return a file stream.
 *
 * `path` and `mode` should be UTF8 encoded.
 *
 * Return value is the same as for the `fopen()` call.
 */
FILE *ns_fopen(const char *path, const char *mode) {
#ifdef _WIN32
  wchar_t wpath[MAX_PATH_SIZE], wmode[10];
  to_wchar(path, wpath, ARRAY_SIZE(wpath));
  to_wchar(mode, wmode, ARRAY_SIZE(wmode));
  return _wfopen(wpath, wmode);
#else
  return fopen(path, mode);
#endif
}

/*
 * Open the given file and return a file stream.
 *
 * `path` should be UTF8 encoded.
 *
 * Return value is the same as for the `open()` syscall.
 */
int ns_open(const char *path, int flag, int mode) { /* LCOV_EXCL_LINE */
#ifdef _WIN32
  wchar_t wpath[MAX_PATH_SIZE];
  to_wchar(path, wpath, ARRAY_SIZE(wpath));
  return _wopen(wpath, flag, mode);
#else
  return open(path, flag, mode);  /* LCOV_EXCL_LINE */
#endif
}

/*
 * Base64-encodes chunk of memory `src`, `src_len` into the destination `dst`.
 * Destination has to have enough space to hold encoded buffer.
 * Destination is '\0'-terminated.
 */
void ns_base64_encode(const unsigned char *src, int src_len, char *dst) {
  static const char *b64 =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  int i, j, a, b, c;

  for (i = j = 0; i < src_len; i += 3) {
    a = src[i];
    b = i + 1 >= src_len ? 0 : src[i + 1];
    c = i + 2 >= src_len ? 0 : src[i + 2];

    dst[j++] = b64[a >> 2];
    dst[j++] = b64[((a & 3) << 4) | (b >> 4)];
    if (i + 1 < src_len) {
      dst[j++] = b64[(b & 15) << 2 | (c >> 6)];
    }
    if (i + 2 < src_len) {
      dst[j++] = b64[c & 63];
    }
  }
  while (j % 4 != 0) {
    dst[j++] = '=';
  }
  dst[j++] = '\0';
}

/* Convert one byte of encoded base64 input stream to 6-bit chunk */
static unsigned char from_b64(unsigned char ch) {
  /* Inverse lookup map */
  static const unsigned char tab[128] = {
    255, 255, 255, 255, 255, 255, 255, 255, /*  0 */
    255, 255, 255, 255, 255, 255, 255, 255, /*  8 */
    255, 255, 255, 255, 255, 255, 255, 255, /*  16 */
    255, 255, 255, 255, 255, 255, 255, 255, /*  24 */
    255, 255, 255, 255, 255, 255, 255, 255, /*  32 */
    255, 255, 255,  62, 255, 255, 255,  63, /*  40 */
     52,  53,  54,  55,  56,  57,  58,  59, /*  48 */
     60,  61, 255, 255, 255, 200, 255, 255, /*  56   '=' is 200, on index 61 */
    255,   0,   1,   2,   3,   4,   5,   6, /*  64 */
      7,   8,   9,  10,  11,  12,  13,  14, /*  72 */
     15,  16,  17,  18,  19,  20,  21,  22, /*  80 */
     23,  24,  25, 255, 255, 255, 255, 255, /*  88 */
    255,  26,  27,  28,  29,  30,  31,  32, /*  96 */
     33,  34,  35,  36,  37,  38,  39,  40, /*  104 */
     41,  42,  43,  44,  45,  46,  47,  48, /*  112 */
     49,  50,  51, 255, 255, 255, 255, 255, /*  120 */
  };
  return tab[ch & 127];
}

/*
 * Decodes base64-encoded string `s`, `len` into the destination `dst`.
 * Destination has to have enough space to hold decoded buffer.
 * Destination is '\0'-terminated.
 */
void ns_base64_decode(const unsigned char *s, int len, char *dst) {
  unsigned char a, b, c, d;
  while (len >= 4 &&
         (a = from_b64(s[0])) != 255 &&
         (b = from_b64(s[1])) != 255 &&
         (c = from_b64(s[2])) != 255 &&
         (d = from_b64(s[3])) != 255) {
    if (a == 200 || b == 200) break;  /* '=' can't be there */
    *dst++ = a << 2 | b >> 4;
    if (c == 200) break;
    *dst++ = b << 4 | c >> 2;
    if (d == 200) break;
    *dst++ = c << 6 | d;
    s += 4;
    len -=4;
  }
  *dst = 0;
}

#ifdef NS_ENABLE_THREADS
/* Starts a new thread. */
void *ns_start_thread(void *(*f)(void *), void *p) {
#ifdef _WIN32
  return (void *) _beginthread((void (__cdecl *)(void *)) f, 0, p);
#else
  pthread_t thread_id = (pthread_t) 0;
  pthread_attr_t attr;

  (void) pthread_attr_init(&attr);
  (void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

#if defined(NS_STACK_SIZE) && NS_STACK_SIZE > 1
  (void) pthread_attr_setstacksize(&attr, NS_STACK_SIZE);
#endif

  pthread_create(&thread_id, &attr, f, p);
  pthread_attr_destroy(&attr);

  return (void *) thread_id;
#endif
}
#endif  /* NS_ENABLE_THREADS */

/* Set close-on-exec bit for a given socket. */
void ns_set_close_on_exec(sock_t sock) {
#ifdef _WIN32
  (void) SetHandleInformation((HANDLE) sock, HANDLE_FLAG_INHERIT, 0);
#else
  fcntl(sock, F_SETFD, FD_CLOEXEC);
#endif
}

/*
 * Converts socket's local or remote address into string.
 *
 * The `flags` parameter is a bit mask that controls the behavior.
 * If bit 2 is set (`flags & 4`) then the remote address is stringified,
 * otherwise local address is stringified. If bit 0 is set, then IP
 * address is printed. If bit 1 is set, then port number is printed. If both
 * port number and IP address are printed, they are separated by `:`.
 */
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
      /* Only Windoze Vista (and newer) have inet_ntop() */
      strncpy(buf, inet_ntoa(sa.sin.sin_addr), len);
#else
      inet_ntop(sa.sa.sa_family, (void *) &sa.sin.sin_addr, buf,
                (socklen_t)len);
#endif
    }
    if (flags & 2) {
      snprintf(buf + strlen(buf), len - (strlen(buf) + 1), "%s%d",
               flags & 1 ? ":" : "", (int) ntohs(sa.sin.sin_port));
    }
  }
}

/*
 * Generates hexdump of memory chunk.
 *
 * Takes a memory buffer `buf` of length `len` and creates a hex dump of that
 * buffer in `dst`.
 */
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

/*
 * Print message to buffer. If buffer is large enough to hold the message,
 * return buffer. If buffer is to small, allocate large enough buffer on heap,
 * and return allocated buffer.
 */
int ns_avprintf(char **buf, size_t size, const char *fmt, va_list ap) {
  va_list ap_copy;
  int len;

  va_copy(ap_copy, ap);
  len = vsnprintf(*buf, size, fmt, ap_copy);
  va_end(ap_copy);

  if (len < 0) {
    /* eCos and Windows are not standard-compliant and return -1 when
     * the buffer is too small. Keep allocating larger buffers until we
     * succeed or out of memory. */
    *buf = NULL;  /* LCOV_EXCL_START */
    while (len < 0) {
      NS_FREE(*buf);
      size *= 2;
      if ((*buf = (char *) NS_MALLOC(size)) == NULL) break;
      va_copy(ap_copy, ap);
      len = vsnprintf(*buf, size, fmt, ap_copy);
      va_end(ap_copy);
    }
    /* LCOV_EXCL_STOP */
  } else if (len > (int) size) {
    /* Standard-compliant code path. Allocate a buffer that is large enough. */
    if ((*buf = (char *) NS_MALLOC(len + 1)) == NULL) {
      len = -1;  /* LCOV_EXCL_LINE */
    } else {     /* LCOV_EXCL_LINE */
      va_copy(ap_copy, ap);
      len = vsnprintf(*buf, len + 1, fmt, ap_copy);
      va_end(ap_copy);
    }
  }

  return len;
}

void ns_hexdump_connection(struct ns_connection *nc, const char *path,
                           int num_bytes, int ev) {
  const struct iobuf *io = ev == NS_SEND ? &nc->send_iobuf : &nc->recv_iobuf;
  FILE *fp;
  char *buf, src[60], dst[60];
  int buf_size = num_bytes * 5 + 100;

  if ((fp = fopen(path, "a")) != NULL) {
    ns_sock_to_str(nc->sock, src, sizeof(src), 3);
    ns_sock_to_str(nc->sock, dst, sizeof(dst), 7);
    fprintf(fp, "%lu %p %s %s %s %d\n", (unsigned long) time(NULL),
            nc->user_data, src,
            ev == NS_RECV ? "<-" : ev == NS_SEND ? "->" :
            ev == NS_ACCEPT ? "<A" : ev == NS_CONNECT ? "C>" : "XX",
            dst, num_bytes);
    if (num_bytes > 0 && (buf = (char *) NS_MALLOC(buf_size)) != NULL) {
      ns_hexdump(io->buf + (ev == NS_SEND ? 0 : io->len) -
                 (ev == NS_SEND ? 0 : num_bytes), num_bytes, buf, buf_size);
      fprintf(fp, "%s", buf);
      NS_FREE(buf);
    }
    fclose(fp);
  }
}
#ifdef NS_MODULE_LINES
#line 1 "modules/json-rpc.c"
/**/
#endif
/* Copyright (c) 2014 Cesanta Software Limited */
/* All rights reserved */

/*
 * == JSON-RPC
 */

#ifndef NS_DISABLE_JSON_RPC


/*
 * Create JSON-RPC reply in a given buffer.
 *
 * Return length of the reply, which
 * can be larger then `len` that indicates an overflow.
 */
int ns_rpc_create_reply(char *buf, int len, const struct ns_rpc_request *req,
                        const char *result_fmt, ...) {
  static const struct json_token null_tok = { "null", 4, 0, JSON_TYPE_NULL };
  const struct json_token *id = req->id == NULL ? &null_tok : req->id;
  va_list ap;
  int n = 0;

  n += json_emit(buf + n, len - n, "{s:s,s:", "jsonrpc", "2.0", "id");
  if (id->type == JSON_TYPE_STRING) {
    n += json_emit_quoted_str(buf + n, len - n, id->ptr, id->len);
  } else {
    n += json_emit_unquoted_str(buf + n, len - n, id->ptr, id->len);
  }
  n += json_emit(buf + n, len - n, ",s:", "result");

  va_start(ap, result_fmt);
  n += json_emit_va(buf + n, len - n, result_fmt, ap);
  va_end(ap);

  n += json_emit(buf + n, len - n, "}");

  return n;
}

/*
 * Create JSON-RPC request in a given buffer.
 *
 * Return length of the request, which
 * can be larger then `len` that indicates an overflow.
 */
int ns_rpc_create_request(char *buf, int len, const char *method,
                          const char *id, const char *params_fmt, ...) {
  va_list ap;
  int n = 0;

  n += json_emit(buf + n, len - n, "{s:s,s:s,s:s,s:",
                 "jsonrpc", "2.0", "id", id, "method", method, "params");
  va_start(ap, params_fmt);
  n += json_emit_va(buf + n, len - n, params_fmt, ap);
  va_end(ap);

  n += json_emit(buf + n, len - n, "}");

  return n;
}

/*
 * Create JSON-RPC error reply in a given buffer.
 *
 * Return length of the error, which
 * can be larger then `len` that indicates an overflow.
 */
int ns_rpc_create_error(char *buf, int len, struct ns_rpc_request *req,
                        int code, const char *message, const char *fmt, ...) {
  va_list ap;
  int n = 0;

  n += json_emit(buf + n, len - n, "{s:s,s:V,s:{s:i,s:s,s:",
                 "jsonrpc", "2.0", "id",
                 req->id == NULL ? "null" : req->id->ptr,
                 req->id == NULL ? 4 : req->id->len,
                 "error", "code", code,
                 "message", message, "data");
  va_start(ap, fmt);
  n += json_emit_va(buf + n, len - n, fmt, ap);
  va_end(ap);

  n += json_emit(buf + n, len - n, "}}");

  return n;
}

/*
 * Create JSON-RPC error in a given buffer.
 *
 * Return length of the error, which
 * can be larger then `len` that indicates an overflow. `code` could be one of:
 * `JSON_RPC_PARSE_ERROR`, `JSON_RPC_INVALID_REQUEST_ERROR`,
 * `JSON_RPC_METHOD_NOT_FOUND_ERROR`, `JSON_RPC_INVALID_PARAMS_ERROR`,
 * `JSON_RPC_INTERNAL_ERROR`, `JSON_RPC_SERVER_ERROR`.
 */
int ns_rpc_create_std_error(char *buf, int len, struct ns_rpc_request *req,
                            int code) {
  const char *message = NULL;

  switch (code) {
    case JSON_RPC_PARSE_ERROR: message = "parse error"; break;
    case JSON_RPC_INVALID_REQUEST_ERROR: message = "invalid request"; break;
    case JSON_RPC_METHOD_NOT_FOUND_ERROR: message = "method not found"; break;
    case JSON_RPC_INVALID_PARAMS_ERROR: message = "invalid parameters"; break;
    case JSON_RPC_SERVER_ERROR: message = "server error"; break;
    default: message = "unspecified error"; break;
  }

  return ns_rpc_create_error(buf, len, req, code, message, "N");
}

/*
 * Dispatches a JSON-RPC request.
 *
 * Parses JSON-RPC request contained in `buf`, `len`. Then, dispatches the request
 * to the correct handler method. Valid method names should be specified in NULL
 * terminated array `methods`, and corresponding handlers in `handlers`.
 * Result is put in `dst`, `dst_len`. Return: length of the result, which
 * can be larger then `dst_len` that indicates an overflow.
 */
int ns_rpc_dispatch(const char *buf, int len, char *dst, int dst_len,
                    const char **methods, ns_rpc_handler_t *handlers) {
  struct json_token tokens[200];
  struct ns_rpc_request req;
  int i, n;

  memset(&req, 0, sizeof(req));
  n = parse_json(buf, len, tokens, sizeof(tokens) / sizeof(tokens[0]));
  if (n <= 0) {
    int err_code = (n == JSON_STRING_INVALID) ?
                   JSON_RPC_PARSE_ERROR : JSON_RPC_SERVER_ERROR;
    return ns_rpc_create_std_error(dst, dst_len, &req, err_code);
  }

  req.message = tokens;
  req.id = find_json_token(tokens, "id");
  req.method = find_json_token(tokens, "method");
  req.params = find_json_token(tokens, "params");

  if (req.id == NULL || req.method == NULL) {
    return ns_rpc_create_std_error(dst, dst_len, &req,
                                   JSON_RPC_INVALID_REQUEST_ERROR);
  }

  for (i = 0; methods[i] != NULL; i++) {
    int mlen = strlen(methods[i]);
    if (mlen == req.method->len &&
        memcmp(methods[i], req.method->ptr, mlen) == 0) break;
  }

  if (methods[i] == NULL) {
    return ns_rpc_create_std_error(dst, dst_len, &req,
                                   JSON_RPC_METHOD_NOT_FOUND_ERROR);
  }

  return handlers[i](dst, dst_len, &req);
}

/*
 * Parse JSON-RPC reply contained in `buf`, `len` into JSON tokens array
 * `toks`, `max_toks`. If buffer contains valid reply, `reply` structure is
 * populated. The result of RPC call is located in `reply.result`. On error,
 * `error` structure is populated. Returns: the result of calling
 * `parse_json(buf, len, toks, max_toks)`.
 */
int ns_rpc_parse_reply(const char *buf, int len,
                       struct json_token *toks, int max_toks,
                       struct ns_rpc_reply *rep, struct ns_rpc_error *er) {
  int n = parse_json(buf, len, toks, max_toks);

  memset(rep, 0, sizeof(*rep));
  memset(er, 0, sizeof(*er));

  if (n > 0) {
    if ((rep->result = find_json_token(toks, "result")) != NULL) {
      rep->message = toks;
      rep->id = find_json_token(toks, "id");
    } else {
      er->message = toks;
      er->id = find_json_token(toks, "id");
      er->error_code = find_json_token(toks, "error.code");
      er->error_message = find_json_token(toks, "error.message");
      er->error_data = find_json_token(toks, "error.data");
    }
  }
  return n;
}

#endif  /* NS_DISABLE_JSON_RPC */
#ifdef NS_MODULE_LINES
#line 1 "modules/mqtt.c"
/**/
#endif
/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

/*
 * == MQTT
 */

#ifndef NS_DISABLE_MQTT


static int parse_mqtt(struct iobuf *io, struct ns_mqtt_message *mm) {
  uint8_t header;
  int cmd;
  size_t len = 0;
  int var_len = 0;
  char *vlen = &io->buf[1];

  if (io->len < 2) return -1;

  header = io->buf[0];
  cmd = header >> 4;

  /* decode mqtt variable length */
  do {
    len += (*vlen & 127) << 7 * (vlen - &io->buf[1]);
  } while ((*vlen++ & 128) != 0 && ((size_t)(vlen - io->buf) <= io->len));

  if (io->len < (size_t)(len - 1)) return -1;

  iobuf_remove(io, 1 + (vlen - &io->buf[1]));
  mm->cmd = cmd;
  mm->qos = NS_MQTT_GET_QOS(header);

  switch (cmd) {
    case NS_MQTT_CMD_CONNECT:
      /* TODO(mkm): parse keepalive and will */
      break;
    case NS_MQTT_CMD_CONNACK:
      mm->connack_ret_code = io->buf[1];
      var_len = 2;
      break;
    case NS_MQTT_CMD_PUBACK:
    case NS_MQTT_CMD_PUBREC:
    case NS_MQTT_CMD_PUBREL:
    case NS_MQTT_CMD_PUBCOMP:
    case NS_MQTT_CMD_SUBACK:
      mm->message_id = ntohs(*(uint16_t*)io->buf);
      var_len = 2;
      break;
    case NS_MQTT_CMD_PUBLISH:
      {
        uint16_t topic_len = ntohs(*(uint16_t*)io->buf);
        mm->topic = (char *) NS_MALLOC(topic_len + 1);
        mm->topic[topic_len] = 0;
        strncpy(mm->topic, io->buf + 2, topic_len);
        var_len = topic_len + 2;

        if (NS_MQTT_GET_QOS(header) > 0) {
          mm->message_id = ntohs(*(uint16_t*)io->buf);
          var_len += 2;
        }
      }
      break;
    case NS_MQTT_CMD_SUBSCRIBE:
      /*
       * topic expressions are left in the payload and can be parsed with
       * `ns_mqtt_next_subscribe_topic`
       */
      mm->message_id = ntohs(* (uint16_t *) io->buf);
      var_len = 2;
      break;
    default:
      printf("TODO: UNHANDLED COMMAND %d\n", cmd);
      break;
  }

  iobuf_remove(io, var_len);
  return len - var_len;
}

static void mqtt_handler(struct ns_connection *nc, int ev, void *ev_data) {
  int len;
  struct iobuf *io = &nc->recv_iobuf;
  struct ns_mqtt_message mm;
  memset(&mm, 0, sizeof(mm));

  nc->handler(nc, ev, ev_data);

  switch (ev) {
    case NS_RECV:
      len = parse_mqtt(io, &mm);
      if (len == -1) break; /* not fully buffered */
      mm.payload.p = io->buf;
      mm.payload.len = len;

      nc->handler(nc, NS_MQTT_EVENT_BASE + mm.cmd, &mm);

      if (mm.topic) {
        NS_FREE(mm.topic);
      }
      iobuf_remove(io, mm.payload.len);
      break;
  }
}

/*
 * Attach built-in MQTT event handler to the given connection.
 *
 * The user-defined event handler will receive following extra events:
 *
 * - NS_MQTT_CONNACK
 * - NS_MQTT_PUBLISH
 * - NS_MQTT_PUBACK
 * - NS_MQTT_PUBREC
 * - NS_MQTT_PUBREL
 * - NS_MQTT_PUBCOMP
 * - NS_MQTT_SUBACK
 */
void ns_set_protocol_mqtt(struct ns_connection *nc) {
  nc->proto_handler = mqtt_handler;
}

/* Send MQTT handshake. */
void ns_send_mqtt_handshake(struct ns_connection *nc, const char *client_id) {
  static struct ns_send_mqtt_handshake_opts opts;
  ns_send_mqtt_handshake_opt(nc, client_id, opts);
}

void ns_send_mqtt_handshake_opt(struct ns_connection *nc,
                                const char *client_id,
                                struct ns_send_mqtt_handshake_opts opts) {
  uint8_t header = NS_MQTT_CMD_CONNECT << 4;
  uint8_t rem_len;
  uint16_t keep_alive;
  uint16_t client_id_len;

  /*
   * 9: version_header(len, magic_string, version_number), 1: flags, 2: keep-alive timer,
   * 2: client_identifier_len, n: client_id
   */
  rem_len = 9+1+2+2+strlen(client_id);

  ns_send(nc, &header, 1);
  ns_send(nc, &rem_len, 1);
  ns_send(nc, "\00\06MQIsdp\03", 9);
  ns_send(nc, &opts.flags, 1);

  if (opts.keep_alive == 0) {
    opts.keep_alive = 60;
  }
  keep_alive = htons(opts.keep_alive);
  ns_send(nc, &keep_alive, 2);

  client_id_len = htons(strlen(client_id));
  ns_send(nc, &client_id_len, 2);
  ns_send(nc, client_id, strlen(client_id));
}

static void ns_mqtt_prepend_header(struct ns_connection *nc, uint8_t cmd,
                                   uint8_t flags, size_t len) {
  size_t off = nc->send_iobuf.len - len;
  uint8_t header = cmd << 4 | (uint8_t)flags;

  uint8_t buf[1 + sizeof(size_t)];
  uint8_t *vlen = &buf[1];

  assert(nc->send_iobuf.len >= len);

  buf[0] = header;

  /* mqtt variable length encoding */
  do {
    *vlen = len % 0x80;
    len /= 0x80;
    if (len > 0)
      *vlen |= 0x80;
    vlen++;
  } while (len > 0);

  iobuf_insert(&nc->send_iobuf, off, buf, vlen - buf);
}

/* Publish a message to a given topic. */
void ns_mqtt_publish(struct ns_connection *nc, const char *topic,
                     uint16_t message_id, int flags,
                     const void *data, size_t len) {
  size_t old_len = nc->send_iobuf.len;

  uint16_t topic_len = htons(strlen(topic));
  uint16_t message_id_net = htons(message_id);

  ns_send(nc, &topic_len, 2);
  ns_send(nc, topic, strlen(topic));
  if (NS_MQTT_GET_QOS(flags) > 0) {
    ns_send(nc, &message_id_net, 2);
  }
  ns_send(nc, data, len);

  ns_mqtt_prepend_header(nc, NS_MQTT_CMD_PUBLISH, flags,
                         nc->send_iobuf.len - old_len);
}

/* Subscribe to a bunch of topics. */
void ns_mqtt_subscribe(struct ns_connection *nc,
                       const struct ns_mqtt_topic_expression *topics,
                       size_t topics_len, uint16_t message_id) {
  size_t old_len = nc->send_iobuf.len;

  uint16_t message_id_n = htons(message_id);
  size_t i;

  ns_send(nc, (char *) &message_id_n, 2);
  for (i = 0; i < topics_len; i++) {
    uint16_t topic_len_n = htons(strlen(topics[i].topic));
    ns_send(nc, &topic_len_n, 2);
    ns_send(nc, topics[i].topic, strlen(topics[i].topic));
    ns_send(nc, &topics[i].qos, 1);
  }

  ns_mqtt_prepend_header(nc, NS_MQTT_CMD_SUBSCRIBE, NS_MQTT_QOS(1),
                         nc->send_iobuf.len - old_len);
}

/*
 * Extract the next topic expression from a SUBSCRIBE command payload.
 *
 * Topic expression name will point to a string in the payload buffer.
 * Return the pos of the next topic expression or -1 when the list
 * of topics is exhausted.
 */
int ns_mqtt_next_subscribe_topic(struct ns_mqtt_message *msg,
                                 struct ns_str *topic,
                                 uint8_t *qos,
                                 int pos) {
  unsigned char *buf = (unsigned char *) msg->payload.p + pos;
  if ((size_t) pos >= msg->payload.len) {
    return -1;
  }

  topic->len = buf[0] << 8 | buf[1];
  topic->p = (char *) buf + 2;
  *qos = buf[2 + topic->len];
  return pos + 2 + topic->len + 1;
}

/* Unsubscribe from a bunch of topics. */
void ns_mqtt_unsubscribe(struct ns_connection *nc, char **topics,
                         size_t topics_len, uint16_t message_id) {
  size_t old_len = nc->send_iobuf.len;

  uint16_t message_id_n = htons(message_id);
  size_t i;

  ns_send(nc, (char *) &message_id_n, 2);
  for (i = 0; i < topics_len; i++) {
    uint16_t topic_len_n = htons(strlen(topics[i]));
    ns_send(nc, &topic_len_n, 2);
    ns_send(nc, topics[i], strlen(topics[i]));
  }

  ns_mqtt_prepend_header(nc, NS_MQTT_CMD_UNSUBSCRIBE, NS_MQTT_QOS(1),
                         nc->send_iobuf.len - old_len);
}

/* Send a CONNACK command with a given `return_code`. */
void ns_mqtt_connack(struct ns_connection *nc, uint8_t return_code) {
  uint8_t unused = 0;
  ns_send(nc, &unused, 1);
  ns_send(nc, &return_code, 1);
  ns_mqtt_prepend_header(nc, NS_MQTT_CMD_CONNACK, 0, 2);
}

/*
 * Sends a command which contains only a `message_id` and a QoS level of 1.
 *
 * Helper function.
 */
static void ns_send_mqtt_short_command(struct ns_connection *nc, uint8_t cmd,
                                       uint16_t message_id) {
  uint16_t message_id_net = htons(message_id);
  ns_send(nc, &message_id_net, 2);
  ns_mqtt_prepend_header(nc, cmd, NS_MQTT_QOS(1), 2);
}

/* Send a PUBACK command with a given `message_id`. */
void ns_mqtt_puback(struct ns_connection *nc, uint16_t message_id) {
  ns_send_mqtt_short_command(nc, NS_MQTT_CMD_PUBACK, message_id);
}

/* Send a PUBREC command with a given `message_id`. */
void ns_mqtt_pubrec(struct ns_connection *nc, uint16_t message_id) {
  ns_send_mqtt_short_command(nc, NS_MQTT_CMD_PUBREC, message_id);
}

/* Send a PUBREL command with a given `message_id`. */
void ns_mqtt_pubrel(struct ns_connection *nc, uint16_t message_id) {
  ns_send_mqtt_short_command(nc, NS_MQTT_CMD_PUBREL, message_id);
}

/* Send a PUBCOMP command with a given `message_id`. */
void ns_mqtt_pubcomp(struct ns_connection *nc, uint16_t message_id) {
  ns_send_mqtt_short_command(nc, NS_MQTT_CMD_PUBCOMP, message_id);
}

/*
 * Send a SUBACK command with a given `message_id`
 * and a sequence of granted QoSs.
 */
void ns_mqtt_suback(struct ns_connection *nc, uint8_t *qoss, size_t qoss_len,
                    uint16_t message_id) {
  size_t i;
  uint16_t message_id_net = htons(message_id);
  ns_send(nc, &message_id_net, 2);
  for (i = 0; i < qoss_len; i++) {
    ns_send(nc, &qoss[i], 1);
  }
  ns_mqtt_prepend_header(nc, NS_MQTT_CMD_SUBACK, NS_MQTT_QOS(1), 2 + qoss_len);
}

/* Send a UNSUBACK command with a given `message_id`. */
void ns_mqtt_unsuback(struct ns_connection *nc, uint16_t message_id) {
  ns_send_mqtt_short_command(nc, NS_MQTT_CMD_UNSUBACK, message_id);
}

/* Send a PINGREQ command. */
void ns_mqtt_ping(struct ns_connection *nc) {
  ns_mqtt_prepend_header(nc, NS_MQTT_CMD_PINGREQ, 0, 0);
}

/* Send a PINGRESP command. */
void ns_mqtt_pong(struct ns_connection *nc) {
  ns_mqtt_prepend_header(nc, NS_MQTT_CMD_PINGRESP, 0, 0);
}

/* Send a DISCONNECT command. */
void ns_mqtt_disconnect(struct ns_connection *nc) {
  ns_mqtt_prepend_header(nc, NS_MQTT_CMD_DISCONNECT, 0, 0);
}

#endif  /* NS_DISABLE_MQTT */
#ifdef NS_MODULE_LINES
#line 1 "modules/mqtt-broker.c"
/**/
#endif
/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

/*
 * == MQTT Broker
 */


#ifdef NS_ENABLE_MQTT_BROKER

static void ns_mqtt_session_init(struct ns_mqtt_broker *brk,
                                 struct ns_mqtt_session *s,
                                 struct ns_connection *nc) {
  s->brk = brk;
  s->subscriptions = NULL;
  s->num_subscriptions = 0;
  s->nc = nc;
}

static void ns_mqtt_add_session(struct ns_mqtt_session *s) {
  s->next = s->brk->sessions;
  s->brk->sessions = s;
  s->prev = NULL;
  if (s->next != NULL) s->next->prev = s;
}

static void ns_mqtt_remove_session(struct ns_mqtt_session *s) {
  if (s->prev == NULL) s->brk->sessions = s->next;
  if (s->prev) s->prev->next = s->next;
  if (s->next) s->next->prev = s->prev;
}

static void ns_mqtt_destroy_session(struct ns_mqtt_session *s) {
  size_t i;
  for (i = 0; i < s->num_subscriptions; i++) {
    NS_FREE((void *) s->subscriptions[i].topic);
  }
  NS_FREE(s);
}

static void ns_mqtt_close_session(struct ns_mqtt_session *s) {
  ns_mqtt_remove_session(s);
  ns_mqtt_destroy_session(s);
}

/* Initializes a MQTT broker. */
void ns_mqtt_broker_init(struct ns_mqtt_broker *brk, void *user_data) {
  brk->sessions = NULL;
  brk->user_data = user_data;
}

static void ns_mqtt_broker_handle_connect(struct ns_mqtt_broker *brk,
                                          struct ns_connection *nc) {
  struct ns_mqtt_session *s = (struct ns_mqtt_session *) malloc(sizeof *s);
  if (s == NULL) {
    /* LCOV_EXCL_START */
    ns_mqtt_connack(nc, NS_MQTT_CONNACK_SERVER_UNAVAILABLE);
    return;
    /* LCOV_EXCL_STOP */
  }

  /* TODO(mkm): check header (magic and version) */

  ns_mqtt_session_init(brk, s, nc);
  s->user_data = nc->user_data;
  nc->user_data = s;
  ns_mqtt_add_session(s);

  ns_mqtt_connack(nc, NS_MQTT_CONNACK_ACCEPTED);
}

static void ns_mqtt_broker_handle_subscribe(struct ns_connection *nc,
                                            struct ns_mqtt_message *msg) {
  struct ns_mqtt_session *ss = (struct ns_mqtt_session *) nc->user_data;
  uint8_t qoss[512];
  size_t qoss_len = 0;
  struct ns_str topic;
  uint8_t qos;
  int pos;
  struct ns_mqtt_topic_expression *te;

  for (pos = 0;
       (pos = ns_mqtt_next_subscribe_topic(msg, &topic, &qos, pos)) != -1; ) {
    qoss[qoss_len++] = qos;
  }

  ss->subscriptions = (struct ns_mqtt_topic_expression *)realloc(
      ss->subscriptions, sizeof(*ss->subscriptions) * qoss_len);
  for (pos = 0;
       (pos = ns_mqtt_next_subscribe_topic(msg, &topic, &qos, pos)) != -1;
       ss->num_subscriptions++) {
    te = &ss->subscriptions[ss->num_subscriptions];
    te->topic = (char *) malloc(topic.len + 1);
    te->qos = qos;
    strncpy((char *) te->topic, topic.p, topic.len + 1);
  }

  ns_mqtt_suback(nc, qoss, qoss_len, msg->message_id);
}

/*
 * Matches a topic against a topic expression
 *
 * See http://goo.gl/iWk21X
 *
 * Returns 1 if it matches; 0 otherwise.
 */
static int ns_mqtt_match_topic_expression(const char *exp, const char *topic) {
  /* TODO(mkm): implement real matching */
  int len = strlen(exp);
  if (strchr(exp, '#')) {
    len -= 2;
  }
  return strncmp(exp, topic, len) == 0;
}

static void ns_mqtt_broker_handle_publish(struct ns_mqtt_broker *brk,
                                          struct ns_mqtt_message *msg) {
  struct ns_mqtt_session *s;
  size_t i;

  for (s = ns_mqtt_next(brk, NULL); s != NULL; s = ns_mqtt_next(brk, s)) {
    for (i = 0; i < s->num_subscriptions; i++) {
      if (ns_mqtt_match_topic_expression(
              s->subscriptions[i].topic, msg->topic)) {
        ns_mqtt_publish(s->nc, msg->topic, 0, 0,
                        msg->payload.p, msg->payload.len);
        break;
      }
    }
  }
}

/*
 * Process a MQTT broker message.
 *
 * Listening connection expects a pointer to an initialized `ns_mqtt_broker`
 * structure in the `user_data` field.
 *
 * Basic usage:
 *
 * [source,c]
 * -----
 * ns_mqtt_broker_init(&brk, NULL);
 *
 * if ((nc = ns_bind(&mgr, address, ns_mqtt_broker)) == NULL) {
 *   // fail;
 * }
 * nc->user_data = &brk;
 * -----
 *
 * New incoming connections will receive a `ns_mqtt_session` structure
 * in the connection `user_data`. The original `user_data` will be stored
 * in the `user_data` field of the session structure. This allows the user
 * handler to store user data before `ns_mqtt_broker` creates the session.
 *
 * Since only the NS_ACCEPT message is processed by the listening socket,
 * for most events the `user_data` will thus point to a `ns_mqtt_session`.
 */
void ns_mqtt_broker(struct ns_connection *nc, int ev, void *data) {
  struct ns_mqtt_message *msg = (struct ns_mqtt_message *)data;
  struct ns_mqtt_broker *brk;

  if (nc->listener) {
    brk = (struct ns_mqtt_broker *) nc->listener->user_data;
  } else {
    brk = (struct ns_mqtt_broker *) nc->user_data;
  }

  switch (ev) {
    case NS_ACCEPT:
      ns_set_protocol_mqtt(nc);
      break;
    case NS_MQTT_CONNECT:
      ns_mqtt_broker_handle_connect(brk, nc);
      break;
    case NS_MQTT_SUBSCRIBE:
      ns_mqtt_broker_handle_subscribe(nc, msg);
      break;
    case NS_MQTT_PUBLISH:
      ns_mqtt_broker_handle_publish(brk, msg);
      break;
    case NS_CLOSE:
      if (nc->listener) {
        ns_mqtt_close_session((struct ns_mqtt_session *) nc->user_data);
      }
      break;
  }
}

/* Iterates over all mqtt sessions connections. */
struct ns_mqtt_session *ns_mqtt_next(struct ns_mqtt_broker *brk,
                                     struct ns_mqtt_session *s) {
  return s == NULL ? brk->sessions : s->next;
}

#endif /* NS_ENABLE_MQTT_BROKER */
#ifdef NS_MODULE_LINES
#line 1 "modules/dns.c"
/**/
#endif
/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

/*
 * == DNS API
 */

#ifndef NS_DISABLE_DNS


#define MAX_DNS_PACKET_LEN  2048

static int ns_dns_tid = 0xa0;

struct ns_dns_header {
  uint16_t transaction_id;
  uint16_t flags;
  uint16_t num_questions;
  uint16_t num_answers;
  uint16_t num_authority_prs;
  uint16_t num_other_prs;
};

struct ns_dns_resource_record *ns_dns_next_record(
    struct ns_dns_message *msg, int query,
    struct ns_dns_resource_record *prev) {
  struct ns_dns_resource_record *rr;

  for (rr = (prev == NULL ? msg->answers : prev + 1);
       rr - msg->answers < msg->num_answers; rr++) {
    if (rr->rtype == query) {
      return rr;
    }
  }
  return NULL;
}

/*
 * Parses the record data from a DNS resource record.
 *
 *  - A:     struct in_addr *ina
 *  - AAAA:  struct in6_addr *ina
 *  - CNAME: char buffer
 *
 * Returns -1 on error.
 *
 * TODO(mkm): MX
 */
int ns_dns_parse_record_data(struct ns_dns_message *msg,
                             struct ns_dns_resource_record *rr,
                             void *data, size_t data_len) {
  switch (rr->rtype) {
    case NS_DNS_A_RECORD:
      if (data_len < sizeof(struct in_addr)) {
        return -1;
      }
      if (rr->rdata.p + data_len > msg->pkt.p + msg->pkt.len) {
        return -1;
      }
      memcpy(data, rr->rdata.p, data_len);
      return 0;
#ifdef NS_ENABLE_IPV6
    case NS_DNS_AAAA_RECORD:
      if (data_len < sizeof(struct in6_addr)) {
        return -1;  /* LCOV_EXCL_LINE */
      }
      memcpy(data, rr->rdata.p, data_len);
      return 0;
#endif
    case NS_DNS_CNAME_RECORD:
      ns_dns_uncompress_name(msg, &rr->rdata, (char *) data, data_len);
      return 0;
  }

  return -1;
}

/*
 * Insert a DNS header to an IO buffer.
 *
 * Returns number of bytes inserted.
 */
int ns_dns_insert_header(struct iobuf *io, size_t pos,
                         struct ns_dns_message *msg) {
  struct ns_dns_header header;

  memset(&header, 0, sizeof(header));
  header.transaction_id = msg->transaction_id;
  header.flags = htons(msg->flags);
  header.num_questions = htons(msg->num_questions);
  header.num_answers = htons(msg->num_answers);

  return iobuf_insert(io, pos, &header, sizeof(header));
}

/*
 * Append already encoded body from an existing message.
 *
 * This is useful when generating a DNS reply message which includes
 * all question records.
 *
 * Returns number of appened bytes.
 */
int ns_dns_copy_body(struct iobuf *io, struct ns_dns_message *msg) {
  return iobuf_append(io, msg->pkt.p + sizeof(struct ns_dns_header),
                      msg->pkt.len - sizeof(struct ns_dns_header));
}

static int ns_dns_encode_name(struct iobuf *io, const char *name, size_t len) {
  const char *s;
  unsigned char n;
  size_t pos = io->len;

  do {
    if ((s = strchr(name, '.')) == NULL) {
      s = name + len;
    }

    if (s - name > 127) {
      return -1;  /* TODO(mkm) cover */
    }
    n = s - name;            /* chunk length */
    iobuf_append(io, &n, 1); /* send length */
    iobuf_append(io, name, n);

    if (*s == '.') {
      n++;
    }

    name += n;
    len -= n;
  } while (*s != '\0');
  iobuf_append(io, "\0", 1);  /* Mark end of host name */

  return io->len - pos;
}

/*
 * Encode and append a DNS resource record to an IO buffer.
 *
 * The record metadata is taken from the `rr` parameter, while the name and data
 * are taken from the parameters, encoded in the appropriate format depending on
 * record type, and stored in the IO buffer. The encoded values might contain
 * offsets within the IO buffer. It's thus important that the IO buffer doesn't
 * get trimmed while a sequence of records are encoded while preparing a DNS reply.
 *
 * This function doesn't update the `name` and `rdata` pointers in the `rr` struct
 * because they might be invalidated as soon as the IO buffer grows again.
 *
 * Returns the number of bytes appened or -1 in case of error.
 */
int ns_dns_encode_record(struct iobuf *io, struct ns_dns_resource_record *rr,
                         const char *name, size_t nlen,
                         const void *rdata, size_t rlen) {
  size_t pos = io->len;
  uint16_t u16;
  uint32_t u32;

  if (rr->kind == NS_DNS_INVALID_RECORD) {
    return -1;  /* LCOV_EXCL_LINE */
  }

  if (ns_dns_encode_name(io, name, nlen) == -1) {
    return -1;
  }

  u16 = htons(rr->rtype);
  iobuf_append(io, &u16, 2);
  u16 = htons(rr->rclass);
  iobuf_append(io, &u16, 2);

  if (rr->kind == NS_DNS_ANSWER) {
    u32 = htonl(rr->ttl);
    iobuf_append(io, &u32, 4);

    if (rr->rtype == NS_DNS_CNAME_RECORD) {
      int clen;
      /* fill size after encoding */
      size_t off = io->len;
      iobuf_append(io, &u16, 2);
      if ((clen = ns_dns_encode_name(io, (const char *) rdata, rlen)) == -1) {
        return -1;
      }
      u16 = clen;
      io->buf[off] = u16 >> 8;
      io->buf[off+1] = u16 & 0xff;
    } else {
      u16 = htons(rlen);
      iobuf_append(io, &u16, 2);
      iobuf_append(io, rdata, rlen);
    }
  }

  return io->len - pos;
}

/*
 * Send a DNS query to the remote end.
 */
void ns_send_dns_query(struct ns_connection* nc, const char *name,
                       int query_type) {
  struct ns_dns_message msg;
  struct iobuf pkt;
  struct ns_dns_resource_record *rr = &msg.questions[0];

  iobuf_init(&pkt, MAX_DNS_PACKET_LEN);
  memset(&msg, 0, sizeof(msg));

  msg.transaction_id = ++ns_dns_tid;
  msg.flags = 0x100;
  msg.num_questions = 1;

  ns_dns_insert_header(&pkt, 0, &msg);

  rr->rtype = query_type;
  rr->rclass = 1; /* Class: inet */
  rr->kind = NS_DNS_QUESTION;

  if (ns_dns_encode_record(&pkt, rr, name, strlen(name), NULL, 0) == -1) {
    /* TODO(mkm): return an error code */
    return; /* LCOV_EXCL_LINE */
  }

  /* TCP DNS requires messages to be prefixed with len */
  if (!(nc->flags & NSF_UDP)) {
    uint16_t len = htons(pkt.len);
    iobuf_insert(&pkt, 0, &len, 2);
  }

  ns_send(nc, pkt.buf, pkt.len);
  iobuf_free(&pkt);
}

static unsigned char *ns_parse_dns_resource_record(
    unsigned char *data, unsigned char *end, struct ns_dns_resource_record *rr,
    int reply) {
  unsigned char *name = data;
  int chunk_len, data_len;

  while(data < end && (chunk_len = *data)) {
    if (((unsigned char *)data)[0] & 0xc0) {
      data += 1;
      break;
    }
    data += chunk_len + 1;
  }

  rr->name.p = (char *) name;
  rr->name.len = data-name+1;

  data++;
  if (data > end - 4) {
    return data;
  }

  rr->rtype = data[0] << 8 | data[1];
  data += 2;

  rr->rclass = data[0] << 8 | data[1];
  data += 2;

  rr->kind = reply ? NS_DNS_ANSWER : NS_DNS_QUESTION;
  if (reply) {
    if (data >= end - 6) {
      return data;
    }

    rr->ttl = data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3];
    data += 4;

    data_len = *data << 8 | *(data+1);
    data += 2;

    rr->rdata.p = (char *) data;
    rr->rdata.len = data_len;
    data += data_len;
  }
  return data;
}

/* Low-level: parses a DNS response. */
int ns_parse_dns(const char *buf, int len, struct ns_dns_message *msg) {
  struct ns_dns_header *header = (struct ns_dns_header *) buf;
  unsigned char *data = (unsigned char *) buf + sizeof(*header);
  unsigned char *end = (unsigned char *) buf + len;
  int i;
  msg->pkt.p = buf;
  msg->pkt.len = len;

  if (len < (int)sizeof(*header)) {
    return -1;  /* LCOV_EXCL_LINE */
  }

  msg->transaction_id = header->transaction_id;
  msg->flags = ntohs(header->flags);
  msg->num_questions = ntohs(header->num_questions);
  msg->num_answers = ntohs(header->num_answers);

  for (i = 0; i < msg->num_questions
           && i < (int)ARRAY_SIZE(msg->questions); i++) {
    data = ns_parse_dns_resource_record(data, end, &msg->questions[i], 0);
  }

  for (i = 0; i < msg->num_answers
           && i < (int)ARRAY_SIZE(msg->answers); i++) {
    data = ns_parse_dns_resource_record(data, end, &msg->answers[i], 1);
  }

  return 0;
}

/*
 * Uncompress a DNS compressed name.
 *
 * The containing dns message is required because the compressed encoding
 * and reference suffixes present elsewhere in the packet.
 *
 * If name is less than `dst_len` characters long, the remainder
 * of `dst` is terminated with `\0' characters. Otherwise, `dst` is not terminated.
 *
 * If `dst_len` is 0 `dst` can be NULL.
 * Returns the uncompressed name length.
 */
size_t ns_dns_uncompress_name(struct ns_dns_message *msg, struct ns_str *name,
                              char *dst, int dst_len) {
  int chunk_len;
  char *old_dst = dst;
  const unsigned char *data = (unsigned char *) name->p;
  const unsigned char *end = (unsigned char *) msg->pkt.p + msg->pkt.len;

  if (data >= end) {
    return 0;
  }

  while((chunk_len = *data++)) {
    int leeway = dst_len - (dst - old_dst);
    if (data >= end) {
      return 0;
    }

    if (chunk_len & 0xc0) {
      uint16_t off = (data[-1] & (~0xc0)) << 8 | data[0];
      if (off >= msg->pkt.len) {
        return 0;
      }
      data = (unsigned char *)msg->pkt.p + off;
      continue;
    }
    if (chunk_len > leeway) {
      chunk_len = leeway;
    }

    if (data + chunk_len >= end) {
      return 0;
    }

    memcpy(dst, data, chunk_len);
    data += chunk_len;
    dst += chunk_len;
    leeway -= chunk_len;
    if (leeway == 0) {
      return dst - old_dst;
    }
    *dst++ = '.';
  }

  if (dst != old_dst) {
    *--dst = 0;
  }
  return dst - old_dst;
}

static void dns_handler(struct ns_connection *nc, int ev, void *ev_data) {
  struct iobuf *io = &nc->recv_iobuf;
  struct ns_dns_message msg;

  /* Pass low-level events to the user handler */
  nc->handler(nc, ev, ev_data);

  switch (ev) {
    case NS_RECV:
      if (!(nc->flags & NSF_UDP)) {
        iobuf_remove(&nc->recv_iobuf, 2);
      }
      if (ns_parse_dns(nc->recv_iobuf.buf, nc->recv_iobuf.len, &msg) == -1) {
        /* reply + recursion allowed + format error */
        memset(&msg, 0, sizeof(msg));
        msg.flags = 0x8081;
        ns_dns_insert_header(io, 0, &msg);
        if (!(nc->flags & NSF_UDP)) {
          uint16_t len = htons(io->len);
          iobuf_insert(io, 0, &len, 2);
        }
        ns_send(nc, io->buf, io->len);
      } else {
        /* Call user handler with parsed message */
        nc->handler(nc, NS_DNS_MESSAGE, &msg);
      }
      iobuf_remove(io, io->len);
      break;
  }
}

/*
 * Attach built-in DNS event handler to the given listening connection.
 *
 * DNS event handler parses incoming UDP packets, treating them as DNS
 * requests. If incoming packet gets successfully parsed by the DNS event
 * handler, a user event handler will receive `NS_DNS_REQUEST` event, with
 * `ev_data` pointing to the parsed `struct ns_dns_message`.
 *
 * See https://github.com/cesanta/fossa/tree/master/examples/captive_dns_server[captive_dns_server]
 * example on how to handle DNS request and send DNS reply.
 */
void ns_set_protocol_dns(struct ns_connection *nc) {
  nc->proto_handler = dns_handler;
}

#endif  /* NS_DISABLE_DNS */
#ifdef NS_MODULE_LINES
#line 1 "modules/dns-server.c"
/**/
#endif
/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

/*
 * == DNS server API
 *
 * Disabled by default; enable with `-DNS_ENABLE_DNS_SERVER`.
 */

#ifdef NS_ENABLE_DNS_SERVER


/*
 * Creates a DNS reply.
 *
 * The reply will be based on an existing query message `msg`.
 * The query body will be appended to the output buffer.
 * "reply + recusions allowed" will be added to the message flags and
 * message's num_answers will be set to 0.
 *
 * Anwer records can be appended with `ns_dns_send_reply` or by lower
 * level function defined in the DNS API.
 *
 * In order to send the reply use `ns_dns_send_reply`.
 * It's possible to use a connection's send buffer as reply buffers,
 * and it will work for both UDP and TCP connections.
 *
 * Example:
 *
 * [source,c]
 * -----
 * reply = ns_dns_create_reply(&nc->send_iobuf, msg);
 * for (i = 0; i < msg->num_questions; i++) {
 *   rr = &msg->questions[i];
 *   if (rr->rtype == NS_DNS_A_RECORD) {
 *     ns_dns_reply_record(&reply, rr, 3600, &dummy_ip_addr, 4);
 *   }
 * }
 * ns_dns_send_reply(nc, &reply);
 * -----
 */
struct ns_dns_reply ns_dns_create_reply(struct iobuf *io,
                                        struct ns_dns_message *msg) {
  struct ns_dns_reply rep;
  rep.msg = msg;
  rep.io = io;
  rep.start = io->len;

  /* reply + recursion allowed */
  msg->flags |= 0x8080;
  ns_dns_copy_body(io, msg);

  msg->num_answers = 0;
  return rep;
}

/*
 * Sends a DNS reply through a connection.
 *
 * The DNS data is stored in an IO buffer pointed by reply structure in `r`.
 * This function mutates the content of that buffer in order to ensure that
 * the DNS header reflects size and flags of the mssage, that might have been
 * updated either with `ns_dns_reply_record` or by direct manipulation of
 * `r->message`.
 *
 * Once sent, the IO buffer will be trimmed unless the reply IO buffer
 * is the connection's send buffer and the connection is not in UDP mode.
 */
int ns_dns_send_reply(struct ns_connection *nc, struct ns_dns_reply *r) {
  size_t sent = r->io->len - r->start;
  ns_dns_insert_header(r->io, r->start, r->msg);
  if (!(nc->flags & NSF_UDP)) {
    uint16_t len = htons(sent);
    iobuf_insert(r->io, r->start, &len, 2);
  }

  if (&nc->send_iobuf != r->io || nc->flags & NSF_UDP) {
    sent = ns_send(nc, r->io->buf + r->start, r->io->len - r->start);
    r->io->len = r->start;
  }
  return sent;
}

/*
 * Append a DNS reply record to the IO buffer and to the DNS message.
 *
 * The message num_answers field will be incremented. It's caller's duty
 * to ensure num_answers is propertly initialized.
 *
 * Returns -1 on error.
 */
int ns_dns_reply_record(struct ns_dns_reply *reply,
                        struct ns_dns_resource_record *question,
                        const char *name, int rtype, int ttl,
                        const void *rdata, size_t rdata_len) {
  struct ns_dns_message *msg = (struct ns_dns_message *)reply->msg;
  char rname[512];
  struct ns_dns_resource_record *ans = &msg->answers[msg->num_answers];
  if (msg->num_answers >= NS_MAX_DNS_ANSWERS) {
    return -1;  /* LCOV_EXCL_LINE */
  }

  if (name == NULL) {
    name = rname;
    rname[511] = 0;
    ns_dns_uncompress_name(msg, &question->name, rname, sizeof(rname) - 1);
  }

  *ans = *question;
  ans->kind = NS_DNS_ANSWER;
  ans->rtype = rtype;
  ans->ttl = ttl;

  if (ns_dns_encode_record(reply->io, ans, name, strlen(name),
                           rdata, rdata_len) == -1) {
    return -1;  /* LCOV_EXCL_LINE */
  };

  msg->num_answers++;
  return 0;
}


#endif  /* NS_ENABLE_DNS_SERVER */
#ifdef NS_MODULE_LINES
#line 1 "modules/resolv.c"
/**/
#endif
/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

/*
 * == Name resolver
 */

#ifndef NS_DISABLE_RESOLVER


static const char *ns_default_dns_server = "udp://8.8.8.8:53";
NS_INTERNAL char ns_dns_server[256];

struct ns_resolve_async_request {
  char name[1024];
  int query;
  ns_resolve_callback_t callback;
  void *data;
  time_t timeout;
  int max_retries;

  /* state */
  time_t last_time;
  int retries;
};

/*
 * Find what nameserver to use.
 *
 * Return 0 if OK, -1 if error
 */
static int ns_get_ip_address_of_nameserver(char *name, size_t name_len) {
  int  ret = 0;

#ifdef _WIN32
  int  i;
  LONG  err;
  HKEY  hKey, hSub;
  char  subkey[512], dhcpns[512], ns[512], value[128], *key =
  "SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces";

  if ((err = RegOpenKey(HKEY_LOCAL_MACHINE,
      key, &hKey)) != ERROR_SUCCESS) {
    fprintf(stderr, "cannot open reg key %s: %d\n", key, err);
    ret--;
  } else {
    for (ret--, i = 0; RegEnumKey(hKey, i, subkey,
        sizeof(subkey)) == ERROR_SUCCESS; i++) {
      DWORD type, len = sizeof(value);
      if (RegOpenKey(hKey, subkey, &hSub) == ERROR_SUCCESS &&
          (RegQueryValueEx(hSub, "NameServer", 0,
          &type, value, &len) == ERROR_SUCCESS ||
          RegQueryValueEx(hSub, "DhcpNameServer", 0,
          &type, value, &len) == ERROR_SUCCESS)) {
        /*
         * See https://github.com/cesanta/fossa/issues/176
         * The value taken from the registry can be empty, a single
         * IP address, or multiple IP addresses separated by comma.
         * If it's multiple IP addresses, take the first one.
         */
        char *comma = strchr(value, ',');
        if (comma != NULL) {
          *comma = '\0';
        }
        strncpy(name, value, name_len);
        ret++;
        RegCloseKey(hSub);
        break;
      }
    }
    RegCloseKey(hKey);
  }
#else
  FILE  *fp;
  char  line[512];

  if ((fp = fopen("/etc/resolv.conf", "r")) == NULL) {
    ret--;
  } else {
    /* Try to figure out what nameserver to use */
    for (ret--; fgets(line, sizeof(line), fp) != NULL; ) {
      char buf[256];
      if (sscanf(line, "nameserver %255[^\n]s", buf) == 1) {
        snprintf(name, name_len, "udp://%s:53", buf);
        ret++;
        break;
      }
    }
    (void) fclose(fp);
  }
#endif /* _WIN32 */

  return ret;
}

/*
 * Resolve a name from `/etc/hosts`.
 *
 * Returns 0 on success, -1 on failure.
 */
int ns_resolve_from_hosts_file(const char *name, union socket_address *usa) {
  /* TODO(mkm) cache /etc/hosts */
  FILE *fp;
  char line[1024];
  char *p;
  char alias[256];
  unsigned int a, b, c, d;
  int len = 0;

  if ((fp = fopen("/etc/hosts", "r")) == NULL) {
    return -1;
  }

  for (; fgets(line, sizeof(line), fp) != NULL; ) {
    if (line[0] == '#') continue;

    if (sscanf(line, "%u.%u.%u.%u%n", &a, &b, &c, &d, &len) == 0) {
      /* TODO(mkm): handle ipv6 */
      continue;
    }
    for (p = line + len; sscanf(p, "%s%n", alias, &len) == 1; p += len) {
      if (strcmp(alias, name) == 0) {
        usa->sin.sin_addr.s_addr = htonl(a << 24 | b << 16 | c << 8 | d);
        return 0;
      }
    }
  }

  return -1;
}

static void ns_resolve_async_eh(struct ns_connection *nc, int ev, void *data) {
  time_t now = time(NULL);
  struct ns_resolve_async_request *req;
  struct ns_dns_message msg;

  req = (struct ns_resolve_async_request *) nc->user_data;

  switch (ev) {
    case NS_POLL:
      if (req->retries > req->max_retries) {
        req->callback(NULL, req->data);
        nc->flags |= NSF_CLOSE_IMMEDIATELY;
        break;
      }
      if (now - req->last_time > req->timeout) {
        ns_send_dns_query(nc, req->name, req->query);
        req->last_time = now;
        req->retries++;
      }
      break;
    case NS_RECV:
      if (ns_parse_dns(nc->recv_iobuf.buf, * (int *) data, &msg) == 0 &&
          msg.num_answers > 0) {
        req->callback(&msg, req->data);
      } else {
        req->callback(NULL, req->data);
      }
      nc->flags |= NSF_CLOSE_IMMEDIATELY;
      break;
  }
}

/* See `ns_resolve_async_opt` */
int ns_resolve_async(struct ns_mgr *mgr, const char *name, int query,
                     ns_resolve_callback_t cb, void *data) {
  static struct ns_resolve_async_opts opts;
  return ns_resolve_async_opt(mgr, name, query, cb, data, opts);
}

/*
 * Resolved a DNS name asynchronously.
 *
 * Upon successful resolution, the user callback will be invoked
 * with the full DNS response message and a pointer to the user's
 * context `data`.
 *
 * In case of timeout while performing the resolution the callback
 * will receive a NULL `msg`.
 *
 * The DNS answers can be extracted with `ns_next_record` and
 * `ns_dns_parse_record_data`:
 *
 * [source,c]
 * ----
 * struct in_addr ina;
 * struct ns_dns_resource_record *rr = ns_next_record(msg, NS_DNS_A_RECORD, NULL);
 * ns_dns_parse_record_data(msg, rr, &ina, sizeof(ina));
 * ----
 */
int ns_resolve_async_opt(struct ns_mgr *mgr, const char *name, int query,
                         ns_resolve_callback_t cb, void *data,
                         struct ns_resolve_async_opts opts) {
  struct ns_resolve_async_request *req;
  struct ns_connection *dns_nc;
  const char *nameserver = opts.nameserver_url;

  /* resolve with DNS */
  req = (struct ns_resolve_async_request *) NS_CALLOC(1, sizeof(*req));
  if (req == NULL) {
    return -1;
  }

  strncpy(req->name, name, sizeof(req->name));
  req->query = query;
  req->callback = cb;
  req->data = data;
  /* TODO(mkm): parse defaults out of resolve.conf */
  req->max_retries = opts.max_retries ? opts.max_retries : 2;
  req->timeout = opts.timeout ? opts.timeout : 5;

  /* Lazily initialize dns server */
  if (nameserver == NULL && ns_dns_server[0] == '\0'  &&
      ns_get_ip_address_of_nameserver(ns_dns_server,
                                      sizeof(ns_dns_server)) == -1) {
    strncpy(ns_dns_server, ns_default_dns_server, sizeof(ns_dns_server));
  }

  if (nameserver == NULL) {
    nameserver = ns_dns_server;
  }

  dns_nc = ns_connect(mgr, nameserver, ns_resolve_async_eh);
  if (dns_nc == NULL) {
    return -1;
  }
  dns_nc->user_data = req;

  return 0;
}

#endif  /* NS_DISABLE_RESOLVE */
#ifdef NS_MODULE_LINES
#line 1 "modules/md5.c"
/**/
#endif
/*
 * This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 *
 * To compute the message digest of a chunk of bytes, declare an
 * MD5Context structure, pass it to MD5Init, call MD5Update as
 * needed on buffers full of bytes, and then call MD5Final, which
 * will fill a supplied 16-byte array with the digest.
 */

#ifndef NS_DISABLE_MD5

static void byteReverse(unsigned char *buf, unsigned longs) {
  uint32_t t;

  /* Forrest: MD5 expect LITTLE_ENDIAN, swap if BIG_ENDIAN */
  if (is_big_endian()) {
    do {
      t = (uint32_t) ((unsigned) buf[3] << 8 | buf[2]) << 16 |
        ((unsigned) buf[1] << 8 | buf[0]);
      * (uint32_t *) buf = t;
      buf += 4;
    } while (--longs);
  }
}

#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

#define MD5STEP(f, w, x, y, z, data, s) \
  ( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )

/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
void MD5_Init(MD5_CTX *ctx) {
  ctx->buf[0] = 0x67452301;
  ctx->buf[1] = 0xefcdab89;
  ctx->buf[2] = 0x98badcfe;
  ctx->buf[3] = 0x10325476;

  ctx->bits[0] = 0;
  ctx->bits[1] = 0;
}

static void MD5Transform(uint32_t buf[4], uint32_t const in[16]) {
  register uint32_t a, b, c, d;

  a = buf[0];
  b = buf[1];
  c = buf[2];
  d = buf[3];

  MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
  MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
  MD5STEP(F1, c, d, a, b, in[2] + 0x242070db, 17);
  MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
  MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
  MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
  MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17);
  MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
  MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);
  MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
  MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
  MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
  MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
  MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
  MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
  MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

  MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
  MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
  MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
  MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
  MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
  MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
  MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
  MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
  MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
  MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
  MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
  MD5STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
  MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
  MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
  MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
  MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

  MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
  MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
  MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
  MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
  MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
  MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
  MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
  MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
  MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
  MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
  MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
  MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
  MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
  MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
  MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
  MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);

  MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);
  MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
  MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
  MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
  MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
  MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
  MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
  MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
  MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
  MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
  MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15);
  MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
  MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
  MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
  MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
  MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);

  buf[0] += a;
  buf[1] += b;
  buf[2] += c;
  buf[3] += d;
}

void MD5_Update(MD5_CTX *ctx, const unsigned char *buf, size_t len) {
  uint32_t t;

  t = ctx->bits[0];
  if ((ctx->bits[0] = t + ((uint32_t) len << 3)) < t)
    ctx->bits[1]++;
  ctx->bits[1] += len >> 29;

  t = (t >> 3) & 0x3f;

  if (t) {
    unsigned char *p = (unsigned char *) ctx->in + t;

    t = 64 - t;
    if (len < t) {
      memcpy(p, buf, len);
      return;
    }
    memcpy(p, buf, t);
    byteReverse(ctx->in, 16);
    MD5Transform(ctx->buf, (uint32_t *) ctx->in);
    buf += t;
    len -= t;
  }

  while (len >= 64) {
    memcpy(ctx->in, buf, 64);
    byteReverse(ctx->in, 16);
    MD5Transform(ctx->buf, (uint32_t *) ctx->in);
    buf += 64;
    len -= 64;
  }

  memcpy(ctx->in, buf, len);
}

void MD5_Final(unsigned char digest[16], MD5_CTX *ctx) {
  unsigned count;
  unsigned char *p;
  uint32_t *a;

  count = (ctx->bits[0] >> 3) & 0x3F;

  p = ctx->in + count;
  *p++ = 0x80;
  count = 64 - 1 - count;
  if (count < 8) {
    memset(p, 0, count);
    byteReverse(ctx->in, 16);
    MD5Transform(ctx->buf, (uint32_t *) ctx->in);
    memset(ctx->in, 0, 56);
  } else {
    memset(p, 0, count - 8);
  }
  byteReverse(ctx->in, 14);

  a = (uint32_t *)ctx->in;
  a[14] = ctx->bits[0];
  a[15] = ctx->bits[1];

  MD5Transform(ctx->buf, (uint32_t *) ctx->in);
  byteReverse((unsigned char *) ctx->buf, 4);
  memcpy(digest, ctx->buf, 16);
  memset((char *) ctx, 0, sizeof(*ctx));
}
#endif
