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

#include "internal.h"

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
#ifdef NS_ENABLE_GETADDRINFO
  int rv = 0;
  struct addrinfo hints, *servinfo, *p;
  struct sockaddr_in *h = NULL;
  char *ip = NS_MALLOC(17);
  memset(ip, '\0', 17);
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  if((rv = getaddrinfo(host, NULL , NULL, &servinfo)) != 0) {
    DBG(("getaddrinfo(%s) failed: %s", host, strerror(errno)));
    return 0;
  }
  for(p = servinfo; p != NULL; p = p->ai_next) {
    memcpy(&h, &p->ai_addr, sizeof(struct sockaddr_in *));
    memcpy(ina, &h->sin_addr, sizeof(ina));
  }
  freeaddrinfo(servinfo);
  return 1;
#else
  struct hostent *he;
  if ((he = gethostbyname(host)) == NULL) {
    DBG(("gethostbyname(%s) failed: %s", host, strerror(errno)));
  } else {
    memcpy(ina, he->h_addr_list[0], sizeof(*ina));
    return 1;
  }
  return 0;
#endif
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

/*
 * Turn the connection into SSL mode.
 * `cert` is the certificate file in PEM format. For listening connections,
 * certificate file must contain private key and server certificate,
 * concatenated. `ca_cert` is a certificate authority (CA) PEM file, and
 * it is optional (can be set to NULL). If `ca_cert` is non-NULL, then
 * the connection is so-called two-way-SSL: other peer's certificate is
 * checked against the `ca_cert`.
 *
 * Handy OpenSSL command to generate test self-signed certificate:
 *
 *    openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 999
 *
 * Return NULL on success, or error message on failure.
 */
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
        conn->flags &= ~(NSF_WANT_READ | NSF_WANT_WRITE);
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
        conn->flags &= ~(NSF_WANT_READ | NSF_WANT_WRITE);
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
    } else {
      /* Successful SSL operation, clear off SSL wait flags */
      conn->flags &= ~(NSF_WANT_READ | NSF_WANT_WRITE);
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
    union socket_address sa = nc.sa;
    /* Copy all attributes, preserving sender address */
    nc = *ls;

    /* Then override some */
    nc.sa = sa;
    nc.recv_iobuf.buf = buf;
    nc.recv_iobuf.len = nc.recv_iobuf.size = n;
    nc.listener = ls;
    nc.flags = NSF_UDP;

    /* Call NS_RECV handler */
    DBG(("%p %d bytes received", ls, n));
    ns_call(&nc, NS_RECV, &n);

    /*
     * See https://github.com/cesanta/fossa/issues/207
     * ns_call migth set flags. They need to be synced back to ls.
     */
    ls->flags = nc.flags;
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
