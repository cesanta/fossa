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
 * license, as set out in <https://www.cesanta.com/license>.
 */

#include "internal.h"

#if NS_MGR_EV_MGR == 1 /* epoll() */
#include <sys/epoll.h>
#endif

#define NS_CTL_MSG_MESSAGE_SIZE 8192
#define NS_READ_BUFFER_SIZE 1024
#define NS_UDP_RECEIVE_BUFFER_SIZE 1500
#define NS_VPRINTF_BUFFER_SIZE 100
#define NS_MAX_HOST_LEN 200

#define NS_COPY_COMMON_CONNECTION_OPTIONS(dst, src) \
  memcpy(dst, src, sizeof(*dst));

/* Which flags can be pre-set by the user at connection creation time. */
#define _NS_ALLOWED_CONNECT_FLAGS_MASK                              \
  (NSF_USER_1 | NSF_USER_2 | NSF_USER_3 | NSF_USER_4 | NSF_USER_5 | \
   NSF_USER_6 | NSF_WEBSOCKET_NO_DEFRAG)
/* Which flags should be modifiable by user's callbacks. */
#define _NS_CALLBACK_MODIFIABLE_FLAGS_MASK                                     \
  (NSF_USER_1 | NSF_USER_2 | NSF_USER_3 | NSF_USER_4 | NSF_USER_5 |            \
   NSF_USER_6 | NSF_WEBSOCKET_NO_DEFRAG | NSF_SEND_AND_CLOSE | NSF_DONT_SEND | \
   NSF_CLOSE_IMMEDIATELY | NSF_IS_WEBSOCKET)

#ifndef intptr_t
#define intptr_t long
#endif

struct ctl_msg {
  ns_event_handler_t callback;
  char message[NS_CTL_MSG_MESSAGE_SIZE];
};

static void ns_ev_mgr_init(struct ns_mgr *mgr);
static void ns_ev_mgr_free(struct ns_mgr *mgr);
static void ns_ev_mgr_add_conn(struct ns_connection *nc);
static void ns_ev_mgr_remove_conn(struct ns_connection *nc);

NS_INTERNAL void ns_add_conn(struct ns_mgr *mgr, struct ns_connection *c) {
  c->mgr = mgr;
  c->next = mgr->active_connections;
  mgr->active_connections = c;
  c->prev = NULL;
  if (c->next != NULL) c->next->prev = c;
  ns_ev_mgr_add_conn(c);
}

NS_INTERNAL void ns_remove_conn(struct ns_connection *conn) {
  if (conn->prev == NULL) conn->mgr->active_connections = conn->next;
  if (conn->prev) conn->prev->next = conn->next;
  if (conn->next) conn->next->prev = conn->prev;
  ns_ev_mgr_remove_conn(conn);
}

NS_INTERNAL void ns_call(struct ns_connection *nc, int ev, void *ev_data) {
  unsigned long flags_before;
  ns_event_handler_t ev_handler;

  DBG(("%p flags=%lu ev=%d ev_data=%p rmbl=%d", nc, nc->flags, ev, ev_data,
       (int) nc->recv_mbuf.len));

#ifndef NS_DISABLE_FILESYSTEM
  /* LCOV_EXCL_START */
  if (nc->mgr->hexdump_file != NULL && ev != NS_POLL &&
      ev != NS_SEND /* handled separately */) {
    int len = (ev == NS_RECV ? *(int *) ev_data : 0);
    ns_hexdump_connection(nc, nc->mgr->hexdump_file, len, ev);
  }
/* LCOV_EXCL_STOP */
#endif

  /*
   * If protocol handler is specified, call it. Otherwise, call user-specified
   * event handler.
   */
  ev_handler = nc->proto_handler ? nc->proto_handler : nc->handler;
  if (ev_handler != NULL) {
    flags_before = nc->flags;
    ev_handler(nc, ev, ev_data);
    if (nc->flags != flags_before) {
      nc->flags = (flags_before & ~_NS_CALLBACK_MODIFIABLE_FLAGS_MASK) |
                  (nc->flags & _NS_CALLBACK_MODIFIABLE_FLAGS_MASK);
    }
  }
  DBG(("call done, flags %d", (int) nc->flags));
}

static size_t ns_out(struct ns_connection *nc, const void *buf, size_t len) {
  if (nc->flags & NSF_UDP) {
    int n = sendto(nc->sock, buf, len, 0, &nc->sa.sa, sizeof(nc->sa.sin));
    DBG(("%p %d %d %d %s:%hu", nc, nc->sock, n, errno,
         inet_ntoa(nc->sa.sin.sin_addr), ntohs(nc->sa.sin.sin_port)));
    return n < 0 ? 0 : n;
  } else {
    return mbuf_append(&nc->send_mbuf, buf, len);
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
  mbuf_free(&conn->recv_mbuf);
  mbuf_free(&conn->send_mbuf);
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
  if (!(conn->flags & NSF_CONNECTING)) {
    ns_call(conn, NS_CLOSE, NULL);
  }
  ns_remove_conn(conn);
  ns_destroy_conn(conn);
}

void ns_mgr_init(struct ns_mgr *s, void *user_data) {
  memset(s, 0, sizeof(*s));
  s->ctl[0] = s->ctl[1] = INVALID_SOCKET;
  s->user_data = user_data;

#ifdef _WIN32
  {
    WSADATA data;
    WSAStartup(MAKEWORD(2, 2), &data);
  }
#elif !defined(AVR_LIBC) && !defined(NS_ESP8266)
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
  ns_ev_mgr_init(s);
  DBG(("=================================="));
  DBG(("init mgr=%p", s));
}

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

  ns_ev_mgr_free(s);
}

int ns_vprintf(struct ns_connection *nc, const char *fmt, va_list ap) {
  char mem[NS_VPRINTF_BUFFER_SIZE], *buf = mem;
  int len;

  if ((len = ns_avprintf(&buf, sizeof(mem), fmt, ap)) > 0) {
    ns_out(nc, buf, len);
  }
  if (buf != mem && buf != NULL) {
    NS_FREE(buf); /* LCOV_EXCL_LINE */
  }               /* LCOV_EXCL_LINE */

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

static void ns_set_non_blocking_mode(sock_t sock) {
#ifdef _WIN32
  unsigned long on = 1;
  ioctlsocket(sock, FIONBIO, &on);
#elif defined(NS_CC3200)
  cc3200_set_non_blocking_mode(sock);
#else
  int flags = fcntl(sock, F_GETFL, 0);
  fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif
}

#ifndef NS_DISABLE_SOCKETPAIR
int ns_socketpair(sock_t sp[2], int sock_type) {
  union socket_address sa;
  sock_t sock;
  socklen_t len = sizeof(sa.sin);
  int ret = 0;

  sock = sp[0] = sp[1] = INVALID_SOCKET;

  (void) memset(&sa, 0, sizeof(sa));
  sa.sin.sin_family = AF_INET;
  sa.sin.sin_port = htons(0);
  sa.sin.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */

  if ((sock = socket(AF_INET, sock_type, 0)) == INVALID_SOCKET) {
  } else if (bind(sock, &sa.sa, len) != 0) {
  } else if (sock_type == SOCK_STREAM && listen(sock, 1) != 0) {
  } else if (getsockname(sock, &sa.sa, &len) != 0) {
  } else if ((sp[0] = socket(AF_INET, sock_type, 0)) == INVALID_SOCKET) {
  } else if (connect(sp[0], &sa.sa, len) != 0) {
  } else if (sock_type == SOCK_DGRAM &&
             (getsockname(sp[0], &sa.sa, &len) != 0 ||
              connect(sock, &sa.sa, len) != 0)) {
  } else if ((sp[1] = (sock_type == SOCK_DGRAM ? sock
                                               : accept(sock, &sa.sa, &len))) ==
             INVALID_SOCKET) {
  } else {
    ns_set_close_on_exec(sp[0]);
    ns_set_close_on_exec(sp[1]);
    if (sock_type == SOCK_STREAM) closesocket(sock);
    ret = 1;
  }

  if (!ret) {
    if (sp[0] != INVALID_SOCKET) closesocket(sp[0]);
    if (sp[1] != INVALID_SOCKET) closesocket(sp[1]);
    if (sock != INVALID_SOCKET) closesocket(sock);
    sock = sp[0] = sp[1] = INVALID_SOCKET;
  }

  return ret;
}
#endif /* NS_DISABLE_SOCKETPAIR */

/* TODO(lsm): use non-blocking resolver */
static int ns_resolve2(const char *host, struct in_addr *ina) {
#ifdef NS_ENABLE_GETADDRINFO
  int rv = 0;
  struct addrinfo hints, *servinfo, *p;
  struct sockaddr_in *h = NULL;
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  if ((rv = getaddrinfo(host, NULL, NULL, &servinfo)) != 0) {
    DBG(("getaddrinfo(%s) failed: %s", host, strerror(errno)));
    return 0;
  }
  for (p = servinfo; p != NULL; p = p->ai_next) {
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
#endif /* NS_ENABLE_GETADDRINFO */
}

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
    conn->flags = opts.flags & _NS_ALLOWED_CONNECT_FLAGS_MASK;
    conn->user_data = opts.user_data;
    /*
     * SIZE_MAX is defined as a long long constant in
     * system headers on some platforms and so it
     * doesn't compile with pedantic ansi flags.
     */
    conn->recv_mbuf_limit = ~0;
  }

  return conn;
}

/* Associate a socket to a connection and and add to the manager. */
NS_INTERNAL void ns_set_sock(struct ns_connection *nc, sock_t sock) {
#ifndef NS_CC3200
  /* Can't get non-blocking connect to work.
   * TODO(rojer): Figure out why it fails where blocking succeeds.
   */
  ns_set_non_blocking_mode(sock);
#endif
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
    sa->sin.sin_addr.s_addr =
        htonl(((uint32_t) a << 24) | ((uint32_t) b << 16) | c << 8 | d);
    sa->sin.sin_port = htons((uint16_t) port);
#ifdef NS_ENABLE_IPV6
  } else if (sscanf(str, "[%99[^]]]:%u%n", buf, &port, &len) == 2 &&
             inet_pton(AF_INET6, buf, &sa->sin6.sin6_addr)) {
    /* IPv6 address, e.g. [3ffe:2a00:100:7031::1]:8080 */
    sa->sin6.sin6_family = AF_INET6;
    sa->sin.sin_port = htons((uint16_t) port);
#endif
#ifndef NS_DISABLE_RESOLVER
  } else if (strlen(str) < host_len &&
             sscanf(str, "%[^ :]:%u%n", host, &port, &len) == 2) {
    sa->sin.sin_port = htons((uint16_t) port);
    if (ns_resolve_from_hosts_file(host, sa) != 0) {
      return 0;
    }
#endif
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
  socklen_t sa_len =
      (sa->sa.sa_family == AF_INET) ? sizeof(sa->sin) : sizeof(sa->sin6);
  sock_t sock = INVALID_SOCKET;
#ifndef NS_CC3200
  int on = 1;
#endif

  if ((sock = socket(sa->sa.sa_family, proto, 0)) != INVALID_SOCKET &&
#ifndef NS_CC3200 /* CC3200 doesn't support either */
#if defined(_WIN32) && defined(SO_EXCLUSIVEADDRUSE)
      /* "Using SO_REUSEADDR and SO_EXCLUSIVEADDRUSE" http://goo.gl/RmrFTm */
      !setsockopt(sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (void *) &on,
                  sizeof(on)) &&
#endif

#if !defined(_WIN32) || !defined(SO_EXCLUSIVEADDRUSE)
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
#endif /* !NS_CC3200 */

      !bind(sock, &sa->sa, sa_len) &&
      (proto == SOCK_DGRAM || listen(sock, SOMAXCONN) == 0)) {
#ifndef NS_CC3200 /* TODO(rojer): Fix this. */
    ns_set_non_blocking_mode(sock);
    /* In case port was set to 0, get the real port number */
    (void) getsockname(sock, &sa->sa, &sa_len);
#endif
  } else if (sock != INVALID_SOCKET) {
    closesocket(sock);
    sock = INVALID_SOCKET;
  }

  return sock;
}

#ifdef NS_ENABLE_SSL
/*
 * Certificate generation script is at
 * https://github.com/cesanta/fossa/blob/master/scripts/generate_ssl_certificates.sh
 */

/*
 * Cipher suite options used for TLS negotiation.
 * https://wiki.mozilla.org/Security/Server_Side_TLS#Recommended_configurations
 */
static const char ns_s_cipher_list[] =
#if defined(NS_SSL_CRYPTO_MODERN)
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:"
    "DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:"
    "ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:"
    "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:"
    "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:"
    "DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:"
    "DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:"
    "!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK"
#elif defined(NS_SSL_CRYPTO_OLD)
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:"
    "DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:"
    "ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:"
    "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:"
    "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:"
    "DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:"
    "DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:"
    "ECDHE-ECDSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:"
    "AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:DES-CBC3-SHA:"
    "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:"
    "!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA"
#else /* Default - intermediate. */
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:"
    "DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:"
    "ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:"
    "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:"
    "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:"
    "DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:"
    "DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:"
    "AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:"
    "DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:"
    "!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA"
#endif
    ;

#ifndef NS_DISABLE_PFS
/*
 * Default DH params for PFS cipher negotiation. This is a 2048-bit group.
 * Will be used if none are provided by the user in the certificate file.
 */
static const char ns_s_default_dh_params[] =
    "\
-----BEGIN DH PARAMETERS-----\n\
MIIBCAKCAQEAlvbgD/qh9znWIlGFcV0zdltD7rq8FeShIqIhkQ0C7hYFThrBvF2E\n\
Z9bmgaP+sfQwGpVlv9mtaWjvERbu6mEG7JTkgmVUJrUt/wiRzwTaCXBqZkdUO8Tq\n\
+E6VOEQAilstG90ikN1Tfo+K6+X68XkRUIlgawBTKuvKVwBhuvlqTGerOtnXWnrt\n\
ym//hd3cd5PBYGBix0i7oR4xdghvfR2WLVu0LgdThTBb6XP7gLd19cQ1JuBtAajZ\n\
wMuPn7qlUkEFDIkAZy59/Hue/H2Q2vU/JsvVhHWCQBL4F1ofEAt50il6ZxR1QfFK\n\
9VGKDC4oOgm9DlxwwBoC2FjqmvQlqVV3kwIBAg==\n\
-----END DH PARAMETERS-----\n";
#endif

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
#ifndef NS_DISABLE_PFS
  } else {
    BIO *bio = NULL;
    DH *dh = NULL;

    /* Try to read DH parameters from the cert/key file. */
    bio = BIO_new_file(pem_file, "r");
    if (bio != NULL) {
      dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
      BIO_free(bio);
    }
    /*
     * If there are no DH params in the file, fall back to hard-coded ones.
     * Not ideal, but better than nothing.
     */
    if (dh == NULL) {
      bio = BIO_new_mem_buf((void *) ns_s_default_dh_params, -1);
      dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
      BIO_free(bio);
    }
    if (dh != NULL) {
      SSL_CTX_set_tmp_dh(ctx, dh);
      SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
      DH_free(dh);
    }

    SSL_CTX_set_mode(ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_use_certificate_chain_file(ctx, pem_file);
    return 0;
#endif
  }
}

/*
 * Turn the connection into SSL mode.
 * `cert` is the certificate file in PEM format. For listening connections,
 * certificate file must contain private key and server certificate,
 * concatenated. It may also contain DH params - these will be used for more
 * secure key exchange. `ca_cert` is a certificate authority (CA) PEM file, and
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
  } else if (!(nc->flags & NSF_LISTENING) && nc->sock != INVALID_SOCKET) {
    /*
     * Socket is open here only if we are connecting to IP address
     * and does not open if we are connecting using async DNS resolver
     */
    SSL_set_fd(nc->ssl, nc->sock);
  }

/* TODO(rojer): remove when krypton exposes this function, even a dummy one */
#ifdef OPENSSL_VERSION_NUMBER
  SSL_CTX_set_cipher_list(nc->ssl_ctx, ns_s_cipher_list);
#endif
  return result;
}

static int ns_ssl_err(struct ns_connection *conn, int res) {
  int ssl_err = SSL_get_error(conn->ssl, res);
  if (ssl_err == SSL_ERROR_WANT_READ) conn->flags |= NSF_WANT_READ;
  if (ssl_err == SSL_ERROR_WANT_WRITE) conn->flags |= NSF_WANT_WRITE;
  return ssl_err;
}
#endif /* NS_ENABLE_SSL */

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
  } else if (ls->ssl_ctx != NULL && ((c->ssl = SSL_new(ls->ssl_ctx)) == NULL ||
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
    c->recv_mbuf_limit = ls->recv_mbuf_limit;
    if (c->ssl == NULL) { /* SSL connections need to perform handshake. */
      ns_call(c, NS_ACCEPT, &sa);
    }
    DBG(("%p %d %p %p", c, c->sock, c->ssl_ctx, c->ssl));
  }

  return c;
}

static int ns_is_error(int n) {
#ifdef NS_CC3200
  DBG(("n = %d, errno = %d", n, errno));
  if (n < 0) errno = n;
#endif
  return n == 0 || (n < 0 && errno != EINTR && errno != EINPROGRESS &&
                    errno != EAGAIN && errno != EWOULDBLOCK
#ifdef NS_CC3200
                    && errno != SL_EALREADY
#endif
#ifdef _WIN32
                    && WSAGetLastError() != WSAEINTR &&
                    WSAGetLastError() != WSAEWOULDBLOCK
#endif
                    );
}

static size_t recv_avail_size(struct ns_connection *conn, size_t max) {
  size_t avail;
  if (conn->recv_mbuf_limit < conn->recv_mbuf.len) return 0;
  avail = conn->recv_mbuf_limit - conn->recv_mbuf.len;
  return avail > max ? max : avail;
}

#ifdef NS_ENABLE_SSL
static void ns_ssl_begin(struct ns_connection *nc) {
  int server_side = nc->listener != NULL;
  int res = server_side ? SSL_accept(nc->ssl) : SSL_connect(nc->ssl);

  if (res == 1) {
    nc->flags |= NSF_SSL_HANDSHAKE_DONE;
    nc->flags &= ~(NSF_WANT_READ | NSF_WANT_WRITE);

    if (server_side) {
      union socket_address sa;
      socklen_t sa_len = sizeof(sa);
      /* In case port was set to 0, get the real port number */
      (void) getsockname(nc->sock, &sa.sa, &sa_len);
      ns_call(nc, NS_ACCEPT, &sa);
    }
  } else {
    int ssl_err = ns_ssl_err(nc, res);
    if (ssl_err != SSL_ERROR_WANT_READ && ssl_err != SSL_ERROR_WANT_WRITE) {
      nc->flags |= NSF_CLOSE_IMMEDIATELY;
    }
  }
}
#endif /* NS_ENABLE_SSL */

static void ns_read_from_socket(struct ns_connection *conn) {
  char buf[NS_READ_BUFFER_SIZE];
  int n = 0, to_recv;

  if (conn->flags & NSF_CONNECTING) {
    int ok = 1, ret;
#ifndef NS_CC3200
    socklen_t len = sizeof(ok);
#endif

    (void) ret;
#ifdef NS_CC3200
    /* On CC3200 we use blocking connect. If we got as far as this,
     * this means connect() was successful.
     * TODO(rojer): Figure out why it fails where blocking succeeds.
     */
    ns_set_non_blocking_mode(conn->sock);
    ret = ok = 0;
#else
    ret = getsockopt(conn->sock, SOL_SOCKET, SO_ERROR, (char *) &ok, &len);
#endif
#ifdef NS_ENABLE_SSL
    if (ret == 0 && ok == 0 && conn->ssl != NULL) {
      ns_ssl_begin(conn);
    }
#endif
    DBG(("%p connect ok=%d", conn, ok));
    if (ok != 0) {
      conn->flags |= NSF_CLOSE_IMMEDIATELY;
    } else {
      conn->flags &= ~NSF_CONNECTING;
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
        DBG(("%p %d bytes <- %d (SSL)", conn, n, conn->sock));
        mbuf_append(&conn->recv_mbuf, buf, n);
        ns_call(conn, NS_RECV, &n);
      }
      ns_ssl_err(conn, n);
    } else {
      ns_ssl_begin(conn);
      return;
    }
  } else
#endif
  {
    to_recv = recv_avail_size(conn, sizeof(buf));
    while ((n = (int) NS_RECV_FUNC(conn->sock, buf, to_recv, 0)) > 0) {
      DBG(("%p %d bytes (PLAIN) <- %d", conn, n, conn->sock));
      mbuf_append(&conn->recv_mbuf, buf, n);
      ns_call(conn, NS_RECV, &n);
#ifdef NS_ESP8266
      /*
       * TODO(alashkin): ESP/RTOS recv implementation tend to block
       * even in non-blocking mode, so, break the loop
       * if received size less than buffer size
       * and wait for next select()
       * Some of RTOS specific call missed?
       */
      if (to_recv > n) {
        break;
      }
      to_recv = recv_avail_size(conn, sizeof(buf));
#endif
    }
    DBG(("recv returns %d", n));
  }

  if (ns_is_error(n)) {
    conn->flags |= NSF_CLOSE_IMMEDIATELY;
  }
}

static void ns_write_to_socket(struct ns_connection *conn) {
  struct mbuf *io = &conn->send_mbuf;
  int n = 0;

  assert(io->len > 0);

#ifdef NS_ENABLE_SSL
  if (conn->ssl != NULL) {
    if (conn->flags & NSF_SSL_HANDSHAKE_DONE) {
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
    } else {
      ns_ssl_begin(conn);
      return;
    }
  } else
#endif
  {
    n = (int) NS_SEND_FUNC(conn->sock, io->buf, io->len, 0);
  }

  DBG(("%p %d bytes -> %d", conn, n, conn->sock));

  if (ns_is_error(n)) {
    conn->flags |= NSF_CLOSE_IMMEDIATELY;
  } else if (n > 0) {
#ifndef NS_DISABLE_FILESYSTEM
    /* LCOV_EXCL_START */
    if (conn->mgr->hexdump_file != NULL) {
      ns_hexdump_connection(conn, conn->mgr->hexdump_file, n, NS_SEND);
    }
/* LCOV_EXCL_STOP */
#endif
    mbuf_remove(io, n);
  }
  ns_call(conn, NS_SEND, &n);
}

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
    nc.recv_mbuf.buf = buf;
    nc.recv_mbuf.len = nc.recv_mbuf.size = n;
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

#define _NSF_FD_CAN_READ 1
#define _NSF_FD_CAN_WRITE 1 << 1
#define _NSF_FD_ERROR 1 << 2

static void ns_mgr_handle_connection(struct ns_connection *nc, int fd_flags,
                                     time_t now) {
  DBG(("%p fd=%d fd_flags=%d nc_flags=%lu rmbl=%d smbl=%d", nc, nc->sock,
       fd_flags, nc->flags, (int) nc->recv_mbuf.len, (int) nc->send_mbuf.len));
  if (fd_flags != 0) nc->last_io_time = now;

  if (nc->flags & NSF_CONNECTING) {
    if (fd_flags != 0) {
      ns_read_from_socket(nc);
    }
    return;
  }

  if (nc->flags & NSF_LISTENING) {
    /*
     * We're not looping here, and accepting just one connection at
     * a time. The reason is that eCos does not respect non-blocking
     * flag on a listening socket and hangs in a loop.
     */
    if (fd_flags & _NSF_FD_CAN_READ) accept_conn(nc);
    return;
  }

  if (fd_flags & _NSF_FD_CAN_READ) {
    if (nc->flags & NSF_UDP) {
      ns_handle_udp(nc);
    } else {
      ns_read_from_socket(nc);
    }
    if (nc->flags & NSF_CLOSE_IMMEDIATELY) return;
  }

  if ((fd_flags & _NSF_FD_CAN_WRITE) && !(nc->flags & NSF_DONT_SEND) &&
      !(nc->flags & NSF_UDP)) { /* Writes to UDP sockets are not buffered. */
    ns_write_to_socket(nc);
  }

  if (!(fd_flags & (_NSF_FD_CAN_READ | _NSF_FD_CAN_WRITE))) {
    ns_call(nc, NS_POLL, &now);
  }

  DBG(("%p after fd=%d nc_flags=%lu rmbl=%d smbl=%d", nc, nc->sock, nc->flags,
       (int) nc->recv_mbuf.len, (int) nc->send_mbuf.len));
}

static void ns_mgr_handle_ctl_sock(struct ns_mgr *mgr) {
  struct ctl_msg ctl_msg;
  int len =
      (int) NS_RECV_FUNC(mgr->ctl[1], (char *) &ctl_msg, sizeof(ctl_msg), 0);
  NS_SEND_FUNC(mgr->ctl[1], ctl_msg.message, 1, 0);
  if (len >= (int) sizeof(ctl_msg.callback) && ctl_msg.callback != NULL) {
    struct ns_connection *nc;
    for (nc = ns_next(mgr, NULL); nc != NULL; nc = ns_next(mgr, nc)) {
      ctl_msg.callback(nc, NS_POLL, ctl_msg.message);
    }
  }
}

#if NS_MGR_EV_MGR == 1 /* epoll() */

#ifndef NS_EPOLL_MAX_EVENTS
#define NS_EPOLL_MAX_EVENTS 100
#endif

#define _NS_EPF_EV_EPOLLIN (1 << 0)
#define _NS_EPF_EV_EPOLLOUT (1 << 1)
#define _NS_EPF_NO_POLL (1 << 2)

static uint32_t ns_epf_to_evflags(unsigned int epf) {
  uint32_t result = 0;
  if (epf & _NS_EPF_EV_EPOLLIN) result |= EPOLLIN;
  if (epf & _NS_EPF_EV_EPOLLOUT) result |= EPOLLOUT;
  return result;
}

static void ns_ev_mgr_epoll_set_flags(const struct ns_connection *nc,
                                      struct epoll_event *ev) {
  /* NOTE: EPOLLERR and EPOLLHUP are always enabled. */
  ev->events = 0;
  if (nc->recv_mbuf.len < nc->recv_mbuf_limit) {
    ev->events |= EPOLLIN;
  }
  if ((nc->flags & NSF_CONNECTING) ||
      (nc->send_mbuf.len > 0 && !(nc->flags & NSF_DONT_SEND))) {
    ev->events |= EPOLLOUT;
  }
}

static void ns_ev_mgr_epoll_ctl(struct ns_connection *nc, int op) {
  int epoll_fd = (intptr_t) nc->mgr->mgr_data;
  struct epoll_event ev;
  assert(op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD || EPOLL_CTL_DEL);
  if (op != EPOLL_CTL_DEL) {
    ns_ev_mgr_epoll_set_flags(nc, &ev);
    if (op == EPOLL_CTL_MOD) {
      uint32_t old_ev_flags = ns_epf_to_evflags((intptr_t) nc->mgr_data);
      if (ev.events == old_ev_flags) return;
    }
    ev.data.ptr = nc;
  }
  if (epoll_ctl(epoll_fd, op, nc->sock, &ev) != 0) {
    perror("epoll_ctl");
    abort();
  }
}

static void ns_ev_mgr_init(struct ns_mgr *mgr) {
  int epoll_fd;
  DBG(("%p using epoll()", mgr));
  epoll_fd = epoll_create(NS_EPOLL_MAX_EVENTS /* unused but required */);
  if (epoll_fd < 0) {
    perror("epoll_ctl");
    abort();
  }
  mgr->mgr_data = (void *) ((intptr_t) epoll_fd);
  if (mgr->ctl[1] != INVALID_SOCKET) {
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = NULL;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, mgr->ctl[1], &ev) != 0) {
      perror("epoll_ctl");
      abort();
    }
  }
}

static void ns_ev_mgr_free(struct ns_mgr *mgr) {
  int epoll_fd = (intptr_t) mgr->mgr_data;
  close(epoll_fd);
}

static void ns_ev_mgr_add_conn(struct ns_connection *nc) {
  ns_ev_mgr_epoll_ctl(nc, EPOLL_CTL_ADD);
}

static void ns_ev_mgr_remove_conn(struct ns_connection *nc) {
  ns_ev_mgr_epoll_ctl(nc, EPOLL_CTL_DEL);
}

time_t ns_mgr_poll(struct ns_mgr *mgr, int timeout_ms) {
  int epoll_fd = (intptr_t) mgr->mgr_data;
  struct epoll_event events[NS_EPOLL_MAX_EVENTS];
  struct ns_connection *nc, *next;
  int num_ev, fd_flags;
  time_t now;

  num_ev = epoll_wait(epoll_fd, events, NS_EPOLL_MAX_EVENTS, timeout_ms);
  now = time(NULL);
  DBG(("epoll_wait @ %ld num_ev=%d", (long) now, num_ev));

  while (num_ev-- > 0) {
    intptr_t epf;
    struct epoll_event *ev = events + num_ev;
    nc = (struct ns_connection *) ev->data.ptr;
    if (nc == NULL) {
      ns_mgr_handle_ctl_sock(mgr);
      continue;
    }
    fd_flags = ((ev->events & (EPOLLIN | EPOLLHUP)) ? _NSF_FD_CAN_READ : 0) |
               ((ev->events & (EPOLLOUT)) ? _NSF_FD_CAN_WRITE : 0) |
               ((ev->events & (EPOLLERR)) ? _NSF_FD_ERROR : 0);
    ns_mgr_handle_connection(nc, fd_flags, now);
    epf = (intptr_t) nc->mgr_data;
    epf ^= _NS_EPF_NO_POLL;
    nc->mgr_data = (void *) epf;
  }

  for (nc = mgr->active_connections; nc != NULL; nc = next) {
    next = nc->next;
    if (!(((intptr_t) nc->mgr_data) & _NS_EPF_NO_POLL)) {
      ns_mgr_handle_connection(nc, 0, now);
    } else {
      intptr_t epf = (intptr_t) nc->mgr_data;
      epf ^= _NS_EPF_NO_POLL;
      nc->mgr_data = (void *) epf;
    }
    if ((nc->flags & NSF_CLOSE_IMMEDIATELY) ||
        (nc->send_mbuf.len == 0 && (nc->flags & NSF_SEND_AND_CLOSE))) {
      ns_close_conn(nc);
    } else {
      ns_ev_mgr_epoll_ctl(nc, EPOLL_CTL_MOD);
    }
  }

  return now;
}

#else /* select() */

static void ns_ev_mgr_init(struct ns_mgr *mgr) {
  (void) mgr;
  DBG(("%p using select()", mgr));
}

static void ns_ev_mgr_free(struct ns_mgr *mgr) {
  (void) mgr;
}

static void ns_ev_mgr_add_conn(struct ns_connection *nc) {
  (void) nc;
}

static void ns_ev_mgr_remove_conn(struct ns_connection *nc) {
  (void) nc;
}

static void ns_add_to_set(sock_t sock, fd_set *set, sock_t *max_fd) {
  if (sock != INVALID_SOCKET) {
    FD_SET(sock, set);
    if (*max_fd == INVALID_SOCKET || sock > *max_fd) {
      *max_fd = sock;
    }
  }
}

time_t ns_mgr_poll(struct ns_mgr *mgr, int milli) {
  time_t now;
  struct ns_connection *nc, *tmp;
  struct timeval tv;
  fd_set read_set, write_set, err_set;
  sock_t max_fd = INVALID_SOCKET;
  int num_selected;

  FD_ZERO(&read_set);
  FD_ZERO(&write_set);
  FD_ZERO(&err_set);
  ns_add_to_set(mgr->ctl[1], &read_set, &max_fd);

  for (nc = mgr->active_connections; nc != NULL; nc = tmp) {
    tmp = nc->next;

    if (!(nc->flags & NSF_WANT_WRITE) &&
        nc->recv_mbuf.len < nc->recv_mbuf_limit) {
      ns_add_to_set(nc->sock, &read_set, &max_fd);
    }

    if (((nc->flags & NSF_CONNECTING) && !(nc->flags & NSF_WANT_READ)) ||
        (nc->send_mbuf.len > 0 && !(nc->flags & NSF_CONNECTING) &&
         !(nc->flags & NSF_DONT_SEND))) {
      ns_add_to_set(nc->sock, &write_set, &max_fd);
      ns_add_to_set(nc->sock, &err_set, &max_fd);
    }
  }

  tv.tv_sec = milli / 1000;
  tv.tv_usec = (milli % 1000) * 1000;

  num_selected = select((int) max_fd + 1, &read_set, &write_set, &err_set, &tv);
  now = time(NULL);
  DBG(("select @ %ld num_ev=%d", (long) now, num_selected));

  if (num_selected > 0 && mgr->ctl[1] != INVALID_SOCKET &&
      FD_ISSET(mgr->ctl[1], &read_set)) {
    ns_mgr_handle_ctl_sock(mgr);
  }

  for (nc = mgr->active_connections; nc != NULL; nc = tmp) {
    int fd_flags = 0;
    if (num_selected > 0) {
      fd_flags = (FD_ISSET(nc->sock, &read_set) ? _NSF_FD_CAN_READ : 0) |
                 (FD_ISSET(nc->sock, &write_set) ? _NSF_FD_CAN_WRITE : 0) |
                 (FD_ISSET(nc->sock, &err_set) ? _NSF_FD_ERROR : 0);
    }
#ifdef NS_CC3200
    // CC3200 does not report UDP sockets as writeable.
    if (nc->flags & NSF_UDP &&
        (nc->send_mbuf.len > 0 || nc->flags & NSF_CONNECTING)) {
      fd_flags |= _NSF_FD_CAN_WRITE;
    }
#endif
    tmp = nc->next;
    ns_mgr_handle_connection(nc, fd_flags, now);
  }

  for (nc = mgr->active_connections; nc != NULL; nc = tmp) {
    tmp = nc->next;
    if ((nc->flags & NSF_CLOSE_IMMEDIATELY) ||
        (nc->send_mbuf.len == 0 && (nc->flags & NSF_SEND_AND_CLOSE))) {
      ns_close_conn(nc);
    }
  }

  return now;
}

#endif

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
    if (nc->flags & NSF_CONNECTING) {
      ns_call(nc, NS_CONNECT, &failure);
    }
    ns_destroy_conn(nc);
    return NULL;
  }

#ifndef NS_CC3200
  ns_set_non_blocking_mode(sock);
#endif
  rc = (proto == SOCK_DGRAM) ? 0 : connect(sock, &sa->sa, sizeof(sa->sin));

  if (rc != 0 && ns_is_error(rc)) {
    NS_SET_PTRPTR(o.error_string, "cannot connect to socket");
    if (nc->flags & NSF_CONNECTING) {
      ns_call(nc, NS_CONNECT, &rc);
    }
    ns_destroy_conn(nc);
    close(sock);
    return NULL;
  }

  /* Fire NS_CONNECT on next poll. */
  nc->flags |= NSF_CONNECTING;

  /* No ns_destroy_conn() call after this! */
  ns_set_sock(nc, sock);

#ifdef NS_ENABLE_SSL
  /*
   * If we are using async resolver, socket isn't open
   * before this place, so
   * for SSL connections we have to add socket to SSL fd set
   */
  if (nc->ssl != NULL && !(nc->flags & NSF_LISTENING)) {
    SSL_set_fd(nc->ssl, nc->sock);
  }
#endif

  return nc;
}

#ifndef NS_DISABLE_RESOLVER
/*
 * Callback for the async resolver on ns_connect_opt() call.
 * Main task of this function is to trigger NS_CONNECT event with
 *    either failure (and dealloc the connection)
 *    or success (and proceed with connect()
 */
static void resolve_cb(struct ns_dns_message *msg, void *data) {
  struct ns_connection *nc = (struct ns_connection *) data;
  int i;
  int failure = -1;

  if (msg != NULL) {
    /*
     * Take the first DNS A answer and run...
     */
    for (i = 0; i < msg->num_answers; i++) {
      if (msg->answers[i].rtype == NS_DNS_A_RECORD) {
        static struct ns_add_sock_opts opts;
        /*
         * Async resolver guarantees that there is at least one answer.
         * TODO(lsm): handle IPv6 answers too
         */
        ns_dns_parse_record_data(msg, &msg->answers[i], &nc->sa.sin.sin_addr,
                                 4);
        /* Make ns_finish_connect() trigger NS_CONNECT on failure */
        nc->flags |= NSF_CONNECTING;
        ns_finish_connect(nc, nc->flags & NSF_UDP ? SOCK_DGRAM : SOCK_STREAM,
                          &nc->sa, opts);
        return;
      }
    }
  }

  /*
   * If we get there was no NS_DNS_A_RECORD in the answer
   */
  ns_call(nc, NS_CONNECT, &failure);
  ns_destroy_conn(nc);
}
#endif

struct ns_connection *ns_connect(struct ns_mgr *mgr, const char *address,
                                 ns_event_handler_t callback) {
  static struct ns_connect_opts opts;
  return ns_connect_opt(mgr, address, callback, opts);
}

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
  nc->flags |= opts.flags & _NS_ALLOWED_CONNECT_FLAGS_MASK;
  nc->flags |= (proto == SOCK_DGRAM) ? NSF_UDP : 0;
  nc->user_data = opts.user_data;

  if (rc == 0) {
#ifndef NS_DISABLE_RESOLVER
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
#else
    NS_SET_PTRPTR(opts.error_string, "Resolver is disabled");
    ns_destroy_conn(nc);
    return NULL;
#endif
  } else {
    /* Address is parsed and resolved to IP. proceed with connect() */
    return ns_finish_connect(nc, proto, &nc->sa, add_sock_opts);
  }
}

struct ns_connection *ns_bind(struct ns_mgr *srv, const char *address,
                              ns_event_handler_t event_handler) {
  static struct ns_bind_opts opts;
  return ns_bind_opt(srv, address, event_handler, opts);
}

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
  } else if ((nc = ns_add_sock_opt(mgr, sock, callback, add_sock_opts)) ==
             NULL) {
    /* opts.error_string set by ns_add_sock_opt */
    DBG(("Failed to ns_add_sock"));
    closesocket(sock);
  } else {
    nc->sa = sa;
    nc->handler = callback;

    if (proto == SOCK_DGRAM) {
      nc->flags |= NSF_UDP;
    } else {
      nc->flags |= NSF_LISTENING;
    }

    DBG(("%p sock %d/%d", nc, sock, proto));
  }

  return nc;
}

struct ns_connection *ns_add_sock(struct ns_mgr *s, sock_t sock,
                                  ns_event_handler_t callback) {
  static struct ns_add_sock_opts opts;
  return ns_add_sock_opt(s, sock, callback, opts);
}

struct ns_connection *ns_add_sock_opt(struct ns_mgr *s, sock_t sock,
                                      ns_event_handler_t callback,
                                      struct ns_add_sock_opts opts) {
  struct ns_connection *nc = ns_create_connection(s, callback, opts);
  if (nc != NULL) {
    ns_set_sock(nc, sock);
  }
  return nc;
}

struct ns_connection *ns_next(struct ns_mgr *s, struct ns_connection *conn) {
  return conn == NULL ? s->active_connections : conn->next;
}

void ns_broadcast(struct ns_mgr *mgr, ns_event_handler_t cb, void *data,
                  size_t len) {
  struct ctl_msg ctl_msg;

  /*
   * Fossa manager has a socketpair, `struct ns_mgr::ctl`,
   * where `ns_broadcast()` pushes the message.
   * `ns_mgr_poll()` wakes up, reads a message from the socket pair, and calls
   * specified callback for each connection. Thus the callback function executes
   * in event manager thread.
   */
  if (mgr->ctl[0] != INVALID_SOCKET && data != NULL &&
      len < sizeof(ctl_msg.message)) {
    ctl_msg.callback = cb;
    memcpy(ctl_msg.message, data, len);
    NS_SEND_FUNC(mgr->ctl[0], (char *) &ctl_msg,
                 offsetof(struct ctl_msg, message) + len, 0);
    NS_RECV_FUNC(mgr->ctl[0], (char *) &len, 1, 0);
  }
}

static int isbyte(int n) {
  return n >= 0 && n <= 255;
}

static int parse_net(const char *spec, uint32_t *net, uint32_t *mask) {
  int n, a, b, c, d, slash = 32, len = 0;

  if ((sscanf(spec, "%d.%d.%d.%d/%d%n", &a, &b, &c, &d, &slash, &n) == 5 ||
       sscanf(spec, "%d.%d.%d.%d%n", &a, &b, &c, &d, &n) == 4) &&
      isbyte(a) && isbyte(b) && isbyte(c) && isbyte(d) && slash >= 0 &&
      slash < 33) {
    len = n;
    *net =
        ((uint32_t) a << 24) | ((uint32_t) b << 16) | ((uint32_t) c << 8) | d;
    *mask = slash ? 0xffffffffU << (32 - slash) : 0;
  }

  return len;
}

int ns_check_ip_acl(const char *acl, uint32_t remote_ip) {
  int allowed, flag;
  uint32_t net, mask;
  struct ns_str vec;

  /* If any ACL is set, deny by default */
  allowed = (acl == NULL || *acl == '\0') ? '+' : '-';

  while ((acl = ns_next_comma_list_entry(acl, &vec, NULL)) != NULL) {
    flag = vec.p[0];
    if ((flag != '+' && flag != '-') ||
        parse_net(&vec.p[1], &net, &mask) == 0) {
      return -1;
    }

    if (net == (remote_ip & mask)) {
      allowed = flag;
    }
  }

  return allowed == '+';
}

/* Move data from one connection to another */
void ns_forward(struct ns_connection *from, struct ns_connection *to) {
  ns_send(to, from->recv_mbuf.buf, from->recv_mbuf.len);
  mbuf_remove(&from->recv_mbuf, from->recv_mbuf.len);
}
