#include "net_skeleton.h"
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
//
// $Date: 2014-09-28 05:04:41 UTC $


#ifndef NS_MALLOC
#define NS_MALLOC malloc
#endif

#ifndef NS_REALLOC
#define NS_REALLOC realloc
#endif

#ifndef NS_FREE
#define NS_FREE free
#endif

#define NS_UDP_RECEIVE_BUFFER_SIZE  2000
#define NS_VPRINTF_BUFFER_SIZE      500

struct ctl_msg {
  ns_event_handler_t callback;
  char message[1024 * 8];
};

void iobuf_resize(struct iobuf *io, size_t new_size) {
  char *p;
  if ((new_size > io->size || (new_size < io->size && new_size >= io->len)) &&
      (p = (char *) NS_REALLOC(io->buf, new_size)) != NULL) {
    io->size = new_size;
    io->buf = p;
  }
}

void iobuf_init(struct iobuf *iobuf, size_t initial_size) {
  iobuf->len = iobuf->size = 0;
  iobuf->buf = NULL;
  iobuf_resize(iobuf, initial_size);
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

static size_t ns_out(struct ns_connection *nc, const void *buf, size_t len) {
  if (nc->flags & NSF_UDP) {
    long n = sendto(nc->sock, buf, len, 0, &nc->sa.sa, sizeof(nc->sa.sin));
    DBG(("%p %d send %ld (%d %s)", nc, nc->sock, n, errno, strerror(errno)));
    return n < 0 ? 0 : n;
  } else {
    return iobuf_append(&nc->send_iobuf, buf, len);
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

#if defined(NS_STACK_SIZE) && NS_STACK_SIZE > 1
  (void) pthread_attr_setstacksize(&attr, NS_STACK_SIZE);
#endif

  pthread_create(&thread_id, &attr, f, p);
  pthread_attr_destroy(&attr);

  return (void *) thread_id;
#endif
}
#endif  // NS_DISABLE_THREADS

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

// Print message to buffer. If buffer is large enough to hold the message,
// return buffer. If buffer is to small, allocate large enough buffer on heap,
// and return allocated buffer.
int ns_avprintf(char **buf, size_t size, const char *fmt, va_list ap) {
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

int ns_vprintf(struct ns_connection *nc, const char *fmt, va_list ap) {
  char mem[NS_VPRINTF_BUFFER_SIZE], *buf = mem;
  int len;

  if ((len = ns_avprintf(&buf, sizeof(mem), fmt, ap)) > 0) {
    ns_out(nc, buf, len);
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

static void hexdump(struct ns_connection *nc, const char *path,
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
      free(buf);
    }
    fclose(fp);
  }
}

static void ns_call(struct ns_connection *nc, int ev, void *p) {
  if (nc->mgr->hexdump_file != NULL && ev != NS_POLL) {
    int len = (ev == NS_RECV || ev == NS_SEND) ? * (int *) p : 0;
    hexdump(nc, nc->mgr->hexdump_file, len, ev);
  }

  nc->callback(nc, ev, p);
}

static void ns_destroy_conn(struct ns_connection *conn) {
  closesocket(conn->sock);
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
  DBG(("%p %d", conn, conn->flags));
  ns_call(conn, NS_CLOSE, NULL);
  ns_remove_conn(conn);
  ns_destroy_conn(conn);
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

// TODO(lsm): use non-blocking resolver
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

// Resolve FDQN "host", store IP address in the "ip".
// Return > 0 (IP address length) on success.
int ns_resolve(const char *host, char *buf, size_t n) {
  struct in_addr ad;
  return ns_resolve2(host, &ad) ? snprintf(buf, n, "%s", inet_ntoa(ad)) : 0;
}

// Address format: [PROTO://][IP_ADDRESS:]PORT[:CERT][:CA_CERT]
static int ns_parse_address(const char *str, union socket_address *sa,
                            int *proto, int *use_ssl, char *cert, char *ca) {
  unsigned int a, b, c, d, port;
  int n = 0, len = 0;
  char host[200];
#ifdef NS_ENABLE_IPV6
  char buf[100];
#endif

  // MacOS needs that. If we do not zero it, subsequent bind() will fail.
  // Also, all-zeroes in the socket address means binding to all addresses
  // for both IPv4 and IPv6 (INADDR_ANY and IN6ADDR_ANY_INIT).
  memset(sa, 0, sizeof(*sa));
  sa->sin.sin_family = AF_INET;

  *proto = SOCK_STREAM;
  *use_ssl = 0;
  cert[0] = ca[0] = '\0';

  if (memcmp(str, "ssl://", 6) == 0) {
    str += 6;
    *use_ssl = 1;
  } else if (memcmp(str, "udp://", 6) == 0) {
    str += 6;
    *proto = SOCK_DGRAM;
  } else if (memcmp(str, "tcp://", 6) == 0) {
    str += 6;
  }

  if (sscanf(str, "%u.%u.%u.%u:%u%n", &a, &b, &c, &d, &port, &len) == 5) {
    // Bind to a specific IPv4 address, e.g. 192.168.1.5:8080
    sa->sin.sin_addr.s_addr = htonl((a << 24) | (b << 16) | (c << 8) | d);
    sa->sin.sin_port = htons((uint16_t) port);
#ifdef NS_ENABLE_IPV6
  } else if (sscanf(str, "[%99[^]]]:%u%n", buf, &port, &len) == 2 &&
             inet_pton(AF_INET6, buf, &sa->sin6.sin6_addr)) {
    // IPv6 address, e.g. [3ffe:2a00:100:7031::1]:8080
    sa->sin6.sin6_family = AF_INET6;
    sa->sin6.sin6_port = htons((uint16_t) port);
#endif
  } else if (sscanf(str, "%199[^ :]:%u%n", host, &port, &len) == 2) {
    sa->sin.sin_port = htons((uint16_t) port);
    ns_resolve2(host, &sa->sin.sin_addr);
  } else if (sscanf(str, "%u%n", &port, &len) == 1) {
    // If only port is specified, bind to IPv4, INADDR_ANY
    sa->sin.sin_port = htons((uint16_t) port);
  }

  if (*use_ssl && (sscanf(str + len, ":%99[^:]:%99[^:]%n", cert, ca, &n) == 2 ||
                   sscanf(str + len, ":%99[^:]%n", cert, &n) == 1)) {
    len += n;
  }

  return port < 0xffff && str[len] == '\0' ? len : 0;
}

// 'sa' must be an initialized address to bind to
static sock_t ns_open_listening_socket(union socket_address *sa, int proto) {
  socklen_t sa_len = (sa->sa.sa_family == AF_INET) ?
    sizeof(sa->sin) : sizeof(sa->sin6);
  sock_t sock = INVALID_SOCKET;
#ifndef _WIN32
  int on = 1;
#endif

  if ((sock = socket(sa->sa.sa_family, proto, 0)) != INVALID_SOCKET &&
#ifndef _WIN32
      // SO_RESUSEADDR is not enabled on Windows because the semantics of
      // SO_REUSEADDR on UNIX and Windows is different. On Windows,
      // SO_REUSEADDR allows to bind a socket to a port without error even if
      // the port is already open by another program. This is not the behavior
      // SO_REUSEADDR was designed for, and leads to hard-to-track failure
      // scenarios. Therefore, SO_REUSEADDR was disabled on Windows.
      !setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on)) &&
#endif
      !bind(sock, &sa->sa, sa_len) &&
      (proto == SOCK_DGRAM || listen(sock, SOMAXCONN) == 0)) {
    ns_set_non_blocking_mode(sock);
    // In case port was set to 0, get the real port number
    (void) getsockname(sock, &sa->sa, &sa_len);
  } else if (sock != INVALID_SOCKET) {
    closesocket(sock);
    sock = INVALID_SOCKET;
  }

  return sock;
}

#ifdef NS_ENABLE_SSL
// Certificate generation script is at
// https://github.com/cesanta/net_skeleton/blob/master/scripts/gen_certs.sh

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
#endif  // NS_ENABLE_SSL

struct ns_connection *ns_bind(struct ns_mgr *srv, const char *str,
                              ns_event_handler_t callback) {
  union socket_address sa;
  struct ns_connection *nc = NULL;
  int use_ssl, proto;
  char cert[100], ca_cert[100];
  sock_t sock;

  ns_parse_address(str, &sa, &proto, &use_ssl, cert, ca_cert);
  if (use_ssl && cert[0] == '\0') return NULL;

  if ((sock = ns_open_listening_socket(&sa, proto)) == INVALID_SOCKET) {
  } else if ((nc = ns_add_sock(srv, sock, callback)) == NULL) {
    closesocket(sock);
  } else {
    nc->sa = sa;
    nc->flags |= NSF_LISTENING;
    nc->callback = callback;

    if (proto == SOCK_DGRAM) {
      nc->flags |= NSF_UDP;
    }

#ifdef NS_ENABLE_SSL
    if (use_ssl) {
      nc->ssl_ctx = SSL_CTX_new(SSLv23_server_method());
      if (ns_use_cert(nc->ssl_ctx, cert) != 0 ||
          ns_use_ca_cert(nc->ssl_ctx, ca_cert) != 0) {
        ns_close_conn(nc);
        nc = NULL;
      }
    }
#endif

    DBG(("%p sock %d/%d ssl %p %p", nc, sock, proto, nc->ssl_ctx, nc->ssl));
  }

  return nc;
}

static struct ns_connection *accept_conn(struct ns_connection *ls) {
  struct ns_connection *c = NULL;
  union socket_address sa;
  socklen_t len = sizeof(sa);
  sock_t sock = INVALID_SOCKET;

  // NOTE(lsm): on Windows, sock is always > FD_SETSIZE
  if ((sock = accept(ls->sock, &sa.sa, &len)) == INVALID_SOCKET) {
  } else if ((c = ns_add_sock(ls->mgr, sock, ls->callback)) == NULL) {
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
      inet_ntop(sa.sa.sa_family, (void *) &sa.sin.sin_addr, buf,(socklen_t)len);
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

#ifdef NS_ENABLE_SSL
static int ns_ssl_err(struct ns_connection *conn, int res) {
  int ssl_err = SSL_get_error(conn->ssl, res);
  if (ssl_err == SSL_ERROR_WANT_READ) conn->flags |= NSF_WANT_READ;
  if (ssl_err == SSL_ERROR_WANT_WRITE) conn->flags |= NSF_WANT_WRITE;
  return ssl_err;
}
#endif

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
      int ssl_err = ns_ssl_err(conn, res);
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
      // SSL library may have more bytes ready to read then we ask to read.
      // Therefore, read in a loop until we read everything. Without the loop,
      // we skip to the next select() cycle which can just timeout.
      while ((n = SSL_read(conn->ssl, buf, sizeof(buf))) > 0) {
        DBG(("%p %d <- %d bytes (SSL)", conn, conn->flags, n));
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
        return; // Call us again
      } else {
        conn->flags |= NSF_CLOSE_IMMEDIATELY;
      }
      return;
    }
  } else
#endif
  {
    while ((n = (int) recv(conn->sock, buf, sizeof(buf), 0)) > 0) {
      DBG(("%p %d <- %d bytes (PLAIN)", conn, conn->flags, n));
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
        return; // Call us again
      } else {
        conn->flags |= NSF_CLOSE_IMMEDIATELY;
      }
    }
  } else
#endif
  { n = (int) send(conn->sock, io->buf, io->len, 0); }

  DBG(("%p %d -> %d bytes", conn, conn->flags, n));

  ns_call(conn, NS_SEND, &n);
  if (ns_is_error(n)) {
    conn->flags |= NSF_CLOSE_IMMEDIATELY;
  } else if (n > 0) {
    iobuf_remove(io, n);
  }
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
    nc.mgr = ls->mgr;
    nc.recv_iobuf.buf = buf;
    nc.recv_iobuf.len = nc.recv_iobuf.size = n;
    nc.sock = ls->sock;
    nc.callback = ls->callback;
    nc.user_data = ls->user_data;
    nc.proto_data = ls->proto_data;
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

time_t ns_mgr_poll(struct ns_mgr *mgr, int milli) {
  struct ns_connection *conn, *tmp_conn;
  struct timeval tv;
  fd_set read_set, write_set;
  sock_t max_fd = INVALID_SOCKET;
  time_t current_time = time(NULL);

  FD_ZERO(&read_set);
  FD_ZERO(&write_set);
  ns_add_to_set(mgr->ctl[1], &read_set, &max_fd);

  for (conn = mgr->active_connections; conn != NULL; conn = tmp_conn) {
    tmp_conn = conn->next;
    if (!(conn->flags & (NSF_LISTENING | NSF_CONNECTING))) {
      ns_call(conn, NS_POLL, &current_time);
    }
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

    // Read wakeup messages
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

    for (conn = mgr->active_connections; conn != NULL; conn = tmp_conn) {
      tmp_conn = conn->next;
      if (FD_ISSET(conn->sock, &read_set)) {
        if (conn->flags & NSF_LISTENING) {
          if (conn->flags & NSF_UDP) {
            ns_handle_udp(conn);
          } else {
            // We're not looping here, and accepting just one connection at
            // a time. The reason is that eCos does not respect non-blocking
            // flag on a listening socket and hangs in a loop.
            accept_conn(conn);
          }
        } else {
          conn->last_io_time = current_time;
          ns_read_from_socket(conn);
        }
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

  for (conn = mgr->active_connections; conn != NULL; conn = tmp_conn) {
    tmp_conn = conn->next;
    if ((conn->flags & NSF_CLOSE_IMMEDIATELY) ||
        (conn->send_iobuf.len == 0 &&
          (conn->flags & NSF_FINISHED_SENDING_DATA))) {
      ns_close_conn(conn);
    }
  }

  return current_time;
}

struct ns_connection *ns_connect(struct ns_mgr *mgr, const char *address,
                                 ns_event_handler_t callback) {
  sock_t sock = INVALID_SOCKET;
  struct ns_connection *nc = NULL;
  union socket_address sa;
  char cert[100], ca_cert[100];
  int rc, use_ssl, proto;

  ns_parse_address(address, &sa, &proto, &use_ssl, cert, ca_cert);
  if ((sock = socket(AF_INET, proto, 0)) == INVALID_SOCKET) {
    return NULL;
  }
  ns_set_non_blocking_mode(sock);
  rc = (proto == SOCK_DGRAM) ? 0 : connect(sock, &sa.sa, sizeof(sa.sin));

  if (rc != 0 && ns_is_error(rc)) {
    closesocket(sock);
    return NULL;
  } else if ((nc = ns_add_sock(mgr, sock, callback)) == NULL) {
    closesocket(sock);
    return NULL;
  }

  nc->sa = sa;   // Important, cause UDP conns will use sendto()
  nc->flags = (proto == SOCK_DGRAM) ? NSF_UDP : NSF_CONNECTING;

#ifdef NS_ENABLE_SSL
  if (use_ssl) {
    if ((nc->ssl_ctx = SSL_CTX_new(SSLv23_client_method())) == NULL ||
        ns_use_cert(nc->ssl_ctx, cert) != 0 ||
        ns_use_ca_cert(nc->ssl_ctx, ca_cert) != 0 ||
        (nc->ssl = SSL_new(nc->ssl_ctx)) == NULL) {
      ns_close_conn(nc);
      return NULL;
    } else {
      SSL_set_fd(nc->ssl, sock);
    }
  }
#endif

  return nc;
}

struct ns_connection *ns_add_sock(struct ns_mgr *s, sock_t sock,
                                  ns_event_handler_t callback) {
  struct ns_connection *conn;
  if ((conn = (struct ns_connection *) NS_MALLOC(sizeof(*conn))) != NULL) {
    memset(conn, 0, sizeof(*conn));
    ns_set_non_blocking_mode(sock);
    ns_set_close_on_exec(sock);
    conn->sock = sock;
    conn->callback = callback;
    conn->mgr = s;
    conn->last_io_time = time(NULL);
    ns_add_conn(s, conn);
    DBG(("%p %d", conn, sock));
  }
  return conn;
}

struct ns_connection *ns_next(struct ns_mgr *s, struct ns_connection *conn) {
  return conn == NULL ? s->active_connections : conn->next;
}

void ns_broadcast(struct ns_mgr *mgr, ns_event_handler_t cb,void *data, size_t len) {
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

void ns_mgr_init(struct ns_mgr *s, void *user_data) {
  memset(s, 0, sizeof(*s));
  s->ctl[0] = s->ctl[1] = INVALID_SOCKET;
  s->user_data = user_data;

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
  {static int init_done; if (!init_done) { SSL_library_init(); init_done++; }}
#endif
}

void ns_mgr_free(struct ns_mgr *s) {
  struct ns_connection *conn, *tmp_conn;

  DBG(("%p", s));
  if (s == NULL) return;
  // Do one last poll, see https://github.com/cesanta/mongoose/issues/286
  ns_mgr_poll(s, 0);

  if (s->ctl[0] != INVALID_SOCKET) closesocket(s->ctl[0]);
  if (s->ctl[1] != INVALID_SOCKET) closesocket(s->ctl[1]);
  s->ctl[0] = s->ctl[1] = INVALID_SOCKET;

  for (conn = s->active_connections; conn != NULL; conn = tmp_conn) {
    tmp_conn = conn->next;
    ns_close_conn(conn);
  }
}
// Copyright (c) 2004-2013 Sergey Lyubka <valenok@gmail.com>
// Copyright (c) 2013 Cesanta Software Limited
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
// license, as set out in <http://cesanta.com/products.html>.

#define _CRT_SECURE_NO_WARNINGS // Disable deprecation warning in VS2005+

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

// identifier = letter { letter | digit | '_' }
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

// string = '"' { quoted_printable_chars } '"'
static int parse_string(struct frozen *f) {
  int n, ch = 0, len = 0;
  TRY(test_and_skip(f, '"'));
  TRY(capture_ptr(f, f->cur, JSON_TYPE_STRING));
  for (; f->cur < f->end; f->cur += len) {
    ch = * (unsigned char *) f->cur;
    len = get_utf8_char_len((unsigned char) ch);
    //printf("[%c] [%d]\n", ch, len);
    EXPECT(ch >= 32 && len > 0, JSON_STRING_INVALID);  // No control chars
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

// number = [ '-' ] digit+ [ '.' digit+ ] [ ['e'|'E'] ['+'|'-'] digit+ ]
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

// array = '[' [ value { ',' value } ] ']'
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

// value = 'null' | 'true' | 'false' | number | string | array | object
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

// key = identifier | string
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

// pair = key ':' value
static int parse_pair(struct frozen *f) {
  TRY(parse_key(f));
  TRY(test_and_skip(f, ':'));
  TRY(parse_value(f));
  return 0;
}

// object = '{' pair { ',' pair } '}'
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

// json = object
int parse_json(const char *s, int s_len, struct json_token *arr, int arr_len) {
  struct frozen frozen = { s + s_len, s, arr, arr_len, 0, 0 };
  TRY(doit(&frozen));
  return frozen.cur - s;
}

struct json_token *parse_json2(const char *s, int s_len) {
  struct frozen frozen = { s + s_len, s, NULL, 0, 0, 1 };
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
      skip = 1;  // In objects, we skip 2 elems while iterating, in arrays 1.
    } else if (toks->type != JSON_TYPE_OBJECT) return 0;
    toks++;
    for (i = 0; i < toks[-1].num_desc; i += skip, ind2++) {
      // ind == -1 indicated that we're iterating an array, not object
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
  return snprintf(buf, buf_len > 0 ? buf_len : 0, "%ld", value);
}

int json_emit_double(char *buf, int buf_len, double value) {
  return snprintf(buf, buf_len > 0 ? buf_len : 0, "%g", value);
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
  if (s < end) *s = '\0';

  return s - begin;
}

int json_emit_unquoted_str(char *buf, int buf_len, const char *str, int len) {
  if (buf_len > 0 && len > 0) {
    memcpy(buf, str, len < buf_len ? len : buf_len);
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

  // Best-effort to 0-terminate generated string
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
// Copyright (c) 2014 Cesanta Software Limited
// All rights reserved

#ifndef NS_DISABLE_HTTP_WEBSOCKET


// Check whether full request is buffered. Return:
//   -1  if request is malformed
//    0  if request is not yet fully buffered
//   >0  actual request length, including last \r\n\r\n
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

static int parse_http(const char *s, int n, struct http_message *req) {
  const char *end;
  int len, i;

  if ((len = get_request_len(s, n)) <= 0) return len;

  memset(req, 0, sizeof(*req));
  req->message.p = s;
  req->body.p = s + len;
  req->message.len = req->body.len = (size_t) ~0;
  end = s + len;

  // Request is fully buffered. Skip leading whitespaces.
  while (s < end && isspace(* (unsigned char *) s)) s++;

  // Parse request line: method, URI, proto
  s = ns_skip(s, end, " ", &req->method);
  s = ns_skip(s, end, " ", &req->uri);
  s = ns_skip(s, end, "\r\n", &req->proto);
  if (req->uri.p <= req->method.p || req->proto.p <= req->uri.p) return -1;

  for (i = 0; i < (int) ARRAY_SIZE(req->header_names); i++) {
    struct ns_str *k = &req->header_names[i], *v = &req->header_values[i];

    s = ns_skip(s, end, ": ", k);
    s = ns_skip(s, end, "\r\n", v);

    while (v->len > 0 && v->p[v->len - 1] == ' ') {
      v->len--;  // Trim trailing spaces in header value
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

  if (req->body.len == (size_t) ~0 && ns_vcasecmp(&req->method, "GET") == 0) {
    req->body.len = 0;
    req->message.len = len;
  }

  return len;
}

struct ns_str *get_http_header(struct http_message *hm, const char *name) {
  size_t i, len = strlen(name);

  for (i = 0; i < ARRAY_SIZE(hm->header_names); i++) {
    struct ns_str *h = &hm->header_names[i], *v = &hm->header_values[i];
    if (h->p != NULL && h->len == len && !ns_ncasecmp(h->p, name, len)) return v;
  }

  return NULL;
}

static int deliver_websocket_data(struct ns_connection *nc) {
  // Having buf unsigned char * is important, as it is used below in arithmetic
  unsigned char *buf = (unsigned char *) nc->recv_iobuf.buf;
  uint64_t i, data_len = 0, frame_len = 0, buf_len = nc->recv_iobuf.len,
  len, mask_len = 0, header_len = 0, ok;

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

    // Apply mask if necessary
    if (mask_len > 0) {
      for (i = 0; i < data_len; i++) {
        buf[i + header_len] ^= (buf + header_len - mask_len)[i % 4];
      }
    }

    // Call event handler
    ((ns_event_handler_t) nc->proto_data)(nc, NS_WEBSOCKET_FRAME, &wsm);

    // Remove frame from the iobuf
    iobuf_remove(&nc->recv_iobuf, frame_len);
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

void ns_send_websocket_frame(struct ns_connection *nc, int op,
                             const void *data, size_t len) {
  ns_send_ws_header(nc, op, len);
  ns_send(nc, data, len);

  if (op == WEBSOCKET_OP_CLOSE) {
    nc->flags |= NSF_FINISHED_SENDING_DATA;
  }
}

void ns_printf_websocket(struct ns_connection *nc, int op,
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
    free(buf);
  }
}

static void websocket_handler(struct ns_connection *nc, int ev, void *ev_data) {
  ns_event_handler_t cb = (ns_event_handler_t) nc->proto_data;

  cb(nc, ev, ev_data);

  switch (ev) {
    case NS_RECV:
      do { } while (deliver_websocket_data(nc));
      break;
    default:
      break;
  }
}

static void send_websocket_handshake(struct ns_connection *nc,
                                     const struct ns_str *key) {
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

static void http_handler(struct ns_connection *nc, int ev, void *ev_data) {
  struct iobuf *io = &nc->recv_iobuf;
  ns_event_handler_t cb = (ns_event_handler_t) nc->proto_data;
  struct http_message hm;
  struct ns_str *vec;
  int req_len;

  cb(nc, ev, ev_data);

  switch (ev) {

    case NS_RECV:
      req_len = parse_http(io->buf, io->len, &hm);
      if (req_len < 0 || io->len >= NS_MAX_HTTP_REQUEST_SIZE) {
        nc->flags |= NSF_CLOSE_IMMEDIATELY;
      } else if (req_len == 0) {
        // Do nothing, request is not yet fully buffered
      } else if (nc->listener == NULL &&
                 get_http_header(&hm, "Sec-WebSocket-Accept")) {
        // We're websocket client, got handshake response from server.
        // TODO(lsm): check the validity of accept Sec-WebSocket-Accept
        iobuf_remove(io, req_len);
        nc->callback = websocket_handler;
        nc->flags |= NSF_USER_1;
        cb(nc, NS_WEBSOCKET_HANDSHAKE_DONE, NULL);
        websocket_handler(nc, NS_RECV, ev_data);
      } else if (nc->listener != NULL &&
                 (vec = get_http_header(&hm, "Sec-WebSocket-Key")) != NULL) {
        // This is a websocket request. Switch protocol handlers.
        iobuf_remove(io, req_len);
        nc->callback = websocket_handler;
        nc->flags |= NSF_USER_1;

        // Send handshake
        cb(nc, NS_WEBSOCKET_HANDSHAKE_REQUEST, NULL);
        if (!(nc->flags & NSF_CLOSE_IMMEDIATELY)) {
          if (nc->send_iobuf.len == 0) {
            send_websocket_handshake(nc, vec);
          }
          cb(nc, NS_WEBSOCKET_HANDSHAKE_DONE, NULL);
          websocket_handler(nc, NS_RECV, ev_data);
        }
      } else if (hm.message.len <= io->len) {
        // Whole HTTP message is fully buffered, call event handler
        if (cb) cb(nc, nc->listener ? NS_HTTP_REQUEST : NS_HTTP_REPLY, &hm);
        iobuf_remove(io, hm.message.len);
      }
      break;

    case NS_CLOSE:
      if (io->len > 0 && parse_http(io->buf, io->len, &hm) > 0 && cb) {
        hm.body.len = io->buf + io->len - hm.body.p;
        cb(nc, nc->listener ? NS_HTTP_REQUEST : NS_HTTP_REPLY, &hm);
      }
      break;

    default:
      break;
  }
}

void ns_set_protocol_http_websocket(struct ns_connection *nc) {
  nc->proto_data = (void *) nc->callback;
  nc->callback = http_handler;
}

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


void ns_send_http_file(struct ns_connection *nc, const char *path,
                       ns_stat_t *st) {
  char buf[BUFSIZ];
  size_t n;
  FILE *fp;

  if ((fp = fopen(path, "rb")) != NULL) {
    ns_printf(nc, "HTTP/1.1 200 OK\r\n"
              "Content-Length: %lu\r\n\r\n", (unsigned long) st->st_size);
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
      ns_send(nc, buf, n);
    }
    fclose(fp);
  } else {
    ns_printf(nc, "%s", "HTTP/1.1 500 Server Error\r\n"
              "Content-Length: 0\r\n\r\n");
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

void ns_serve_http(struct ns_connection *nc, struct http_message *hm,
                   struct http_server_opts opts) {
  char path[NS_MAX_PATH];
  ns_stat_t st;

  snprintf(path, sizeof(path), "%s/%.*s", opts.document_root, (int) hm->uri.len, hm->uri.p);
  remove_double_dots(path);

  if (stat(path, &st) != 0) {
    ns_printf(nc, "%s", "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
  } else if (S_ISDIR(st.st_mode)) {
    strncat(path, "/index.html", sizeof(path) - (strlen(path) + 1));
    if (stat(path, &st) == 0) {
      ns_send_http_file(nc, path, &st);
    } else {
      ns_printf(nc, "%s", "HTTP/1.1 403 Access Denied\r\n"
                "Content-Length: 0\r\n\r\n");
    }
  } else {
    ns_send_http_file(nc, path, &st);
  }
}
#endif  // NS_DISABLE_HTTP_WEBSOCKET
// Copyright(c) By Steve Reid <steve@edmweb.com>
// 100% Public Domain

#ifndef NS_DISABLE_HTTP_WEBSOCKET

#include <string.h>

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
  // Forrest: SHA expect BIG_ENDIAN, swap if LITTLE_ENDIAN
  if (!is_big_endian()) {
    block->l[i] = (rol(block->l[i], 24) & 0xFF00FF00) |
      (rol(block->l[i], 8) & 0x00FF00FF);
  }
  return block->l[i];
}

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
  // Erase working structures. The order of operations is important,
  // used to ensure that compiler doesn't optimize those out.
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
#endif  // NS_DISABLE_HTTP_WEBSOCKET// Copyright (c) 2014 Cesanta Software Limited
// All rights reserved


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

int ns_ncasecmp(const char *s1, const char *s2, size_t len) {
  int diff = 0;

  if (len > 0)
    do {
      diff = lowercase(s1++) - lowercase(s2++);
    } while (diff == 0 && s1[-1] != '\0' && --len > 0);

  return diff;
}

int ns_vcasecmp(const struct ns_str *str2, const char *str1) {
  size_t n1 = strlen(str1), n2 = str2->len;
  return n1 == n2 ? ns_ncasecmp(str1, str2->p, n1) : n1 > n2 ? 1 : -1;
}

int ns_vcmp(const struct ns_str *str2, const char *str1) {
  size_t n1 = strlen(str1), n2 = str2->len;
  return n1 == n2 ? memcmp(str1, str2->p, n2) : n1 > n2 ? 1 : -1;
}

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

// Convert one byte of encoded base64 input stream to 6-bit chunk
static unsigned char from_b64(unsigned char ch) {
  // Inverse lookup map
  static const unsigned char tab[128] = {
    255, 255, 255, 255, 255, 255, 255, 255, //  0
    255, 255, 255, 255, 255, 255, 255, 255, //  8
    255, 255, 255, 255, 255, 255, 255, 255, //  16
    255, 255, 255, 255, 255, 255, 255, 255, //  24
    255, 255, 255, 255, 255, 255, 255, 255, //  32
    255, 255, 255,  62, 255, 255, 255,  63, //  40
     52,  53,  54,  55,  56,  57,  58,  59, //  48
     60,  61, 255, 255, 255, 200, 255, 255, //  56   '=' is 200, on index 61
    255,   0,   1,   2,   3,   4,   5,   6, //  64
      7,   8,   9,  10,  11,  12,  13,  14, //  72
     15,  16,  17,  18,  19,  20,  21,  22, //  80
     23,  24,  25, 255, 255, 255, 255, 255, //  88
    255,  26,  27,  28,  29,  30,  31,  32, //  96
     33,  34,  35,  36,  37,  38,  39,  40, //  104
     41,  42,  43,  44,  45,  46,  47,  48, //  112
     49,  50,  51, 255, 255, 255, 255, 255, //  120
  };
  return tab[ch & 127];
}

void ns_base64_decode(const unsigned char *s, int len, char *dst) {
  unsigned char a, b, c, d;
  while (len >= 4 &&
         (a = from_b64(s[0])) != 255 &&
         (b = from_b64(s[1])) != 255 &&
         (c = from_b64(s[2])) != 255 &&
         (d = from_b64(s[3])) != 255) {
    if (a == 200 || b == 200) break;  // '=' can't be there
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
// Copyright (c) 2014 Cesanta Software Limited
// All rights reserved

#ifndef NS_DISABLE_JSON_RPC


int ns_rpc_reply(struct ns_connection *nc, const char *fmt, ...) {
  struct iobuf *io = &nc->send_iobuf;
  va_list ap, ap_copy;
  int len, n = 0;

  // Find out how long the message is, without actually making a message
  va_start(ap, fmt);
  va_copy(ap_copy, ap);
  len = json_emit_va(NULL, 0, fmt, ap);
  va_end(ap);

  if (len > 0) {
    if (io->size < io->len + len) {
      iobuf_resize(io, io->len + len);
    }
    if (io->size <= io->len + len) {
      // Output buffer is large enough to hold RPC message, create a message
      n = json_emit_va(io->buf + io->len, len, fmt, ap_copy);
      io->len += n;
    }
  }
  va_end(ap_copy);

  return n;
}

#if 0
static struct ns_rpc_method *find_method(struct ns_rpc_method *tbl,
                                         const char *name, int name_len) {
  while (tbl->name != NULL) {
    if (strncmp(tbl->name, name, name_len) == 0) return tbl;
    tbl++;
  }
  return NULL;
}

int nc_rpc_dispatch(struct ns_connection *nc, struct ns_rpc_method *tbl) {
  struct iobuf *io = &nc->recv_iobuf;
  struct json_token toks[200], *method, *params, *id;
  struct ns_rpc_method *m;

  int n = parse_json(io->buf, io->len, toks, sizeof(toks));
  if (n == JSON_STRING_INCOMPLETE) {
    // Do nothing, we haven't received everything yet
  } else if (n > 0) {
    method = find_json_token(toks, "method");
    params = find_json_token(toks, "params");
    id = find_json_token(toks, "id");
    if (method != NULL && params != NULL &&
        (m = find_method(tbl, method->ptr, method->len)) != NULL) {
      m->handler(nc, id, params);
    }
    iobuf_remove(io, n);
  } else {
    iobuf_remove(io, io->len);
  }

  return n;
}
#endif

#endif  // NS_DISABLE_JSON_RPC
