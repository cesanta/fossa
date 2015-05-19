/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
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

#include "../fossa.h"
#include "../src/internal.h"
#include "unit_test.h"
#include "test_util.h"

#if __STDC_VERSION__ < 199901L && !defined(WIN32)
#define __func__ ""
#endif

#define FETCH_BUF_SIZE (1024 * 16)

#define HTTP_PORT "45772"
#define LOOPBACK_IP "127.0.0.1"
#define LISTENING_ADDR LOOPBACK_IP ":" HTTP_PORT

static const char *s_argv_0 = NULL;
static struct ns_serve_http_opts s_http_server_opts;

#define TEST_NS_MALLOC malloc
#define TEST_NS_CALLOC calloc

#ifndef intptr_t
#define intptr_t long
#endif

void *(*test_malloc)(size_t) = TEST_NS_MALLOC;
void *(*test_calloc)(size_t, size_t) = TEST_NS_CALLOC;

void *failing_malloc(size_t size) {
  (void) size;
  return NULL;
}

void *failing_calloc(size_t count, size_t size) {
  (void) count;
  (void) size;
  return NULL;
}

static char *read_file(const char *path, size_t *size) {
  FILE *fp;
  struct stat st;
  char *data = NULL;
  if ((fp = ns_fopen(path, "rb")) != NULL && !fstat(fileno(fp), &st)) {
    *size = st.st_size;
    data = (char *) malloc(*size);
    fread(data, 1, *size, fp);
    fclose(fp);
  }
  return data;
}

static const char *test_mbuf(void) {
  struct mbuf io;
  const char *data = "TEST";
  const char *prefix = "MY";
  const char *big_prefix = "Some long prefix: ";
  size_t old_size;

  mbuf_init(&io, 0);
  ASSERT(io.buf == NULL);
  ASSERT_EQ(io.len, 0);
  ASSERT_EQ(io.size, 0);
  mbuf_free(&io);
  ASSERT(io.buf == NULL);
  ASSERT_EQ(io.len, 0);
  ASSERT_EQ(io.size, 0);

  mbuf_init(&io, 10);
  ASSERT(io.buf != NULL);
  ASSERT_EQ(io.len, 0);
  ASSERT_EQ(io.size, 10);
  mbuf_free(&io);
  ASSERT(io.buf == NULL);
  ASSERT_EQ(io.len, 0);
  ASSERT_EQ(io.size, 0);

  mbuf_init(&io, 10);
  ASSERT_EQ(mbuf_append(&io, NULL, 0), 0);
  /* test allocation failure */
  ASSERT_EQ(mbuf_append(&io, NULL, 1125899906842624), 0);

  ASSERT_EQ(mbuf_append(&io, data, strlen(data)), strlen(data));

  mbuf_resize(&io, 2);
  ASSERT_EQ(io.size, 10);
  ASSERT_EQ(io.len, strlen(data));

  ASSERT_EQ(mbuf_insert(&io, 0, prefix, strlen(prefix)), strlen(prefix));
  ASSERT_EQ(io.size, 10);
  ASSERT_EQ(io.len, strlen(data) + strlen(prefix));

  ASSERT_EQ(mbuf_insert(&io, 0, big_prefix, strlen(big_prefix)),
            strlen(big_prefix));
  ASSERT_EQ(io.size, MBUF_SIZE_MULTIPLIER *
                         (strlen(big_prefix) + strlen(prefix) + strlen(data)));
  ASSERT_STREQ_NZ(io.buf, "Some long prefix: MYTEST");

  old_size = io.size;
  ASSERT_EQ(mbuf_insert(&io, strlen(big_prefix), data, strlen(data)),
            strlen(data));
  ASSERT_EQ(io.size, old_size);
  ASSERT_STREQ_NZ(io.buf, "Some long prefix: TESTMYTEST");

  /* test allocation failure */
  ASSERT_EQ(mbuf_insert(&io, 0, NULL, 1125899906842624), 0);

  /* test overflow */
  ASSERT_EQ(mbuf_insert(&io, 0, NULL, -1), 0);
  mbuf_free(&io);
  return NULL;
}

static int c_str_ne(void *a, void *b) {
  int r = strcmp((const char *) a, (const char *) b);
  DBG(("%p %p %d", a.p, b.p, r));
  return r;
}

static int c_int_eq(void *a, void *b) {
  return *((int *) a) == (intptr_t) b;
}

static void poll_until(struct ns_mgr *mgr, int timeout_ms,
                       int (*cond)(void *, void *), void *cond_arg1,
                       void *cond_arg2) {
  int i, num_iterations = timeout_ms / 2;
  for (i = 0; i < num_iterations; i++) {
    ns_mgr_poll(mgr, 2);
    if (cond != NULL && cond(cond_arg1, cond_arg2)) {
      /* A few more cycles to test for overshoots. */
      for (i = 0; i < 5; i++) {
        ns_mgr_poll(mgr, 2);
      }
      return;
    }
  }
}

static void eh1(struct ns_connection *nc, int ev, void *ev_data) {
  struct mbuf *io = &nc->recv_mbuf;

  switch (ev) {
    case NS_CONNECT:
      ns_printf(nc, "%d %s there", *(int *) ev_data, "hi");
      break;
    case NS_RECV:
      if (nc->listener != NULL) {
        ns_printf(nc, "%d", (int) io->len);
        mbuf_remove(io, io->len);
      } else if (io->len == 2 && memcmp(io->buf, "10", 2) == 0) {
        sprintf((char *) nc->user_data, "%s", "ok!");
        nc->flags |= NSF_CLOSE_IMMEDIATELY;
      }
      break;
    default:
      break;
  }
}

#define S_PEM "server.pem"
#define C_PEM "client.pem"
#define CA_PEM "ca.pem"

static const char *test_mgr_with_ssl(int use_ssl) {
  char addr[100] = "127.0.0.1:0", ip[sizeof(addr)], buf[100] = "";
  struct ns_mgr mgr;
  struct ns_connection *nc;
  int port, port2;
#ifndef NS_ENABLE_SSL
  (void) use_ssl;
#endif

  ns_mgr_init(&mgr, NULL);
  /* mgr.hexdump_file = "/dev/stdout"; */

  ASSERT((nc = ns_bind(&mgr, addr, eh1)) != NULL);
  port2 = htons(nc->sa.sin.sin_port);
  ASSERT(port2 > 0);
#ifdef NS_ENABLE_SSL
  if (use_ssl) {
    ASSERT(ns_set_ssl(nc, S_PEM, CA_PEM) == NULL);
  }
#endif

  ns_sock_to_str(nc->sock, addr, sizeof(addr), 3);
  ASSERT_EQ(sscanf(addr, "%[^:]:%d", ip, &port), 2);
  ASSERT_STREQ(ip, "127.0.0.1");
  ASSERT_EQ(port, port2);

  ASSERT((nc = ns_connect(&mgr, addr, eh1)) != NULL);
#ifdef NS_ENABLE_SSL
  if (use_ssl) {
    ASSERT(ns_set_ssl(nc, C_PEM, CA_PEM) == NULL);
  }
#endif
  nc->user_data = buf;
  poll_until(&mgr, 1000, c_str_ne, buf, (void *) "");

  ASSERT_STREQ(buf, "ok!");

  ns_mgr_free(&mgr);
  return NULL;
}

static const char *test_mgr(void) {
  return test_mgr_with_ssl(0);
}

#ifdef NS_ENABLE_SSL
static const char *test_ssl(void) {
  return test_mgr_with_ssl(1);
}
#endif

static const char *test_to64(void) {
  ASSERT_EQ(to64("0"), 0);
  ASSERT_EQ(to64(""), 0);
  ASSERT_EQ(to64("123"), 123);
  ASSERT_EQ(to64("-34"), -34);
  ASSERT_EQ(to64("3566626116"), 3566626116U);
  return NULL;
}

static const char *test_check_ip_acl(void) {
  uint32_t ip = 0x01020304;
  ASSERT_EQ(ns_check_ip_acl(NULL, ip), 1);
  ASSERT_EQ(ns_check_ip_acl("", ip), 1);
  ASSERT_EQ(ns_check_ip_acl("invalid", ip), -1);
  ASSERT_EQ(ns_check_ip_acl("-0.0.0.0/0", ip), 0);
  ASSERT_EQ(ns_check_ip_acl("-0.0.0.0/0,+1.0.0.0/8", ip), 1);
  ASSERT_EQ(ns_check_ip_acl("-0.0.0.0/0,+1.2.3.4", ip), 1);
  ASSERT_EQ(ns_check_ip_acl("-0.0.0.0/0,+1.0.0.0/16", ip), 0);
  return NULL;
}

/* TODO(mkm) port these test cases to the new async parse_address */
static const char *test_parse_address(void) {
  static const char *valid[] = {
    "1",
    "1.2.3.4:1",
    "tcp://123",
    "udp://0.0.0.0:99",
#ifndef _WIN32 /* No /etc/hosts on Windows. */
    "tcp://localhost:99",
#endif
    ":8080",
#if defined(NS_ENABLE_IPV6)
    "udp://[::1]:123",
    "[3ffe:2a00:100:7031::1]:900",
#endif
    NULL
  };
  static const int protos[] = {
    SOCK_STREAM,
    SOCK_STREAM,
    SOCK_STREAM,
    SOCK_DGRAM,
    SOCK_STREAM,
    SOCK_STREAM
#if defined(NS_ENABLE_IPV6)
    ,
    SOCK_DGRAM,
    SOCK_STREAM
#endif
  };
  static const char *need_lookup[] = {"udp://a.com:53", "locl_host:12", NULL};
  static const char *invalid[] = {
      "99999", "1k", "1.2.3", "1.2.3.4:", "1.2.3.4:2p", "blah://12", ":123x",
      "veeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeery.long:12345",
      "udp://missingport", NULL};
  char host[50];
  union socket_address sa;
  int i, proto;

  for (i = 0; valid[i] != NULL; i++) {
    ASSERT(ns_parse_address(valid[i], &sa, &proto, host, sizeof(host)) > 0);
    ASSERT_EQ(proto, protos[i]);
  }

  for (i = 0; invalid[i] != NULL; i++) {
    ASSERT_EQ(ns_parse_address(invalid[i], &sa, &proto, host, sizeof(host)),
              -1);
  }

  for (i = 0; need_lookup[i] != NULL; i++) {
    ASSERT_EQ(ns_parse_address(need_lookup[i], &sa, &proto, host, sizeof(host)),
              0);
  }

  return NULL;
}

static void connect_fail_cb(struct ns_connection *nc, int ev, void *p) {
  switch (ev) {
    case NS_CONNECT:
      /* On connection success, set flag 1, else set 4 */
      *(int *) nc->user_data |= *(int *) p == 0 ? 1 : 4;
      break;
    case NS_CLOSE:
      *(int *) nc->user_data |= 2;
      break;
  }
}

static const char *test_connection_errors(void) {
  struct ns_mgr mgr;
  struct ns_bind_opts bopts;
  struct ns_connect_opts copts;
  struct ns_connection *nc;
  const char *error_string;
  int data = 0;

  copts.flags = 0;
  ns_mgr_init(&mgr, NULL);

  DBG(("now"));
  bopts.error_string = &error_string;
  ASSERT(ns_bind_opt(&mgr, "blah://12", NULL, bopts) == NULL);
  ASSERT_STREQ(error_string, "cannot parse address");

  ASSERT(ns_bind_opt(&mgr, "tcp://8.8.8.8:88", NULL, bopts) == NULL);
  ASSERT_STREQ(error_string, "failed to open listener");

  copts.error_string = &error_string;
  ASSERT(ns_connect_opt(&mgr, "tcp://255.255.255.255:0", NULL, copts) == NULL);
  ASSERT_STREQ(error_string, "cannot connect to socket");

  copts.user_data = &data;
  ASSERT(ns_connect_opt(&mgr, "tcp://255.255.255.255:0", connect_fail_cb,
                        copts) == NULL);
  ASSERT_STREQ(error_string, "cannot connect to socket");
  /* handler isn't invoked when it fails synchronously */
  ASSERT_EQ(data, 0);

  data = 0;
  copts.user_data = &data;
  ASSERT((nc = ns_connect_opt(&mgr, "tcp://does.not.exist:8080",
                              connect_fail_cb, copts)) != NULL);

  /* handler is invoked when it fails asynchronously */
  poll_until(&mgr, 1000, c_int_eq, &data, (void *) 4);
  ASSERT_EQ(data, 4);

  /* ns_bind() does not use NS_CALLOC, but async resolver does */
  test_calloc = failing_calloc;
#ifndef _WIN32
  ASSERT(ns_connect(&mgr, "some.domain.needs.async.resolv:777", NULL) == NULL);
#endif
  test_calloc = TEST_NS_CALLOC;

  /* ns_create_connection() uses NS_MALLOC */
  test_malloc = failing_malloc;
#ifndef _WIN32
  ASSERT(ns_bind(&mgr, ":4321", NULL) == NULL);
#endif
  test_malloc = TEST_NS_MALLOC;

  ns_mgr_free(&mgr);
  return NULL;
}

static int avt(char **buf, size_t buf_size, const char *fmt, ...) {
  int result;
  va_list ap;
  va_start(ap, fmt);
  result = ns_avprintf(buf, buf_size, fmt, ap);
  va_end(ap);
  return result;
}

static const char *test_alloc_vprintf(void) {
  char buf[5], *p = buf;

  ASSERT_EQ(avt(&p, sizeof(buf), "%d", 123), 3);
  ASSERT(p == buf);
  ASSERT_STREQ(p, "123");

  ASSERT_EQ(avt(&p, sizeof(buf), "%d", 123456789), 9);
  ASSERT(p != buf);
  ASSERT_STREQ(p, "123456789");
  free(p);

  return NULL;
}

static const char *test_socketpair(void) {
  sock_t sp[2];
  static const char foo[] = "hi there";
  char buf[20];

  ASSERT_EQ(ns_socketpair(sp, SOCK_DGRAM), 1);
  ASSERT(sizeof(foo) < sizeof(buf));

  /* Send string in one direction */
  ASSERT_EQ(send(sp[0], foo, sizeof(foo), 0), sizeof(foo));
  ASSERT_EQ(recv(sp[1], buf, sizeof(buf), 0), sizeof(foo));
  ASSERT_STREQ(buf, "hi there");

  /* Now in opposite direction */
  ASSERT_EQ(send(sp[1], foo, sizeof(foo), 0), sizeof(foo));
  ASSERT_EQ(recv(sp[0], buf, sizeof(buf), 0), sizeof(foo));
  ASSERT_STREQ(buf, "hi there");

  closesocket(sp[0]);
  closesocket(sp[1]);

  return NULL;
}

#ifdef NS_ENABLE_THREADS
static void eh2(struct ns_connection *nc, int ev, void *p) {
  (void) p;
  switch (ev) {
    case NS_RECV:
      strcpy((char *) nc->user_data, nc->recv_mbuf.buf);
      break;
    default:
      break;
  }
}

static void *thread_func(void *param) {
  sock_t sock = *(sock_t *) param;
  send(sock, ":-)", 4, 0);
  return NULL;
}

static const char *test_thread(void) {
  struct ns_mgr mgr;
  struct ns_connection *nc;
  sock_t sp[2];
  char buf[20] = "";

  ASSERT_EQ(ns_socketpair(sp, SOCK_STREAM), 1);
  ns_start_thread(thread_func, &sp[1]);

  ns_mgr_init(&mgr, NULL);
  ASSERT((nc = ns_add_sock(&mgr, sp[0], eh2)) != NULL);
  nc->user_data = buf;
  poll_until(&mgr, 1000, c_str_ne, buf, (void *) "");
  ASSERT_STREQ(buf, ":-)");
  ns_mgr_free(&mgr);
  closesocket(sp[1]);

  return NULL;
}
#endif /* NS_ENABLE_THREADS */

struct udp_res {
  char buf_srv[20];
  char buf_clnt[20];
};

static void eh3_srv(struct ns_connection *nc, int ev, void *p) {
  struct mbuf *io = &nc->recv_mbuf;
  (void) p;

  if (ev == NS_RECV) {
    memcpy(((struct udp_res *) nc->mgr->user_data)->buf_srv, io->buf, io->len);
    ns_send(nc, io->buf, io->len);
  }
}

static void eh3_clnt(struct ns_connection *nc, int ev, void *p) {
  struct mbuf *io = &nc->recv_mbuf;
  (void) p;

  if (ev == NS_RECV) {
    memcpy(((struct udp_res *) nc->mgr->user_data)->buf_clnt, io->buf, io->len);
  }
}

static const char *test_udp(void) {
  struct ns_mgr mgr;
  struct ns_connection *nc1, *nc2;
  const char *address = "udp://127.0.0.1:7878";
  struct udp_res res;
  res.buf_srv[0] = '\0';
  res.buf_clnt[0] = '\0';

  ns_mgr_init(&mgr, &res);
  ASSERT((nc1 = ns_bind(&mgr, address, eh3_srv)) != NULL);
  ASSERT((nc2 = ns_connect(&mgr, address, eh3_clnt)) != NULL);
  ns_printf(nc2, "%s", "boo!");

  poll_until(&mgr, 1000, c_str_ne, res.buf_clnt, (void *) "");
  ASSERT_EQ(memcmp(res.buf_srv, "boo!", 4), 0);
  ASSERT_EQ(memcmp(res.buf_clnt, "boo!", 4), 0);
  ns_mgr_free(&mgr);

  return NULL;
}

static const char *test_parse_http_message(void) {
  static const char *a = "GET / HTTP/1.0\n\n";
  static const char *b = "GET /blah HTTP/1.0\r\nFoo:  bar  \r\n\r\n";
  static const char *c = "get b c\nz:  k \nb: t\nvvv\n\n xx";
  static const char *d = "a b c\nContent-Length: 21 \nb: t\nvvv\n\n";
  static const char *e = "GET /foo?a=b&c=d HTTP/1.0\n\n";
  static const char *f = "POST /x HTTP/1.0\n\n";
  static const char *g = "WOHOO /x HTTP/1.0\n\n";
  static const char *h = "HTTP/1.0 200 OK\n\n";
  static const char *i = "HTTP/1.0 999 OMGWTFBBQ\n\n";
  struct ns_str *v;
  struct http_message req;

  ASSERT_EQ(ns_parse_http("\b23", 3, &req, 1), -1);
  ASSERT_EQ(ns_parse_http("\b23", 3, &req, 0), -1);
  ASSERT_EQ(ns_parse_http("get\n\n", 5, &req, 1), -1);
  ASSERT_EQ(ns_parse_http("get\n\n", 5, &req, 0), -1);
  ASSERT_EQ(ns_parse_http(a, strlen(a) - 1, &req, 1), 0);
  ASSERT_EQ(ns_parse_http(a, strlen(a), &req, 0), -1);

  ASSERT_EQ(ns_parse_http(a, strlen(a), &req, 1), (int) strlen(a));
  ASSERT_EQ(req.message.len, strlen(a));
  ASSERT_EQ(req.body.len, 0);

  ASSERT_EQ(ns_parse_http(b, strlen(b), &req, 0), -1);
  ASSERT_EQ(ns_parse_http(b, strlen(b), &req, 1), (int) strlen(b));
  ASSERT_EQ(req.header_names[0].len, 3);
  ASSERT_EQ(req.header_values[0].len, 3);
  ASSERT(req.header_names[1].p == NULL);
  ASSERT_EQ(req.query_string.len, 0);
  ASSERT_EQ(req.message.len, strlen(b));
  ASSERT_EQ(req.body.len, 0);

  ASSERT_EQ(ns_parse_http(c, strlen(c), &req, 1), (int) strlen(c) - 3);
  ASSERT(req.header_names[2].p == NULL);
  ASSERT(req.header_names[0].p != NULL);
  ASSERT(req.header_names[1].p != NULL);
  ASSERT_EQ(memcmp(req.header_values[1].p, "t", 1), 0);
  ASSERT_EQ(req.header_names[1].len, 1);
  ASSERT_EQ(req.body.len, 0);

  ASSERT_EQ(ns_parse_http(d, strlen(d), &req, 1), (int) strlen(d));
  ASSERT_EQ(req.body.len, 21);
  ASSERT_EQ(req.message.len, 21 + strlen(d));
  ASSERT(ns_get_http_header(&req, "foo") == NULL);
  ASSERT((v = ns_get_http_header(&req, "contENT-Length")) != NULL);
  ASSERT_EQ(v->len, 2);
  ASSERT_STREQ_NZ(v->p, "21");

  ASSERT_EQ(ns_parse_http(e, strlen(e), &req, 1), (int) strlen(e));
  ASSERT_EQ(ns_vcmp(&req.uri, "/foo"), 0);
  ASSERT_EQ(ns_vcmp(&req.query_string, "a=b&c=d"), 0);

  ASSERT_EQ(ns_parse_http(f, strlen(f), &req, 1), (int) strlen(f));
  ASSERT_EQ(req.body.len, (size_t) ~0);

  ASSERT_EQ(ns_parse_http(g, strlen(g), &req, 1), (int) strlen(g));
  ASSERT_EQ(req.body.len, 0);

  ASSERT_EQ(ns_parse_http(h, strlen(h), &req, 0), (int) strlen(h));
  ASSERT_EQ(ns_vcmp(&req.proto, "HTTP/1.0"), 0);
  ASSERT_EQ(req.resp_code, 200);
  ASSERT_EQ(ns_vcmp(&req.resp_status_msg, "OK"), 0);
  ASSERT_EQ(req.body.len, (size_t) ~0);

  ASSERT_EQ(ns_parse_http(i, strlen(i), &req, 0), -1);

  return NULL;
}

static const char *test_get_http_var(void) {
  char buf[256];
  struct ns_str body;
  body.p = "key1=value1&key2=value2&key3=value%203&key4=value+4";
  body.len = strlen(body.p);

  ASSERT(ns_get_http_var(&body, "key1", buf, sizeof(buf)) > 0);
  ASSERT_STREQ(buf, "value1");
  ASSERT(ns_get_http_var(&body, "KEY1", buf, sizeof(buf)) > 0);
  ASSERT_STREQ(buf, "value1");
  ASSERT(ns_get_http_var(&body, "key2", buf, sizeof(buf)) > 0);
  ASSERT_STREQ(buf, "value2");
  ASSERT(ns_get_http_var(&body, "key3", buf, sizeof(buf)) > 0);
  ASSERT_STREQ(buf, "value 3");
  ASSERT(ns_get_http_var(&body, "key4", buf, sizeof(buf)) > 0);
  ASSERT_STREQ(buf, "value 4");

  ASSERT_EQ(ns_get_http_var(&body, "key", NULL, sizeof(buf)), -2);
  ASSERT_EQ(ns_get_http_var(&body, "key", buf, 0), -2);
  ASSERT_EQ(ns_get_http_var(&body, NULL, buf, sizeof(buf)), -1);

  body.p = "key=broken%2";
  body.len = strlen(body.p);
  ASSERT(ns_get_http_var(&body, "key", buf, sizeof(buf)) < 0);

  body.p = "key=broken%2x";
  body.len = strlen(body.p);
  ASSERT(ns_get_http_var(&body, "key", buf, sizeof(buf)) < 0);
  return NULL;
}

static void cb1(struct ns_connection *nc, int ev, void *ev_data) {
  struct http_message *hm = (struct http_message *) ev_data;

  if (ev == NS_HTTP_REQUEST) {
    if (ns_vcmp(&hm->uri, "/foo") == 0) {
      ns_printf(nc, "HTTP/1.0 200 OK\n\n[%.*s %d]", (int) hm->uri.len,
                hm->uri.p, (int) hm->body.len);
      nc->flags |= NSF_SEND_AND_CLOSE;
    } else {
      s_http_server_opts.document_root = ".";
      s_http_server_opts.per_directory_auth_file = "passwords.txt";
      s_http_server_opts.auth_domain = "foo.com";
      s_http_server_opts.ssi_suffix = ".shtml";
      s_http_server_opts.dav_document_root = "./data/dav";
      s_http_server_opts.hidden_file_pattern = "hidden_file.*$";
#ifdef _WIN32
      s_http_server_opts.cgi_interpreter = "perl.exe";
#endif
      s_http_server_opts.url_rewrites =
          "/~joe=./data/rewrites,"
          "@foo.com=./data/rewrites/foo.com";
      s_http_server_opts.custom_mime_types =
          ".txt=text/plain; charset=windows-1251,"
          ".c=text/plain; charset=utf-8";
      ns_serve_http(nc, hm, s_http_server_opts);
    }
  }
}

static void cb2(struct ns_connection *nc, int ev, void *ev_data) {
  struct http_message *hm = (struct http_message *) ev_data;

  if (ev == NS_HTTP_REPLY) {
    sprintf((char *) nc->user_data, "%.*s %lu", (int) hm->body.len, hm->body.p,
            (unsigned long) hm->message.len);
    nc->flags |= NSF_CLOSE_IMMEDIATELY;
  }
}

static void cb7(struct ns_connection *nc, int ev, void *ev_data) {
  struct http_message *hm = (struct http_message *) ev_data;
  size_t size;
  char *data, *user_data = (char *) nc->user_data;

  if (ev == NS_HTTP_REPLY) {
    /* Make sure that we've downloaded this executable, byte-to-byte */
    data = read_file(s_argv_0, &size);
    if (data != NULL && size == hm->body.len &&
        memcmp(hm->body.p, data, size) == 0) {
      strcpy(user_data, "success");
    } else {
      strcpy(user_data, "fail");
    }
    free(data);
    nc->flags |= NSF_CLOSE_IMMEDIATELY;
  }
}

static void cb8(struct ns_connection *nc, int ev, void *ev_data) {
  struct http_message *hm = (struct http_message *) ev_data;
  DBG(("ev=%d", ev));

  if (ev == NS_HTTP_REPLY) {
    DBG(("OMGOMGOMG"));
    snprintf((char *) nc->user_data, FETCH_BUF_SIZE, "%.*s",
             (int) hm->message.len, hm->message.p);
    nc->flags |= NSF_CLOSE_IMMEDIATELY;
  }
}

static void cb10(struct ns_connection *nc, int ev, void *ev_data) {
  struct http_message *hm = (struct http_message *) ev_data;
  struct ns_str *s;

  if (ev == NS_HTTP_REPLY &&
      (s = ns_get_http_header(hm, "Content-Type")) != NULL) {
    sprintf((char *) nc->user_data, "%.*s", (int) s->len, s->p);
  }
}

static void cb_auth_fail(struct ns_connection *nc, int ev, void *ev_data) {
  struct http_message *hm = (struct http_message *) ev_data;

  if (ev == NS_HTTP_REPLY) {
    *((int *) nc->user_data) = hm->resp_code;
  }
}

static void cb_auth_ok(struct ns_connection *nc, int ev, void *ev_data) {
  struct http_message *hm = (struct http_message *) ev_data;

  if (ev == NS_HTTP_REPLY) {
    sprintf((char *) nc->user_data, "%d %.*s", hm->resp_code,
            (int) hm->body.len, hm->body.p);
  }
}

static void fetch_http(char *buf, const char *request_fmt, ...) {
  static int listening_port = 23456;
  struct ns_mgr mgr;
  struct ns_connection *nc;
  char local_addr[50];
  va_list ap;

  /* Setup server. Use different local port for the next invocation. */
  ns_mgr_init(&mgr, NULL);
  /* mgr.hexdump_file = "/dev/stdout"; */
  snprintf(local_addr, sizeof(local_addr), "127.0.0.1:%d", listening_port++);
  nc = ns_bind(&mgr, local_addr, cb1);
  ns_set_protocol_http_websocket(nc);

  /* Setup client */
  nc = ns_connect(&mgr, local_addr, cb8);
  ns_set_protocol_http_websocket(nc);
  nc->user_data = buf;
  va_start(ap, request_fmt);
  ns_vprintf(nc, request_fmt, ap);
  va_end(ap);

  /* Run event loop, destroy server */
  buf[0] = '\0';
  poll_until(&mgr, 10000, c_str_ne, buf, (void *) "");
  ns_mgr_free(&mgr);
}

static const char *test_http(void) {
  struct ns_mgr mgr;
  struct ns_connection *nc;
  const char *this_binary, *local_addr = "127.0.0.1:7777";
  char buf[20] = "", status[100] = "", mime1[20] = "", mime2[100] = "";
  int resp_code;
  char auth_ok[20] = "", auth_hdr[200] = "", url[1000];

  ns_mgr_init(&mgr, NULL);
  /* mgr.hexdump_file = "/dev/stdout"; */
  ASSERT((nc = ns_bind(&mgr, local_addr, cb1)) != NULL);
  ns_set_protocol_http_websocket(nc);
  /* Valid HTTP request. Pass test buffer to the callback. */
  ASSERT((nc = ns_connect_http(&mgr, cb2, "http://127.0.0.1:7777/foo", NULL,
                               "0123456789")) != NULL);
  nc->user_data = buf;

  /* Invalid HTTP request */
  ASSERT((nc = ns_connect(&mgr, local_addr, cb2)) != NULL);
  ns_set_protocol_http_websocket(nc);

  ns_printf(nc, "%s", "bl\x03\n\n");
  /* Test static file download by downloading this executable, argv[0] */
  ASSERT((nc = ns_connect(&mgr, local_addr, cb7)) != NULL);
  ns_set_protocol_http_websocket(nc);
  nc->user_data = status;

  /* Wine and GDB set argv0 to full path: strip the dir component */
  if ((this_binary = strrchr(s_argv_0, '\\')) != NULL) {
    this_binary++;
  } else if ((this_binary = strrchr(s_argv_0, '/')) != NULL) {
    this_binary++;
  } else {
    this_binary = s_argv_0;
  }
  ns_printf(nc, "GET /%s HTTP/1.0\n\n", this_binary);
  /* Test mime type for static file */
  snprintf(url, sizeof(url), "http://%s/data/dummy.xml", local_addr);
  ASSERT((nc = ns_connect_http(&mgr, cb10, url, NULL, NULL)) != NULL);
  nc->user_data = mime1;

  /* Test custom mime type for static file */
  snprintf(url, sizeof(url), "http://%s/data/range.txt", local_addr);
  ASSERT((nc = ns_connect_http(&mgr, cb10, url, NULL, NULL)) != NULL);
  nc->user_data = mime2;

  /* Test digest authorization popup */
  snprintf(url, sizeof(url), "http://%s/data/auth/a.txt", local_addr);
  ASSERT((nc = ns_connect_http(&mgr, cb_auth_fail, url, NULL, NULL)) != NULL);
  ns_set_protocol_http_websocket(nc);
  nc->user_data = &resp_code;

  /* Test digest authorization success */
  snprintf(url, sizeof(url), "http://%s/data/auth/a.txt", local_addr);
  ns_http_create_digest_auth_header(auth_hdr, sizeof(auth_hdr), "GET",
                                    "/data/auth/a.txt", "foo.com", "joe",
                                    "doe");
  ASSERT((nc = ns_connect_http(&mgr, cb_auth_ok, url, auth_hdr, NULL)) != NULL);
  ns_set_protocol_http_websocket(nc);
  nc->user_data = auth_ok;
  /* Run event loop. Use more cycles to let file download complete. */
  poll_until(&mgr, 10000, c_str_ne, status, (void *) "");
  ns_mgr_free(&mgr);

  /* Check that test buffer has been filled by the callback properly. */
  ASSERT_STREQ(buf, "[/foo 10] 26");
  ASSERT_STREQ(status, "success");
  ASSERT_STREQ(mime1, "text/xml");
  ASSERT_STREQ(mime2, "text/plain; charset=windows-1251");
  ASSERT_EQ(resp_code, 401); /* Must be 401 Unauthorized */
  ASSERT_STREQ(auth_ok, "200 hi\n");

  return NULL;
}

static const char *test_http_errors(void) {
  struct ns_mgr mgr;
  struct ns_connection *nc;
  const char *local_addr = "127.0.0.1:7777";
  char status[1000] = "";

  ns_mgr_init(&mgr, NULL);
  s_http_server_opts.enable_directory_listing = NULL;
  ASSERT((nc = ns_bind(&mgr, local_addr, cb1)) != NULL);
  ns_set_protocol_http_websocket(nc);

#if !defined(TEST_UNDER_VIRTUALBOX) && !defined(_WIN32)
  /* Test file which exists but cannot be opened */
  ASSERT((nc = ns_connect(&mgr, local_addr, cb8)) != NULL);
  ns_set_protocol_http_websocket(nc);
  nc->user_data = status;
  system("touch test_unreadable; chmod 000 test_unreadable");
  ns_printf(nc, "GET /%s HTTP/1.0\n\n", "../test_unreadable");

  /* Run event loop. Use more cycles to let file download complete. */
  poll_until(&mgr, 1000, c_str_ne, status, (void *) "");
  system("rm -f test_unreadable");

  /* Check that it failed */
  ASSERT_STREQ_NZ(status, "HTTP/1.1 500");
#endif

  /* Test non existing file */
  ASSERT((nc = ns_connect(&mgr, local_addr, cb8)) != NULL);
  ns_set_protocol_http_websocket(nc);
  status[0] = '\0';
  nc->user_data = status;
  ns_printf(nc, "GET /%s HTTP/1.0\n\n", "/please_dont_create_this_file_srsly");

  poll_until(&mgr, 1000, c_str_ne, status, (void *) "");

  /* Check that it failed */
  ASSERT_STREQ_NZ(status, "HTTP/1.1 404");

  /* Test directory without index.html */
  ASSERT((nc = ns_connect(&mgr, local_addr, cb8)) != NULL);
  ns_set_protocol_http_websocket(nc);
  nc->user_data = status;
  status[0] = '\0';
  ns_printf(nc, "GET /%s HTTP/1.0\n\n", "/");

  s_http_server_opts.enable_directory_listing = "no";

  poll_until(&mgr, 1000, c_str_ne, status, (void *) "");

  /* Check that it failed */
  ASSERT_STREQ_NZ(status, "HTTP/1.1 403");

  /* Cleanup */
  ns_mgr_free(&mgr);

  return NULL;
}

static const char *test_http_index(void) {
  char buf[FETCH_BUF_SIZE];
  fetch_http(buf, "%s", "GET /data/dir_with_index/ HTTP/1.0\r\n\r\n");
  ASSERT_STREQ_NZ(buf, "HTTP/1.1 200");
  ASSERT(strstr(buf, "Content-Length: 3\r\n") != 0);
  ASSERT_STREQ(buf + strlen(buf) - 5, "\r\nfoo");
  s_http_server_opts.enable_directory_listing = "yes";

  fetch_http(buf, "%s", "GET /data/dir_no_index/ HTTP/1.0\r\n\r\n");
  ASSERT_STREQ_NZ(buf,
                  "HTTP/1.1 200 OK\r\n"
                  "Transfer-Encoding: chunked\r\n");
  ASSERT(strstr(buf, "40A\r\n<html><head><title>") != NULL);

  /* Test that trailing slash in directory does not get truncated */
  snprintf(buf, sizeof(buf), "%s", "/foo/bar/");
  find_index_file(buf, sizeof(buf), "", NULL);
  ASSERT_STREQ(buf, "/foo/bar/");

  return NULL;
}

static const char *test_ssi(void) {
  char buf[FETCH_BUF_SIZE];
  fetch_http(buf, "%s", "GET /data/ssi/ HTTP/1.0\n\n");
  ASSERT(strcmp(buf,
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                "Connection: close\r\n\r\na\n\nb\n\n\n") == 0);
  return NULL;
}

static const char *test_cgi(void) {
  char buf[FETCH_BUF_SIZE];
  const char *post_data = "aa=1234&bb=hi there";

  fetch_http(buf, "POST /data/cgi/ HTTP/1.0\nContent-Length: %d\n\n%s",
             (int) strlen(post_data), post_data);

/* Needs perl interpreter to run the test */
#ifndef _WIN32
  ASSERT_STREQ_NZ(buf, "HTTP/1.1 201 Created\r\n");
  ASSERT(strstr(buf, "\nSCRIPT_NAME=/data/cgi/index.cgi\n") != NULL);
  ASSERT(strstr(buf, "\nREQUEST_URI=/data/cgi/\n") != NULL);
  ASSERT(strstr(buf, "\nHTTP_CONTENT_LENGTH=19\n") != NULL);
  ASSERT(strstr(buf, "\nPATH_TRANSLATED=./data/cgi/index.cgi\n") != NULL);
  ASSERT(strstr(buf, "\naa=1234\n") != NULL);
  ASSERT(strstr(buf, "\nbb=hi there\n") != NULL);
#endif

  return NULL;
}

static const char *test_http_rewrites(void) {
  char buf[FETCH_BUF_SIZE];

  /* Test rewrite */
  fetch_http(buf, "%s", "GET /~joe/msg.txt HTTP/1.0\nHost: foo.co\n\n");
  ASSERT_STREQ_NZ(buf, "HTTP/1.1 200 OK");
  ASSERT(strstr(buf, "Content-Length: 6\r\n") != 0);
  ASSERT_STREQ(buf + strlen(buf) - 8, "\r\nworks\n");

  /* Test rewrite that points to directory, expect redirect */
  fetch_http(buf, "%s", "GET /~joe HTTP/1.0\n\n");
  ASSERT(strcmp(buf,
                "HTTP/1.1 301 Moved\r\nLocation: /~joe/\r\n"
                "Content-Length: 0\r\n\r\n") == 0);

  /* Test domain-based rewrite */
  fetch_http(buf, "%s", "GET / HTTP/1.0\nHost: foo.com\n\n");
  ASSERT_STREQ_NZ(buf, "HTTP/1.1 200 OK");
  ASSERT(strstr(buf, "Content-Length: 9\r\n") != 0);
  ASSERT_STREQ(buf + strlen(buf) - 11, "\r\nfoo_root\n");

  return NULL;
}

static const char *test_http_dav(void) {
  char buf[FETCH_BUF_SIZE];
  ns_stat_t st;

  remove("./data/dav/b.txt");
  rmdir("./data/dav/d");

  /* Test PROPFIND  */
  fetch_http(buf, "%s", "PROPFIND / HTTP/1.0\n\n");
  ASSERT_STREQ_NZ(buf, "HTTP/1.1 207");
  ASSERT(strstr(buf, "a.txt") != NULL);
  ASSERT(strstr(buf, "hidden_file.txt") == NULL);

  /* Test MKCOL */
  fetch_http(buf, "%s", "MKCOL /d HTTP/1.0\nContent-Length:5\n\n12345");
  ASSERT_STREQ_NZ(buf, "HTTP/1.1 415");
  fetch_http(buf, "%s", "MKCOL /d HTTP/1.0\n\n");
  ASSERT_STREQ_NZ(buf, "HTTP/1.1 201");
  fetch_http(buf, "%s", "MKCOL /d HTTP/1.0\n\n");
  ASSERT_STREQ_NZ(buf, "HTTP/1.1 405");
  fetch_http(buf, "%s", "MKCOL /x/d HTTP/1.0\n\n");
  ASSERT_STREQ_NZ(buf, "HTTP/1.1 409");

  /* Test PUT */
  fetch_http(buf, "%s", "PUT /b.txt HTTP/1.0\nContent-Length: 5\n\n12345");
  ASSERT_STREQ_NZ(buf, "HTTP/1.1 201");
  fetch_http(buf, "%s", "GET /data/dav/b.txt HTTP/1.0\n\n");
  ASSERT_STREQ_NZ(buf, "HTTP/1.1 200");
  ASSERT(strstr(buf, "Content-Length: 5\r\n") != 0);
  ASSERT_STREQ(buf + strlen(buf) - 7, "\r\n12345");

  /* Test DELETE */
  fetch_http(buf, "%s", "DELETE /b.txt HTTP/1.0\n\n");
  ASSERT_STREQ_NZ(buf, "HTTP/1.1 204");
  ASSERT(ns_stat("./data/dav/b.txt", &st) != 0);
  fetch_http(buf, "%s", "DELETE /d HTTP/1.0\n\n");
  ASSERT(ns_stat("./data/dav/d", &st) != 0);

  return NULL;
}

static const char *test_http_range(void) {
  char buf[FETCH_BUF_SIZE];

  fetch_http(buf, "%s", "GET /data/range.txt HTTP/1.0\n\n");
  ASSERT_STREQ_NZ(buf, "HTTP/1.1 200 OK");
  ASSERT(strstr(buf, "Content-Length: 312\r\n") != 0);

  /* Fetch a piece from the middle of the file */
  fetch_http(buf, "%s", "GET /data/range.txt HTTP/1.0\nRange: bytes=5-10\n\n");
  ASSERT_STREQ_NZ(buf, "HTTP/1.1 206 Partial Content");
  ASSERT(strstr(buf, "Content-Length: 6\r\n") != 0);
  ASSERT(strstr(buf, "Content-Range: bytes 5-10/312\r\n") != 0);
  ASSERT_STREQ(buf + strlen(buf) - 8, "\r\n of co");

  /* Fetch till EOF */
  fetch_http(buf, "%s", "GET /data/range.txt HTTP/1.0\nRange: bytes=300-\n\n");
  ASSERT_STREQ_NZ(buf, "HTTP/1.1 206 Partial Content");
  ASSERT(strstr(buf, "Content-Length: 12\r\n") != 0);
  ASSERT(strstr(buf, "Content-Range: bytes 300-311/312\r\n") != 0);
  ASSERT_STREQ(buf + strlen(buf) - 14, "\r\nis disease.\n");

  /* Fetch past EOF, must trigger 416 response */
  fetch_http(buf, "%s", "GET /data/range.txt HTTP/1.0\nRange: bytes=1000-\n\n");
  ASSERT_STREQ_NZ(buf, "HTTP/1.1 416");
  ASSERT(strstr(buf, "Content-Length: 0\r\n") != 0);
  ASSERT(strstr(buf, "Content-Range: bytes */312\r\n") != 0);

  /* Request range past EOF, must trigger 416 response */
  fetch_http(buf, "%s", "GET /data/range.txt HTTP/1.0\nRange: bytes=0-312\n\n");
  ASSERT_STREQ_NZ(buf, "HTTP/1.1 416");

  return NULL;
}

static void cb3(struct ns_connection *nc, int ev, void *ev_data) {
  struct websocket_message *wm = (struct websocket_message *) ev_data;

  if (ev == NS_WEBSOCKET_FRAME) {
    const char *reply = wm->size == 2 && !memcmp(wm->data, "hi", 2) ? "A" : "B";
    ns_printf_websocket_frame(nc, WEBSOCKET_OP_TEXT, "%s", reply);
  }
}

static void cb4(struct ns_connection *nc, int ev, void *ev_data) {
  struct websocket_message *wm = (struct websocket_message *) ev_data;

  if (ev == NS_WEBSOCKET_FRAME) {
    memcpy(nc->user_data, wm->data, wm->size);
    ns_send_websocket_frame(nc, WEBSOCKET_OP_CLOSE, NULL, 0);
  } else if (ev == NS_WEBSOCKET_HANDSHAKE_DONE) {
    /* Send "hi" to server. server must reply "A". */
    struct ns_str h[2];
    h[0].p = "h";
    h[0].len = 1;
    h[1].p = "i";
    h[1].len = 1;
    ns_send_websocket_framev(nc, WEBSOCKET_OP_TEXT, h, 2);
  }
}

static const char *test_websocket(void) {
  struct ns_mgr mgr;
  struct ns_connection *nc;
  const char *local_addr = "127.0.0.1:7778";
  char buf[20] = "";

  ns_mgr_init(&mgr, NULL);
  /* mgr.hexdump_file = "/dev/stdout"; */
  ASSERT((nc = ns_bind(&mgr, local_addr, cb3)) != NULL);
  ns_set_protocol_http_websocket(nc);

  /* Websocket request */
  ASSERT((nc = ns_connect(&mgr, local_addr, cb4)) != NULL);
  ns_set_protocol_http_websocket(nc);
  nc->user_data = buf;
  ns_send_websocket_handshake(nc, "/ws", NULL);
  poll_until(&mgr, 1000, c_str_ne, buf, (void *) "");
  ns_mgr_free(&mgr);

  /* Check that test buffer has been filled by the callback properly. */
  ASSERT_STREQ(buf, "A");

  return NULL;
}

struct big_payload_params {
  size_t size;
  char *buf;
};

static void cb3_big(struct ns_connection *nc, int ev, void *ev_data) {
  struct websocket_message *wm = (struct websocket_message *) ev_data;

  if (ev == NS_WEBSOCKET_FRAME) {
    int success = 1;
    size_t i;
    for (i = 0; i < wm->size; i++) {
      if (wm->data[i] != 'x') {
        success = 0;
        break;
      }
    }
    ns_printf_websocket_frame(nc, WEBSOCKET_OP_TEXT, "%s",
                              success ? "success" : "fail");
  }
}

static void cb4_big(struct ns_connection *nc, int ev, void *ev_data) {
  struct websocket_message *wm = (struct websocket_message *) ev_data;
  struct big_payload_params *params =
      (struct big_payload_params *) nc->user_data;

  if (ev == NS_WEBSOCKET_FRAME) {
    memcpy(params->buf, wm->data, wm->size);
    ns_send_websocket_frame(nc, WEBSOCKET_OP_CLOSE, NULL, 0);
  } else if (ev == NS_WEBSOCKET_HANDSHAKE_DONE) {
    /* Send large payload to server. server must reply "success". */
    char *payload = (char *) malloc(params->size);
    memset(payload, 'x', params->size);
    ns_printf_websocket_frame(nc, WEBSOCKET_OP_TEXT, "%.*s", params->size,
                              payload);
    free(payload);
  }
}

/* Big payloads follow a different code path because it will use the extended
 * length field and possibly ns_avprintf will need to reallocate the buffer. */
static const char *test_websocket_big(void) {
  struct ns_mgr mgr;
  struct ns_connection *nc;
  const char *local_addr = "127.0.0.1:7778";
  char buf[20] = "";
  struct big_payload_params params;
  params.buf = buf;

  ns_mgr_init(&mgr, NULL);
  /* mgr.hexdump_file = "/dev/stdout"; */
  ASSERT((nc = ns_bind(&mgr, local_addr, cb3_big)) != NULL);
  ns_set_protocol_http_websocket(nc);

  /* Websocket request */
  ASSERT((nc = ns_connect(&mgr, local_addr, cb4_big)) != NULL);
  ns_set_protocol_http_websocket(nc);
  params.size = 8192;
  nc->user_data = &params;
  params.buf[0] = '\0';
  ns_send_websocket_handshake(nc, "/ws", NULL);
  poll_until(&mgr, 1000, c_str_ne, params.buf, (void *) "");

  /* Check that test buffer has been filled by the callback properly. */
  ASSERT_STREQ(buf, "success");

  /* Websocket request */
  ASSERT((nc = ns_connect(&mgr, local_addr, cb4_big)) != NULL);
  ns_set_protocol_http_websocket(nc);
  params.size = 65535;
  nc->user_data = &params;
  params.buf[0] = '\0';
  ns_send_websocket_handshake(nc, "/ws", NULL);
  poll_until(&mgr, 1000, c_str_ne, params.buf, (void *) "");
  ns_mgr_free(&mgr);

  /* Check that test buffer has been filled by the callback properly. */
  ASSERT_STREQ(buf, "success");

  return NULL;
}

static const char *test_mqtt_handshake(void) {
  struct ns_connection *nc = (struct ns_connection *) calloc(1, sizeof(*nc));
  const char *client_id = "testclient";
  const char *got;

  ns_send_mqtt_handshake(nc, client_id);
  got = nc->send_mbuf.buf;

  /* handshake header + keepalive + client id len + client id */
  ASSERT_EQ(nc->send_mbuf.len, 12 + 2 + 2 + strlen(client_id));

  ASSERT_EQ(got[2], 0);
  ASSERT_EQ(got[3], 6);
  ASSERT_STREQ_NZ(&got[4], "MQIsdp");
  ASSERT_EQ(got[10], 3);
  ASSERT_EQ(got[11], 0); /* connect flags, TODO */
  ASSERT_EQ(got[12], 0);
  ASSERT_EQ(got[13], 60);

  ASSERT_EQ(got[14], 0);
  ASSERT_EQ(got[15], (char) strlen(client_id));
  ASSERT_EQ(strncmp(&got[16], client_id, strlen(client_id)), 0);

  mbuf_free(&nc->send_mbuf);
  free(nc);
  return NULL;
}

static const char *test_mqtt_publish(void) {
  struct ns_connection *nc = (struct ns_connection *) calloc(1, sizeof(*nc));
  char data[] = "dummy";
  const char *got;

  ns_mqtt_publish(nc, "/test", 42, NS_MQTT_QOS(1) | NS_MQTT_RETAIN, data,
                  sizeof(data));
  got = nc->send_mbuf.buf;
  ASSERT_EQ(nc->send_mbuf.len, 17);

  ASSERT(got[0] & NS_MQTT_RETAIN);
  ASSERT_EQ((got[0] & 0xf0), (NS_MQTT_CMD_PUBLISH << 4));
  ASSERT_EQ(NS_MQTT_GET_QOS(got[0]), 1);
  ASSERT_EQ((size_t) got[1], (nc->send_mbuf.len - 2));

  ASSERT_EQ(got[2], 0);
  ASSERT_EQ(got[3], 5);
  ASSERT_STREQ_NZ(&got[4], "/test");

  ASSERT_EQ(got[9], 0);
  ASSERT_EQ(got[10], 42);

  ASSERT_EQ(strncmp(&got[11], data, sizeof(data)), 0);

  mbuf_free(&nc->send_mbuf);
  free(nc);
  return NULL;
}

static const char *test_mqtt_subscribe(void) {
  struct ns_connection *nc = (struct ns_connection *) calloc(1, sizeof(*nc));
  const char *got;
  const int qos = 1;
  struct ns_mqtt_topic_expression topic_expressions[] = {{"/stuff", qos}};

  ns_mqtt_subscribe(nc, topic_expressions, 1, 42);
  got = nc->send_mbuf.buf;
  ASSERT_EQ(nc->send_mbuf.len, 13);
  ASSERT_EQ((got[0] & 0xf0), (NS_MQTT_CMD_SUBSCRIBE << 4));
  ASSERT_EQ((size_t) got[1], (nc->send_mbuf.len - 2));
  ASSERT_EQ(got[2], 0);
  ASSERT_EQ(got[3], 42);

  ASSERT_EQ(got[4], 0);
  ASSERT_EQ(got[5], 6);
  ASSERT_STREQ_NZ(&got[6], "/stuff");
  ASSERT_EQ(got[12], qos);

  mbuf_free(&nc->send_mbuf);
  free(nc);
  return NULL;
}

static const char *test_mqtt_unsubscribe(void) {
  struct ns_connection *nc = (struct ns_connection *) calloc(1, sizeof(*nc));
  const char *got;
  char *topics[] = {(char *) "/stuff"};

  ns_mqtt_unsubscribe(nc, topics, 1, 42);
  got = nc->send_mbuf.buf;
  ASSERT_EQ(nc->send_mbuf.len, 12);
  ASSERT_EQ((got[0] & 0xf0), (NS_MQTT_CMD_UNSUBSCRIBE << 4));
  ASSERT_EQ((size_t) got[1], (nc->send_mbuf.len - 2));
  ASSERT_EQ(got[2], 0);
  ASSERT_EQ(got[3], 42);

  ASSERT_EQ(got[4], 0);
  ASSERT_EQ(got[5], 6);
  ASSERT_STREQ_NZ(&got[6], "/stuff");

  mbuf_free(&nc->send_mbuf);
  free(nc);
  return NULL;
}

static const char *test_mqtt_connack(void) {
  struct ns_connection *nc = (struct ns_connection *) calloc(1, sizeof(*nc));
  const char *got;
  ns_mqtt_connack(nc, 42);
  got = nc->send_mbuf.buf;
  ASSERT(nc->send_mbuf.len > 0);
  ASSERT_EQ((got[0] & 0xf0), (NS_MQTT_CMD_CONNACK << 4));
  ASSERT_EQ((size_t) got[1], (nc->send_mbuf.len - 2));
  ASSERT_EQ(got[3], 42);

  mbuf_free(&nc->send_mbuf);
  free(nc);
  return NULL;
}

static const char *test_mqtt_suback(void) {
  struct ns_connection *nc = (struct ns_connection *) calloc(1, sizeof(*nc));
  const char *got;

  uint8_t qoss[] = {1};

  ns_mqtt_suback(nc, qoss, 1, 42);

  got = nc->send_mbuf.buf;
  ASSERT_EQ(nc->send_mbuf.len, 5);
  ASSERT_EQ((got[0] & 0xf0), (NS_MQTT_CMD_SUBACK << 4));
  ASSERT_EQ(NS_MQTT_GET_QOS(got[0]), 1);
  ASSERT_EQ((size_t) got[1], (nc->send_mbuf.len - 2));
  ASSERT_EQ(got[2], 0);
  ASSERT_EQ(got[3], 42);
  ASSERT_EQ(got[4], 1);

  mbuf_free(&nc->send_mbuf);
  free(nc);
  return NULL;
}

static const char *test_mqtt_simple_acks(void) {
  unsigned long i;
  struct {
    uint8_t cmd;
    void (*f)(struct ns_connection *, uint16_t);
  } cases[] = {
      {NS_MQTT_CMD_PUBACK, ns_mqtt_puback},
      {NS_MQTT_CMD_PUBREC, ns_mqtt_pubrec},
      {NS_MQTT_CMD_PUBREL, ns_mqtt_pubrel},
      {NS_MQTT_CMD_PUBCOMP, ns_mqtt_pubcomp},
      {NS_MQTT_CMD_UNSUBACK, ns_mqtt_unsuback},
  };

  for (i = 0; i < ARRAY_SIZE(cases); i++) {
    struct ns_connection *nc = (struct ns_connection *) calloc(1, sizeof(*nc));
    const char *got;

    cases[i].f(nc, 42);

    got = nc->send_mbuf.buf;
    ASSERT_EQ(nc->send_mbuf.len, 4);
    ASSERT_EQ((got[0] & 0xf0), (cases[i].cmd << 4));
    ASSERT_EQ(NS_MQTT_GET_QOS(got[0]), 1);
    ASSERT_EQ((size_t) got[1], (nc->send_mbuf.len - 2));
    ASSERT_EQ(got[2], 0);
    ASSERT_EQ(got[3], 42);

    mbuf_free(&nc->send_mbuf);
    free(nc);
  }
  return NULL;
}

static const char *test_mqtt_nullary(void) {
  unsigned long i;
  struct {
    uint8_t cmd;
    void (*f)(struct ns_connection *);
  } cases[] = {
      {NS_MQTT_CMD_PINGREQ, ns_mqtt_ping},
      {NS_MQTT_CMD_PINGRESP, ns_mqtt_pong},
      {NS_MQTT_CMD_DISCONNECT, ns_mqtt_disconnect},
  };

  for (i = 0; i < ARRAY_SIZE(cases); i++) {
    struct ns_connection *nc = (struct ns_connection *) calloc(1, sizeof(*nc));
    const char *got;

    cases[i].f(nc);

    got = nc->send_mbuf.buf;
    ASSERT_EQ(nc->send_mbuf.len, 2);
    ASSERT_EQ((got[0] & 0xf0), (cases[i].cmd << 4));
    ASSERT_EQ((size_t) got[1], (nc->send_mbuf.len - 2));

    mbuf_free(&nc->send_mbuf);
    free(nc);
  }
  return NULL;
}

static const size_t mqtt_long_payload_len = 200;
static const size_t mqtt_very_long_payload_len = 20000;

static void mqtt_eh(struct ns_connection *nc, int ev, void *ev_data) {
  struct ns_mqtt_message *mm = (struct ns_mqtt_message *) ev_data;
  size_t i;
  (void) nc;
  (void) ev_data;

  switch (ev) {
    case NS_MQTT_SUBACK:
      *((int *) nc->user_data) = 1;
      break;
    case NS_MQTT_PUBLISH:
      if (strncmp(mm->topic, "/topic", 6)) break;

      for (i = 0; i < mm->payload.len; i++) {
        if (nc->recv_mbuf.buf[10 + i] != 'A') break;
      }

      if (mm->payload.len == mqtt_long_payload_len) {
        *((int *) nc->user_data) = 2;
      } else if (mm->payload.len == mqtt_very_long_payload_len) {
        *((int *) nc->user_data) = 3;
      }
      break;
    case NS_MQTT_CONNACK:
      *((int *) nc->user_data) = 4;
      break;
  }
}

static const char *test_mqtt_parse_mqtt(void) {
  struct ns_connection *nc = (struct ns_connection *) calloc(1, sizeof(*nc));
  char msg[] = {(char) (NS_MQTT_CMD_SUBACK << 4), 2};
  char *long_msg;
  int check = 0;
  int num_bytes = sizeof(msg);
  int rest_len;

  nc->user_data = &check;
  nc->handler = mqtt_eh;
  ns_set_protocol_mqtt(nc);

  mbuf_append(&nc->recv_mbuf, msg, num_bytes);
  nc->proto_handler(nc, NS_RECV, &num_bytes);

  ASSERT_EQ(check, 1);
  mbuf_free(&nc->recv_mbuf);

  /* test a payload whose length encodes as two bytes */
  rest_len = 8 + mqtt_long_payload_len;
  long_msg = (char *) malloc(512);
  long_msg[0] = (char) (NS_MQTT_CMD_PUBLISH << 4);
  long_msg[1] = (rest_len & 127) | 0x80;
  long_msg[2] = rest_len >> 7;
  memcpy(&long_msg[3], "\0\006/topic", 8);
  memset(&long_msg[11], 'A', mqtt_long_payload_len);

  num_bytes = 2 + rest_len;
  mbuf_append(&nc->recv_mbuf, long_msg, num_bytes);
  nc->proto_handler(nc, NS_RECV, &num_bytes);

  ASSERT_EQ(check, 2);
  mbuf_free(&nc->recv_mbuf);
  free(long_msg);

  /* test a payload whose length encodes as two bytes */
  rest_len = 8 + mqtt_very_long_payload_len;
  long_msg = (char *) malloc(20100);
  long_msg[0] = (char) (NS_MQTT_CMD_PUBLISH << 4);
  long_msg[1] = (rest_len & 127) | 0x80;
  long_msg[2] = ((rest_len >> 7) & 127) | 0x80;
  long_msg[3] = (rest_len >> 14);
  memcpy(&long_msg[4], "\0\006/topic", 8);
  memset(&long_msg[12], 'A', mqtt_very_long_payload_len);

  num_bytes = 2 + rest_len;
  mbuf_append(&nc->recv_mbuf, long_msg, num_bytes);
  nc->proto_handler(nc, NS_RECV, &num_bytes);

  ASSERT_EQ(check, 3);
  mbuf_free(&nc->recv_mbuf);
  free(long_msg);

  /* test encoding a large payload */
  long_msg = (char *) malloc(mqtt_very_long_payload_len);
  memset(long_msg, 'A', mqtt_very_long_payload_len);
  ns_mqtt_publish(nc, "/topic", 0, 0, long_msg, mqtt_very_long_payload_len);
  nc->recv_mbuf = nc->send_mbuf;
  mbuf_init(&nc->send_mbuf, 0);
  num_bytes = nc->recv_mbuf.len;
  nc->proto_handler(nc, NS_RECV, &num_bytes);

  ASSERT_EQ(check, 3);
  mbuf_free(&nc->recv_mbuf);
  free(long_msg);

  /* test connack parsing */
  ns_mqtt_connack(nc, 0);
  nc->recv_mbuf = nc->send_mbuf;
  mbuf_init(&nc->send_mbuf, 0);
  num_bytes = 4;
  nc->proto_handler(nc, NS_RECV, &num_bytes);

  ASSERT_EQ(check, 4);
  mbuf_free(&nc->recv_mbuf);

  free(nc);
  return NULL;
}

#ifdef NS_ENABLE_MQTT_BROKER
struct ns_mqtt_topic_expression brk_test_te[] = {{"/dummy", 0}, {"/unit/#", 0}};

static void brk_cln_cb1(struct ns_connection *nc, int ev, void *p) {
  struct ns_mqtt_message *msg = (struct ns_mqtt_message *) p;

  switch (ev) {
    case NS_CONNECT:
      ns_set_protocol_mqtt(nc);
      ns_send_mqtt_handshake(nc, "dummy");
      break;
    case NS_MQTT_CONNACK:
      ns_mqtt_subscribe(nc, brk_test_te, ARRAY_SIZE(brk_test_te), 42);
      break;
    case NS_MQTT_SUBACK:
      ns_mqtt_publish(nc, "/unit/test", 0, NS_MQTT_QOS(0), "payload", 7);
      break;
    case NS_MQTT_PUBLISH:
      if (strncmp(msg->topic, "/unit/test", 10) == 0 && msg->payload.len == 7 &&
          ns_vcmp(&msg->payload, "payload") == 0) {
        *(int *) nc->user_data = 1;
      }
      break;
  }
}

static const char *test_mqtt_broker(void) {
  struct ns_mgr mgr;
  struct ns_mqtt_broker brk;
  struct ns_connection *brk_nc;
  struct ns_connection *cln_nc;
  const char *brk_local_addr = "127.0.0.1:7777";
  int brk_data = 0, cln_data = 0;

  ns_mgr_init(&mgr, NULL);
  ns_mqtt_broker_init(&brk, &brk_data);

  ASSERT((brk_nc = ns_bind(&mgr, brk_local_addr, ns_mqtt_broker)) != NULL);
  brk_nc->user_data = &brk;

  ASSERT((cln_nc = ns_connect(&mgr, brk_local_addr, brk_cln_cb1)) != NULL);
  cln_nc->user_data = &cln_data;

  /* Run event loop. Use more cycles to let client and broker communicate. */
  poll_until(&mgr, 1000, c_int_eq, &cln_data, (void *) 1);

  ASSERT_EQ(cln_data, 1);

  ns_mgr_free(&mgr);

  return NULL;
}
#endif /* NS_ENABLE_MQTT_BROKER */

static int rpc_sum(char *buf, int len, struct ns_rpc_request *req) {
  double sum = 0;
  int i;

  if (req->params[0].type != JSON_TYPE_ARRAY) {
    return ns_rpc_create_std_error(buf, len, req,
                                   JSON_RPC_INVALID_PARAMS_ERROR);
  }

  for (i = 0; i < req->params[0].num_desc; i++) {
    if (req->params[i + 1].type != JSON_TYPE_NUMBER) {
      return ns_rpc_create_std_error(buf, len, req,
                                     JSON_RPC_INVALID_PARAMS_ERROR);
    }
    sum += strtod(req->params[i + 1].ptr, NULL);
  }
  return ns_rpc_create_reply(buf, len, req, "f", sum);
}

static void rpc_server(struct ns_connection *nc, int ev, void *ev_data) {
  struct http_message *hm = (struct http_message *) ev_data;
  static const char *methods[] = {"sum", NULL};
  static ns_rpc_handler_t handlers[] = {rpc_sum, NULL};
  char buf[100];

  switch (ev) {
    case NS_HTTP_REQUEST:
      ns_rpc_dispatch(hm->body.p, hm->body.len, buf, sizeof(buf), methods,
                      handlers);
      ns_printf(nc,
                "HTTP/1.0 200 OK\r\nContent-Length: %d\r\n"
                "Content-Type: application/json\r\n\r\n%s",
                (int) strlen(buf), buf);
      nc->flags |= NSF_SEND_AND_CLOSE;
      break;
    default:
      break;
  }
}

static void rpc_client(struct ns_connection *nc, int ev, void *ev_data) {
  struct http_message *hm = (struct http_message *) ev_data;
  struct ns_rpc_reply rpc_reply;
  struct ns_rpc_error rpc_error;
  struct json_token toks[20];
  char buf[100];

  switch (ev) {
    case NS_CONNECT:
      ns_rpc_create_request(buf, sizeof(buf), "sum", "1", "[f,f,f]", 1.0, 2.0,
                            13.0);
      ns_printf(nc,
                "POST / HTTP/1.0\r\nContent-Type: application/json\r\n"
                "Content-Length: %d\r\n\r\n%s",
                (int) strlen(buf), buf);
      break;
    case NS_HTTP_REPLY:
      ns_rpc_parse_reply(hm->body.p, hm->body.len, toks,
                         sizeof(toks) / sizeof(toks[0]), &rpc_reply,
                         &rpc_error);
      if (rpc_reply.result != NULL) {
        sprintf((char *) nc->user_data, "%d %.*s %.*s", rpc_reply.id->type,
                (int) rpc_reply.id->len, rpc_reply.id->ptr,
                (int) rpc_reply.result->len, rpc_reply.result->ptr);
      }
      break;
    default:
      break;
  }
}

static const char *test_rpc(void) {
  struct ns_mgr mgr;
  struct ns_connection *nc;
  const char *local_addr = "127.0.0.1:7779";
  char buf[100] = "";

  ns_mgr_init(&mgr, NULL);

  ASSERT((nc = ns_bind(&mgr, local_addr, rpc_server)) != NULL);
  ns_set_protocol_http_websocket(nc);

  ASSERT((nc = ns_connect(&mgr, local_addr, rpc_client)) != NULL);
  ns_set_protocol_http_websocket(nc);
  nc->user_data = buf;

  poll_until(&mgr, 1000, c_str_ne, buf, (void *) "");
  ns_mgr_free(&mgr);

  ASSERT_STREQ(buf, "1 1 16");

  return NULL;
}

static void cb5(struct ns_connection *nc, int ev, void *ev_data) {
  switch (ev) {
    case NS_CONNECT:
      sprintf((char *) nc->user_data, "%d", *(int *) ev_data);
      break;
    default:
      break;
  }
}

static const char *test_connect_fail(void) {
  struct ns_mgr mgr;
  struct ns_connection *nc;
  char buf[100] = "0";

  ns_mgr_init(&mgr, NULL);
  ASSERT((nc = ns_connect(&mgr, "127.0.0.1:33211", cb5)) != NULL);
  nc->user_data = buf;
  poll_until(&mgr, 1000, c_str_ne, buf, (void *) "0");
  ns_mgr_free(&mgr);

/* printf("failed connect status: [%s]\n", buf); */
/* TODO(lsm): fix this for Win32 */
#ifndef _WIN32
  ASSERT(strcmp(buf, "0") != 0);
#endif

  return NULL;
}

static void cb6(struct ns_connection *nc, int ev, void *ev_data) {
  (void) ev;
  (void) ev_data;
  nc->flags |= NSF_USER_4;
  nc->flags |= NSF_WANT_READ; /* Should not be allowed. */
}

static const char *test_connect_opts(void) {
  struct ns_mgr mgr;
  struct ns_connection *nc;
  struct ns_connect_opts opts;

  opts.user_data = (void *) 0xdeadbeef;
  opts.flags = NSF_USER_6;
  opts.flags |= NSF_WANT_READ; /* Should not be allowed. */

  ns_mgr_init(&mgr, NULL);
  ASSERT((nc = ns_connect_opt(&mgr, "127.0.0.1:33211", cb6, opts)) != NULL);
  ASSERT(nc->user_data == (void *) 0xdeadbeef);
  ASSERT(nc->flags & NSF_USER_6);
  ASSERT(!(nc->flags & NSF_WANT_READ));
  /* TODO(rojer): find a way to test this w/o touching nc (already freed).
    poll_mgr(&mgr, 25);
    ASSERT(nc->flags & NSF_USER_4);
    ASSERT(nc->flags & NSF_USER_6);
    ASSERT(!(nc->flags & NSF_WANT_READ));
  */
  ns_mgr_free(&mgr);
  return NULL;
}

static const char *test_connect_opts_error_string(void) {
  struct ns_mgr mgr;
  struct ns_connection *nc;
  struct ns_connect_opts opts;
  const char *error_string = NULL;

  opts.error_string = &error_string;

  ns_mgr_init(&mgr, NULL);
  ASSERT((nc = ns_connect_opt(&mgr, "127.0.0.1:65537", cb6, opts)) == NULL);
  ASSERT(error_string != NULL);
  ASSERT_STREQ(error_string, "cannot parse address");
  ns_mgr_free(&mgr);
  return NULL;
}

#ifndef NO_DNS_TEST
static const char *test_resolve(void) {
  char buf[20];

  ASSERT(ns_resolve("localhost", buf, sizeof(buf)) > 0);
  ASSERT_STREQ(buf, "127.0.0.1");

  ASSERT_EQ(ns_resolve("please_dont_name_a_host_like_ths", buf, sizeof(buf)),
            0);
  return NULL;
}
#endif

static const char *test_base64(void) {
  const char *cases[] = {"test", "longer string"};
  unsigned long i;
  char enc[8192];
  char dec[8192];

  for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    ns_base64_encode((unsigned char *) cases[i], strlen(cases[i]), enc);
    ns_base64_decode((unsigned char *) enc, strlen(enc), dec);

    ASSERT_EQ(strcmp(cases[i], dec), 0);
  }

  ASSERT_EQ(ns_base64_decode((unsigned char *) "кю", 4, dec), 0);
  ASSERT_EQ(ns_base64_decode((unsigned char *) "AAAA----", 8, dec), 4);
  ASSERT_EQ(ns_base64_decode((unsigned char *) "Q2VzYW50YQ==", 12, dec), 12);
  ASSERT_STREQ(dec, "Cesanta");

  return NULL;
}

static const char *test_sock_addr_to_str(void) {
  char buf[60];
  buf[0] = '\0';
  {
    union socket_address a4;
    memset(&a4, 0, sizeof(a4));
    a4.sa.sa_family = AF_INET;
    a4.sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    a4.sin.sin_port = htons(12345);
    ns_sock_addr_to_str(&a4, buf, sizeof(buf), 0);
    ASSERT_STREQ(buf, "");
    ns_sock_addr_to_str(&a4, buf, sizeof(buf), NS_SOCK_STRINGIFY_IP);
    ASSERT_STREQ(buf, "127.0.0.1");
    ns_sock_addr_to_str(&a4, buf, sizeof(buf), NS_SOCK_STRINGIFY_PORT);
    ASSERT_STREQ(buf, "12345");
    ns_sock_addr_to_str(&a4, buf, sizeof(buf),
                        NS_SOCK_STRINGIFY_IP | NS_SOCK_STRINGIFY_PORT);
    ASSERT_STREQ(buf, "127.0.0.1:12345");
  }
#if defined(NS_ENABLE_IPV6) && !defined(_WIN32)
  {
    union socket_address a6;
    memset(&a6, 0, sizeof(a6));
    a6.sa.sa_family = AF_INET6;
    ASSERT_EQ(inet_pton(AF_INET6, "2001::123", &a6.sin6.sin6_addr), 1);
    a6.sin6.sin6_port = htons(12345);
    ns_sock_addr_to_str(&a6, buf, sizeof(buf), 0);
    ASSERT_STREQ(buf, "");
    ns_sock_addr_to_str(&a6, buf, sizeof(buf), NS_SOCK_STRINGIFY_IP);
    ASSERT_STREQ(buf, "2001::123");
    ns_sock_addr_to_str(&a6, buf, sizeof(buf), NS_SOCK_STRINGIFY_PORT);
    ASSERT_STREQ(buf, "12345");
    ns_sock_addr_to_str(&a6, buf, sizeof(buf),
                        NS_SOCK_STRINGIFY_IP | NS_SOCK_STRINGIFY_PORT);
    ASSERT_STREQ(buf, "[2001::123]:12345");
  }
#endif
  return NULL;
}

static const char *test_hexdump(void) {
  const char *src = "\1\2\3\4abcd";
  char got[256];

  const char *want =
      "0000  01 02 03 04 61 62 63 64"
      "                          ....abcd\n\n";
  ASSERT_EQ(ns_hexdump(src, strlen(src), got, sizeof(got)), (int) strlen(want));
  ASSERT_EQ(strcmp(got, want), 0);
  return NULL;
}

static const char *test_hexdump_file(void) {
  const char *path = "test_hexdump";
  const char *want =
      "0xbeef :0 -> :0 3\n"
      "0000  66 6f 6f   "
      "                                      foo\n\n";
  char *data, *got;
  size_t size;
  struct ns_connection *nc = (struct ns_connection *) calloc(1, sizeof(*nc));

  /* "In the GNU system, non-null pointers are printed as unsigned integers,
   * as if a `%#x' conversion were used. Null pointers print as `(nil)'.
   * (Pointers might print differently in other systems.)"
   * indeed it prints 0x0 on apple.
   */
  nc->user_data = (void *) 0xbeef;
  close(open(path, O_TRUNC | O_WRONLY));

  mbuf_append(&nc->send_mbuf, "foo", 3);
  mbuf_append(&nc->recv_mbuf, "bar", 3);
  ns_hexdump_connection(nc, path, 3, NS_SEND);

  mbuf_free(&nc->send_mbuf);
  mbuf_free(&nc->recv_mbuf);
  free(nc);

  ASSERT((data = read_file(path, &size)) != NULL);
  unlink(path);

  got = data;
  while (got - data < (int) size && *got++ != ' ')
    ;
  size -= got - data;
/* Windows uses different formatting for */
#ifdef _WIN32
  ASSERT(strstr(got,
                "0000  66 6f 6f                "
                "                         foo") != NULL);
#else
  ASSERT_EQ(strncmp(got, want, size), 0);
#endif

  free(data);
  return NULL;
}

static const char *test_http_chunk(void) {
  struct ns_connection nc;

  memset(&nc, 0, sizeof(nc));

  ns_printf_http_chunk(&nc, "%d %s", 123, ":-)");
  ASSERT_EQ(nc.send_mbuf.len, 12);
  ASSERT_EQ(memcmp(nc.send_mbuf.buf, "7\r\n123 :-)\r\n", 12), 0);
  mbuf_free(&nc.send_mbuf);

  ns_send_http_chunk(&nc, "", 0);
  ASSERT_EQ(nc.send_mbuf.len, 5);
  ASSERT_EQ(memcmp(nc.send_mbuf.buf, "0\r\n\r\n", 3), 0);
  mbuf_free(&nc.send_mbuf);

  return NULL;
}

static const char *test_dns_encode(void) {
  struct ns_connection nc;
  const char *got;
  int query_types[] = {NS_DNS_A_RECORD, NS_DNS_AAAA_RECORD};
  size_t i;
  memset(&nc, 0, sizeof(nc));

  /*
   * Testing TCP encoding since when the connection
   * is in UDP mode the data is not stored in the send buffer.
   */

  for (i = 0; i < ARRAY_SIZE(query_types); i++) {
    ns_send_dns_query(&nc, "www.cesanta.com", query_types[i]);
    got = nc.send_mbuf.buf;
    ASSERT_EQ(nc.send_mbuf.len, 12 + 4 + 13 + 4 + 2);
    ASSERT_EQ(got[14], 3);
    ASSERT_STREQ_NZ(&got[15], "www");
    ASSERT_EQ(got[18], 7);
    ASSERT_STREQ_NZ(&got[19], "cesanta");
    ASSERT_EQ(got[26], 3);
    ASSERT_STREQ_NZ(&got[27], "com");
    ASSERT_EQ(got[30], 0);
    ASSERT_EQ(got[31], 0);
    ASSERT_EQ(got[32], query_types[i]);
    ASSERT_EQ(got[33], 0);
    ASSERT_EQ(got[34], 1);

    mbuf_free(&nc.send_mbuf);
  }
  return NULL;
}

static const char *test_dns_uncompress(void) {
#if 1
  return NULL;
#else
  struct ns_dns_message msg;
  struct ns_str name = NS_STR("\3www\7cesanta\3com\0");
  struct ns_str comp_name = NS_STR("\3www\300\5");
  char dst[256];
  int len;
  size_t i;

  const char *cases[] = {"www.cesanta.com", "www", "ww", "www.", "www.c"};

  memset(&msg, 0, sizeof(msg));
  msg.pkt.p = "dummy\07cesanta\3com";
  msg.pkt.len = strlen(msg.pkt.p);

  for (i = 0; i < ARRAY_SIZE(cases); i++) {
    size_t l = strlen(cases[i]);
    memset(dst, 'X', sizeof(dst));
    len = ns_dns_uncompress_name(&msg, &name, dst, l);
    ASSERT_EQ(len, (int) l);
    ASSERT_EQ(strncmp(dst, cases[i], l), 0);
    ASSERT_EQ(dst[l], 'X');
  }

  /* if dst has enough space, check the trailing '\0' */
  memset(dst, 'X', sizeof(dst));
  len = ns_dns_uncompress_name(&msg, &name, dst, sizeof(dst));
  ASSERT_EQ(len, 15);
  ASSERT_EQ(len, (int) strlen(dst));
  ASSERT_STREQ_NZ(dst, "www.cesanta.com");
  ASSERT_EQ(dst[15], 0);

  /* check compressed name */
  memset(dst, 'X', sizeof(dst));
  len = ns_dns_uncompress_name(&msg, &comp_name, dst, sizeof(dst));
  ASSERT_EQ(len, 15);
  ASSERT_EQ(len, (int) strlen(dst));
  ASSERT_STREQ_NZ(dst, "www.cesanta.com");
  ASSERT_EQ(dst[15], 0);

  return NULL;
#endif
}

static const char *test_dns_decode(void) {
  struct ns_dns_message msg;
  char name[256];
  const char *hostname = "go.cesanta.com";
  const char *cname = "ghs.googlehosted.com";
  struct ns_dns_resource_record *r;
  uint16_t tiny;
  struct in_addr ina;
  int n;

  /*
   * Response for a record A query host for `go.cesanta.com`.
   * The response contains two answers:
   *
   * CNAME go.cesanta.com -> ghs.googlehosted.com
   * A ghs.googlehosted.com -> 74.125.136.121
   *
   * Captured from a reply generated by Google DNS server (8.8.8.8)
   */
  const unsigned char pkt[] = {
      0xa1, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
      0x02, 0x67, 0x6f, 0x07, 0x63, 0x65, 0x73, 0x61, 0x6e, 0x74, 0x61, 0x03,
      0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05,
      0x00, 0x01, 0x00, 0x00, 0x09, 0x52, 0x00, 0x13, 0x03, 0x67, 0x68, 0x73,
      0x0c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x68, 0x6f, 0x73, 0x74, 0x65,
      0x64, 0xc0, 0x17, 0xc0, 0x2c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01,
      0x2b, 0x00, 0x04, 0x4a, 0x7d, 0x88, 0x79};

  ASSERT_EQ(ns_parse_dns((const char *) pkt, sizeof(pkt), &msg), 0);
  ASSERT_EQ(msg.num_questions, 1);
  ASSERT_EQ(msg.num_answers, 2);

  r = &msg.questions[0];
  ASSERT_EQ(ns_dns_uncompress_name(&msg, &r->name, name, sizeof(name)),
            strlen(hostname));
  ASSERT_EQ(strncmp(name, hostname, strlen(hostname)), 0);

  r = &msg.answers[0];
  ASSERT_EQ(ns_dns_uncompress_name(&msg, &r->name, name, sizeof(name)),
            strlen(hostname));
  ASSERT_EQ(strncmp(name, hostname, strlen(hostname)), 0);

  ASSERT_EQ(ns_dns_uncompress_name(&msg, &r->rdata, name, sizeof(name)),
            strlen(cname));
  ASSERT_EQ(strncmp(name, cname, strlen(cname)), 0);

  r = &msg.answers[1];
  ASSERT_EQ(ns_dns_uncompress_name(&msg, &r->name, name, sizeof(name)),
            strlen(cname));
  ASSERT_EQ(strncmp(name, cname, strlen(cname)), 0);
  ASSERT_EQ(ns_dns_parse_record_data(&msg, r, &tiny, sizeof(tiny)), -1);
  ASSERT_EQ(ns_dns_parse_record_data(&msg, r, &ina, sizeof(ina)), 0);
  ASSERT_EQ(ina.s_addr, inet_addr("74.125.136.121"));

  /* Test iteration */
  n = 0;
  r = NULL;
  while ((r = ns_dns_next_record(&msg, NS_DNS_A_RECORD, r))) {
    n++;
  }
  ASSERT_EQ(n, 1);

  n = 0;
  r = NULL;
  while ((r = ns_dns_next_record(&msg, NS_DNS_CNAME_RECORD, r))) {
    n++;
  }
  ASSERT_EQ(n, 1);

  /* Test unknown record type */
  r = ns_dns_next_record(&msg, NS_DNS_A_RECORD, r);
  r->rtype = 0xff;
  ASSERT_EQ(ns_dns_parse_record_data(&msg, r, &ina, sizeof(ina)), -1);

  return NULL;
}

static const char *test_dns_decode_truncated(void) {
  struct ns_dns_message msg;
  char name[256];
  const char *hostname = "go.cesanta.com";
  const char *cname = "ghs.googlehosted.com";
  struct ns_dns_resource_record *r;
  uint16_t tiny;
  struct in_addr ina;
  int n;
  int i;

  const unsigned char src[] = {
      0xa1, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
      0x02, 0x67, 0x6f, 0x07, 0x63, 0x65, 0x73, 0x61, 0x6e, 0x74, 0x61, 0x03,
      0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05,
      0x00, 0x01, 0x00, 0x00, 0x09, 0x52, 0x00, 0x13, 0x03, 0x67, 0x68, 0x73,
      0x0c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x68, 0x6f, 0x73, 0x74, 0x65,
      0x64, 0xc0, 0x17, 0xc0, 0x2c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01,
      0x2b, 0x00, 0x04, 0x4a, 0x7d, 0x88, 0x79};
  char *pkt = NULL;

#define WONDER(expr) \
  if (!(expr)) continue

  for (i = sizeof(src) - 1; i > 0; i--) {
    if (pkt != NULL) {
      free(pkt);
    }
    pkt = (char *) malloc(i);
    memcpy(pkt, src, i);

    WONDER(ns_parse_dns((const char *) pkt, i, &msg) == 0);
    WONDER(msg.num_questions == 1);
    WONDER(msg.num_answers == 2);

    r = &msg.questions[0];
    WONDER(ns_dns_uncompress_name(&msg, &r->name, name, sizeof(name)) ==
           strlen(hostname));
    WONDER(strncmp(name, hostname, strlen(hostname)) == 0);

    r = &msg.answers[0];
    WONDER(ns_dns_uncompress_name(&msg, &r->name, name, sizeof(name)) ==
           strlen(hostname));
    WONDER(strncmp(name, hostname, strlen(hostname)) == 0);

    WONDER(ns_dns_uncompress_name(&msg, &r->rdata, name, sizeof(name)) ==
           strlen(cname));
    WONDER(strncmp(name, cname, strlen(cname)) == 0);

    r = &msg.answers[1];
    WONDER(ns_dns_uncompress_name(&msg, &r->name, name, sizeof(name)) ==
           strlen(cname));
    WONDER(strncmp(name, cname, strlen(cname)) == 0);
    WONDER(ns_dns_parse_record_data(&msg, r, &tiny, sizeof(tiny)) == -1);
    WONDER(ns_dns_parse_record_data(&msg, r, &ina, sizeof(ina)) == 0);
    WONDER(ina.s_addr == inet_addr("74.125.136.121"));

    /* Test iteration */
    n = 0;
    r = NULL;
    while ((r = ns_dns_next_record(&msg, NS_DNS_A_RECORD, r))) {
      n++;
    }
    WONDER(n == 1);

    n = 0;
    r = NULL;
    while ((r = ns_dns_next_record(&msg, NS_DNS_CNAME_RECORD, r))) {
      n++;
    }
    WONDER(n == 1);

    /* Test unknown record type */
    r = ns_dns_next_record(&msg, NS_DNS_A_RECORD, r);
    WONDER(r != NULL);
    printf("GOT %p\n", r);
    r->rtype = 0xff;
    WONDER(ns_dns_parse_record_data(&msg, r, &ina, sizeof(ina)) == -1);

    ASSERT("Should have failed" != NULL);
  }
  return NULL;
}

static const char *check_www_cesanta_com_reply(const char *pkt, size_t len) {
  char name[256];

  in_addr_t addr = inet_addr("54.194.65.250");
  struct in_addr ina;
  struct ns_dns_message msg;

  memset(&msg, 0, sizeof(msg));
  ASSERT(ns_parse_dns(pkt, len, &msg) != -1);

  memset(name, 0, sizeof(name));
  ASSERT(ns_dns_uncompress_name(&msg, &msg.questions[0].name, name,
                                sizeof(name)) > 0);
  ASSERT_STREQ_NZ(name, "www.cesanta.com");
  memset(name, 0, sizeof(name));
  ASSERT(ns_dns_uncompress_name(&msg, &msg.answers[0].name, name,
                                sizeof(name)) > 0);
  ASSERT_STREQ_NZ(name, "www.cesanta.com");
  ASSERT_EQ(msg.answers[0].rtype, NS_DNS_CNAME_RECORD);
  memset(name, 0, sizeof(name));
  ASSERT(ns_dns_parse_record_data(&msg, &msg.answers[0], name, sizeof(name)) !=
         -1);
  ASSERT_STREQ_NZ(name, "cesanta.com");
  memset(name, 0, sizeof(name));
  ASSERT(ns_dns_uncompress_name(&msg, &msg.answers[1].name, name,
                                sizeof(name)) > 0);
  ASSERT_STREQ_NZ(name, "cesanta.com");

  ASSERT_EQ(msg.answers[1].rtype, NS_DNS_A_RECORD);
  ASSERT(ns_dns_parse_record_data(&msg, &msg.answers[1], &ina, sizeof(ina)) !=
         -1);
  ASSERT_EQ(ina.s_addr, addr);

  return NULL;
}

static const char *test_dns_reply_encode(void) {
  const char *err;
  struct ns_dns_message msg;
  struct ns_dns_resource_record *rr;
  char name[256];
  in_addr_t addr = inet_addr("54.194.65.250");
  struct mbuf pkt;
  struct ns_connection nc;

  mbuf_init(&pkt, 0);
  memset(&nc, 0, sizeof(nc));

  /* create a fake query */

  ns_send_dns_query(&nc, "www.cesanta.com", NS_DNS_A_RECORD);
  /* remove message length from tcp buffer */
  mbuf_remove(&nc.send_mbuf, 2);

  ns_parse_dns(nc.send_mbuf.buf, nc.send_mbuf.len, &msg);

  /* build an answer */

  msg.num_answers = 2;
  ns_dns_insert_header(&pkt, 0, &msg);
  ns_dns_copy_body(&pkt, &msg);

  ns_dns_uncompress_name(&msg, &msg.questions[0].name, name, sizeof(name));

  rr = &msg.answers[0];
  *rr = msg.questions[0];
  rr->rtype = NS_DNS_CNAME_RECORD;
  rr->ttl = 3600;
  rr->kind = NS_DNS_ANSWER;
  ASSERT(ns_dns_encode_record(&pkt, rr, "www.cesanta.com", 15,
                              (void *) "cesanta.com", 11) != -1);

  rr = &msg.answers[1];
  *rr = msg.questions[0];
  rr->ttl = 3600;
  rr->kind = NS_DNS_ANSWER;
  ASSERT(ns_dns_encode_record(&pkt, rr, "cesanta.com", 11, &addr, 4) != -1);

  if ((err = check_www_cesanta_com_reply(pkt.buf, pkt.len)) != NULL) {
    return err;
  }

  mbuf_free(&pkt);
  mbuf_free(&nc.send_mbuf);
  return NULL;
}

#ifdef NS_ENABLE_DNS_SERVER
static void dns_server_eh(struct ns_connection *nc, int ev, void *ev_data) {
  struct ns_dns_message *msg;
  struct ns_dns_resource_record *rr;
  struct ns_dns_reply reply;
  char name[512];
  int i;

  name[511] = 0;
  switch (ev) {
    case NS_DNS_MESSAGE:
      msg = (struct ns_dns_message *) ev_data;
      reply = ns_dns_create_reply(&nc->send_mbuf, msg);

      for (i = 0; i < msg->num_questions; i++) {
        rr = &msg->questions[i];
        if (rr->rtype == NS_DNS_A_RECORD) {
          ns_dns_uncompress_name(msg, &rr->name, name, sizeof(name) - 1);

          if (strcmp(name, "cesanta.com") == 0) {
            ns_dns_reply_record(&reply, rr, NULL, rr->rtype, 3600,
                                nc->user_data, 4);
          } else if (strcmp(name, "www.cesanta.com") == 0) {
            ns_dns_reply_record(&reply, rr, NULL, NS_DNS_CNAME_RECORD, 3600,
                                "cesanta.com", strlen("cesanta.com"));

            ns_dns_reply_record(&reply, rr, "cesanta.com", rr->rtype, 3600,
                                nc->user_data, 4);
          }
        }
      }

      /*
       * We don't set the error flag even if there were no answers
       * maching the NS_DNS_A_RECORD query type.
       * This indicates that we have (syntetic) answers for NS_DNS_A_RECORD.
       * See http://goo.gl/QWvufr for a distinction between NXDOMAIN and NODATA.
       */

      ns_dns_send_reply(nc, &reply);
      break;
  }
}

static int check_record_name(struct ns_dns_message *msg, struct ns_str *n,
                             const char *want) {
  char name[512];
  if (ns_dns_uncompress_name(msg, n, name, sizeof(name)) == 0) {
    return 0;
  }
  return strncmp(name, want, sizeof(name)) == 0;
}

static const char *test_dns_server(void) {
  const char *err;
  struct ns_connection nc;
  struct ns_dns_message msg;
  in_addr_t addr = inet_addr("54.194.65.250");
  int ilen;

  memset(&nc, 0, sizeof(nc));

  nc.handler = dns_server_eh;
  nc.user_data = &addr;
  ns_set_protocol_dns(&nc);

  ns_send_dns_query(&nc, "www.cesanta.com", NS_DNS_A_RECORD);

  nc.recv_mbuf = nc.send_mbuf;
  mbuf_init(&nc.send_mbuf, 0);

  ilen = nc.recv_mbuf.len;
  nc.proto_handler(&nc, NS_RECV, &ilen);
  /* remove message length from tcp buffer before manually checking */
  mbuf_remove(&nc.send_mbuf, 2);

  if ((err = check_www_cesanta_com_reply(nc.send_mbuf.buf, nc.send_mbuf.len)) !=
      NULL) {
    return err;
  }

  mbuf_free(&nc.send_mbuf);

  /* test ns_dns_reply_record */
  ns_send_dns_query(&nc, "cesanta.com", NS_DNS_A_RECORD);

  nc.recv_mbuf = nc.send_mbuf;
  mbuf_init(&nc.send_mbuf, 0);

  ilen = nc.recv_mbuf.len;
  nc.proto_handler(&nc, NS_RECV, &ilen);
  /* remove message length from tcp buffer before manually checking */
  mbuf_remove(&nc.send_mbuf, 2);

  ASSERT(ns_parse_dns(nc.send_mbuf.buf, nc.send_mbuf.len, &msg) != -1);
  ASSERT_EQ(msg.num_answers, 1);
  ASSERT_EQ(msg.answers[0].rtype, NS_DNS_A_RECORD);
  ASSERT(check_record_name(&msg, &msg.answers[0].name, "cesanta.com"));

  mbuf_free(&nc.send_mbuf);
  mbuf_free(&nc.recv_mbuf);

  /* check malformed request error */
  memset(&msg, 0, sizeof(msg));
  ilen = 0;
  nc.proto_handler(&nc, NS_RECV, &ilen);
  /* remove message length from tcp buffer before manually checking */
  mbuf_remove(&nc.send_mbuf, 2);

  ASSERT(ns_parse_dns(nc.send_mbuf.buf, nc.send_mbuf.len, &msg) != -1);
  ASSERT(msg.flags & 1);
  ASSERT_EQ(msg.num_questions, 0);
  ASSERT_EQ(msg.num_answers, 0);

  mbuf_free(&nc.send_mbuf);
  return NULL;
}
#endif /* NS_ENABLE_DNS_SERVER */

static void dns_resolve_cb(struct ns_dns_message *msg, void *data) {
  struct ns_dns_resource_record *rr;
  char cname[256];
  struct in_addr got_addr;
  in_addr_t want_addr = inet_addr("54.194.65.250");

  rr = ns_dns_next_record(msg, NS_DNS_A_RECORD, NULL);
  ns_dns_parse_record_data(msg, rr, &got_addr, sizeof(got_addr));

  rr = ns_dns_next_record(msg, NS_DNS_CNAME_RECORD, NULL);
  ns_dns_parse_record_data(msg, rr, cname, sizeof(cname));

  if (want_addr == got_addr.s_addr && strcmp(cname, "cesanta.com") == 0) {
    *(int *) data = 1;
  }
}

static const char *test_dns_resolve(void) {
  struct ns_mgr mgr;
  int data = 0;
  ns_mgr_init(&mgr, NULL);

  ns_resolve_async(&mgr, "www.cesanta.com", NS_DNS_A_RECORD, dns_resolve_cb,
                   &data);

  poll_until(&mgr, 10000, c_int_eq, &data, (void *) 1);
  ASSERT_EQ(data, 1);

  ns_mgr_free(&mgr);
  return NULL;
}

static void dns_resolve_timeout_cb(struct ns_dns_message *msg, void *data) {
  if (msg == NULL) {
    *(int *) data = 1;
  }
}

extern char ns_dns_server[256];

static const char *test_dns_resolve_timeout(void) {
  struct ns_mgr mgr;
  struct ns_resolve_async_opts opts;
  int data = 0;
  ns_mgr_init(&mgr, NULL);
  memset(&opts, 0, sizeof(opts));

  opts.nameserver_url = "udp://7.7.7.7:53";
  opts.timeout = -1; /* 0 would be the default timeout */
  opts.max_retries = 1;
  ns_resolve_async_opt(&mgr, "www.cesanta.com", NS_DNS_A_RECORD,
                       dns_resolve_timeout_cb, &data, opts);

  poll_until(&mgr, 10000, c_int_eq, &data, (void *) 1);
  ASSERT_EQ(data, 1);

  ns_mgr_free(&mgr);
  return NULL;
}

static const char *test_dns_resolve_hosts(void) {
  union socket_address sa;
  in_addr_t want_addr = inet_addr("127.0.0.1");

  memset(&sa, 0, sizeof(sa));
  ASSERT_EQ(ns_resolve_from_hosts_file("localhost", &sa), 0);
  ASSERT_EQ(sa.sin.sin_addr.s_addr, want_addr);
  ASSERT_EQ(ns_resolve_from_hosts_file("does_not,exist!in_host*file", &sa), -1);

  return NULL;
}

static void ehb_srv(struct ns_connection *nc, int ev, void *p) {
  struct mbuf *io = &nc->recv_mbuf;
  (void) io;
  (void) p;

  if (ev == NS_RECV) {
    if (*(int *) p == 1) (*(int *) nc->mgr->user_data)++;
    mbuf_remove(io, *(int *) p);
  }
}

static const char *test_buffer_limit(void) {
  struct ns_mgr mgr;
  struct ns_connection *clnt, *srv;
  const char *address = "tcp://127.0.0.1:7878";
  int res = 0;

  ns_mgr_init(&mgr, &res);
  ASSERT((srv = ns_bind(&mgr, address, ehb_srv)) != NULL);
  srv->recv_mbuf_limit = 1;
  ASSERT((clnt = ns_connect(&mgr, address, NULL)) != NULL);
  ns_printf(clnt, "abcd");

  poll_until(&mgr, 1000, c_int_eq, &res, (void *) 4);

  /* expect four single byte read events */
  ASSERT_EQ(res, 4);

  ns_mgr_free(&mgr);
  return NULL;
}

static const char *test_http_parse_header(void) {
  static struct ns_str h = NS_STR(
      "xx=1 kl yy, ert=234 kl=123, "
      "uri=\"/?naii=x,y\", ii=\"12\\\"34\" zz='aa bb',tt=2,gf=\"xx d=1234");
  char buf[20];

  ASSERT_EQ(ns_http_parse_header(&h, "ert", buf, sizeof(buf)), 3);
  ASSERT_STREQ(buf, "234");
  ASSERT_EQ(ns_http_parse_header(&h, "ert", buf, 2), 0);
  ASSERT_EQ(ns_http_parse_header(&h, "ert", buf, 3), 0);
  ASSERT_EQ(ns_http_parse_header(&h, "ert", buf, 4), 3);
  ASSERT_EQ(ns_http_parse_header(&h, "gf", buf, sizeof(buf)), 0);
  ASSERT_EQ(ns_http_parse_header(&h, "zz", buf, sizeof(buf)), 5);
  ASSERT_STREQ(buf, "aa bb");
  ASSERT_EQ(ns_http_parse_header(&h, "d", buf, sizeof(buf)), 4);
  ASSERT_STREQ(buf, "1234");
  buf[0] = 'x';
  ASSERT_EQ(ns_http_parse_header(&h, "MMM", buf, sizeof(buf)), 0);
  ASSERT_EQ(buf[0], '\0');
  ASSERT_EQ(ns_http_parse_header(&h, "kl", buf, sizeof(buf)), 3);
  ASSERT_STREQ(buf, "123");
  ASSERT_EQ(ns_http_parse_header(&h, "xx", buf, sizeof(buf)), 1);
  ASSERT_STREQ(buf, "1");
  ASSERT_EQ(ns_http_parse_header(&h, "ii", buf, sizeof(buf)), 5);
  ASSERT_STREQ(buf, "12\"34");
  ASSERT_EQ(ns_http_parse_header(&h, "tt", buf, sizeof(buf)), 1);
  ASSERT_STREQ(buf, "2");
  ASSERT(ns_http_parse_header(&h, "uri", buf, sizeof(buf)) > 0);

  return NULL;
}

#ifdef NS_ENABLE_COAP
struct results {
  int server;
  int client;
};

static void coap_handler_1(struct ns_connection *nc, int ev, void *p) {
  switch (ev) {
    case NS_CONNECT: {
      struct ns_coap_message cm;
      memset(&cm, 0, sizeof(cm));
      cm.msg_id = 1;
      cm.msg_type = NS_COAP_MSG_CON;
      ns_coap_send_message(nc, &cm);
      break;
    }
    case NS_COAP_ACK: {
      struct ns_coap_message *cm = (struct ns_coap_message *) p;
      ((struct results *) (nc->user_data))->client = cm->msg_id + cm->msg_type;
      break;
    }
    case NS_COAP_CON: {
      struct ns_coap_message *cm = (struct ns_coap_message *) p;
      ((struct results *) (nc->user_data))->server = cm->msg_id + cm->msg_type;
      ns_coap_send_ack(nc, cm->msg_id);
      break;
    }
  }
}

static const char *test_coap(void) {
  struct mbuf packet_in, packet_out;
  struct ns_coap_message cm;
  uint32_t res;

  unsigned char coap_packet_1[] = {0x42, 0x01, 0xe9, 0x1b, 0x07, 0x90, 0xb8,
                                   0x73, 0x65, 0x70, 0x61, 0x72, 0x61, 0x74,
                                   0x65, 0x10, 0xd1, 0x23, 0x11};
  unsigned char coap_packet_2[] = {0x60, 0x00, 0xe9, 0x1b};
  unsigned char coap_packet_3[] = {
      0x42, 0x45, 0x57, 0x0f, 0x07, 0x90, 0xff, 0x54, 0x68, 0x69, 0x73, 0x20,
      0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x77, 0x61, 0x73, 0x20,
      0x73, 0x65, 0x6e, 0x74, 0x20, 0x62, 0x79, 0x20, 0x61, 0x20, 0x73, 0x65,
      0x70, 0x61, 0x72, 0x61, 0x74, 0x65, 0x20, 0x72, 0x65, 0x73, 0x70, 0x6f,
      0x6e, 0x73, 0x65, 0x2e, 0x0a, 0x59, 0x6f, 0x75, 0x72, 0x20, 0x63, 0x6c,
      0x69, 0x65, 0x6e, 0x74, 0x20, 0x77, 0x69, 0x6c, 0x6c, 0x20, 0x6e, 0x65,
      0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x61, 0x63, 0x6b, 0x6e, 0x6f, 0x77,
      0x6c, 0x65, 0x64, 0x67, 0x65, 0x20, 0x69, 0x74, 0x2c, 0x20, 0x6f, 0x74,
      0x68, 0x65, 0x72, 0x77, 0x69, 0x73, 0x65, 0x20, 0x69, 0x74, 0x20, 0x77,
      0x69, 0x6c, 0x6c, 0x20, 0x62, 0x65, 0x20, 0x72, 0x65, 0x74, 0x72, 0x61,
      0x6e, 0x73, 0x6d, 0x69, 0x74, 0x74, 0x65, 0x64, 0x2e};
  unsigned char coap_packet_4[] = {0x60, 0x00, 0x57, 0x0f};
  unsigned char coap_packet_5[] = {
      0x40, 0x03, 0x95, 0x22, 0xb7, 0x73, 0x74, 0x6f, 0x72, 0x61,
      0x67, 0x65, 0x0a, 0x6d, 0x79, 0x72, 0x65, 0x73, 0x6f, 0x75,
      0x72, 0x63, 0x65, 0xff, 0x6d, 0x79, 0x64, 0x61, 0x74, 0x61};
  unsigned char coap_packet_6[] = {0xFF, 0x00, 0xFF, 0x00};
  unsigned char coap_packet_7[] = {
      0x40, 0x03, 0x95, 0x22, 0xb7, 0x73, 0x74, 0x6f, 0x72, 0x61,
      0x67, 0x65, 0x0a, 0x6d, 0x79, 0x72, 0x65, 0x73, 0x6f, 0x75,
      0x72, 0x63, 0x65, 0xf1, 0x6d, 0x79, 0x64, 0x61, 0x74, 0x61};

  mbuf_init(&packet_in, 0);
  /* empty buf */
  res = ns_coap_parse(&packet_in, &cm);
  ASSERT((res & NS_COAP_NOT_ENOUGH_DATA) != 0);
  ns_coap_free_options(&cm);
  mbuf_free(&packet_in);

  mbuf_init(&packet_out, 0);
  /* ACK, MID: 59675, Empty Message */
  packet_in.buf = (char *) coap_packet_2;
  packet_in.len = sizeof(coap_packet_2);
  res = ns_coap_parse(&packet_in, &cm);
  ASSERT_EQ((res & NS_COAP_ERROR), 0);
  ASSERT_EQ(cm.code_class, 0);
  ASSERT_EQ(cm.code_detail, 0);
  ASSERT_EQ(cm.msg_id, 59675);
  ASSERT_EQ(cm.msg_type, NS_COAP_MSG_ACK);
  ASSERT(cm.options == NULL);
  ASSERT_EQ(cm.payload.len, 0);
  ASSERT(cm.payload.p == NULL);
  ASSERT_EQ(cm.token.len, 0);
  ASSERT(cm.token.p == NULL);
  res = ns_coap_compose(&cm, &packet_out);
  ASSERT_EQ(res, 0);
  ASSERT_EQ(packet_out.len, sizeof(coap_packet_2));
  ASSERT_EQ(memcmp(packet_out.buf, coap_packet_2, packet_out.len), 0);
  ns_coap_free_options(&cm);
  mbuf_free(&packet_out);

  /* ACK, MID: 22287, Empty Message */
  packet_in.buf = (char *) coap_packet_4;
  packet_in.len = sizeof(coap_packet_4);
  res = ns_coap_parse(&packet_in, &cm);
  ASSERT_EQ((res & NS_COAP_ERROR), 0);
  ASSERT_EQ(cm.code_class, 0);
  ASSERT_EQ(cm.code_detail, 0);
  ASSERT_EQ(cm.msg_id, 22287);
  ASSERT_EQ(cm.msg_type, NS_COAP_MSG_ACK);
  ASSERT(cm.options == NULL);
  ASSERT_EQ(cm.payload.len, 0);
  ASSERT(cm.payload.p == NULL);
  ASSERT_EQ(cm.token.len, 0);
  ASSERT(cm.token.p == NULL);
  res = ns_coap_compose(&cm, &packet_out);
  ASSERT_EQ(res, 0);
  ASSERT_EQ(packet_out.len, sizeof(coap_packet_4));
  ASSERT_EQ(memcmp(packet_out.buf, coap_packet_4, packet_out.len), 0);
  ns_coap_free_options(&cm);
  mbuf_free(&packet_out);

  /* CON, MID: 59675 ... */
  packet_in.buf = (char *) coap_packet_1;
  packet_in.len = sizeof(coap_packet_1);
  res = ns_coap_parse(&packet_in, &cm);
  ASSERT_EQ((res & NS_COAP_ERROR), 0);
  ASSERT_EQ(cm.code_class, 0);
  ASSERT_EQ(cm.code_detail, 1);
  ASSERT_EQ(cm.msg_id, 59675);
  ASSERT_EQ(cm.msg_type, NS_COAP_MSG_CON);
  ASSERT(cm.options != 0);
  ASSERT_EQ(cm.options->number, 11);
  ASSERT_EQ(cm.options->value.len, 8);
  ASSERT_STREQ_NZ(cm.options->value.p, "separate");
  ASSERT(cm.options->next != 0);
  ASSERT_EQ(cm.options->next->number, 12);
  ASSERT_EQ(cm.options->next->value.len, 0);
  ASSERT(cm.options->next->next != 0);
  ASSERT_EQ(cm.options->next->next->number, 60);
  ASSERT_EQ(cm.options->next->next->value.len, 1);
  ASSERT_EQ(*cm.options->next->next->value.p, 0x11);
  ASSERT(cm.options->next->next->next == NULL);
  ASSERT_EQ(cm.payload.len, 0);
  ASSERT(cm.payload.p == NULL);
  ASSERT_EQ(cm.token.len, 2);
  ASSERT_EQ(*cm.token.p, 0x07);
  ASSERT_EQ((unsigned char) *(cm.token.p + 1), 0x90);
  res = ns_coap_compose(&cm, &packet_out);
  ASSERT_EQ(res, 0);
  ASSERT_EQ(packet_out.len, sizeof(coap_packet_1));
  ASSERT_EQ(memcmp(packet_out.buf, coap_packet_1, packet_out.len), 0);
  ns_coap_free_options(&cm);
  mbuf_free(&packet_out);

  /* CON, MID: 22287 ... */
  packet_in.buf = (char *) coap_packet_3;
  packet_in.len = sizeof(coap_packet_3);
  res = ns_coap_parse(&packet_in, &cm);
  ASSERT_EQ((res & NS_COAP_ERROR), 0);
  ASSERT_EQ(cm.code_class, 2);
  ASSERT_EQ(cm.code_detail, 5);
  ASSERT_EQ(cm.msg_id, 22287);
  ASSERT_EQ(cm.msg_type, NS_COAP_MSG_CON);
  ASSERT(cm.options == NULL);
  ASSERT_EQ(cm.token.len, 2);
  ASSERT_EQ(*cm.token.p, 0x07);
  ASSERT_EQ((unsigned char) *(cm.token.p + 1), 0x90);
  ASSERT_EQ(cm.payload.len, 122);
  ASSERT(strncmp(cm.payload.p,
                 "This message was sent by a separate response.\n"
                 "Your client will need to acknowledge it,"
                 " otherwise it will be retransmitted.",
                 122) == 0);
  res = ns_coap_compose(&cm, &packet_out);
  ASSERT_EQ(res, 0);
  ASSERT_EQ(packet_out.len, sizeof(coap_packet_3));
  ASSERT_EQ(memcmp(packet_out.buf, coap_packet_3, packet_out.len), 0);
  ns_coap_free_options(&cm);
  mbuf_free(&packet_out);

  packet_in.buf = (char *) coap_packet_5;
  packet_in.len = sizeof(coap_packet_5);
  res = ns_coap_parse(&packet_in, &cm);
  ASSERT_EQ((res & NS_COAP_ERROR), 0);
  ASSERT_EQ(cm.code_class, 0);
  ASSERT_EQ(cm.code_detail, 3);
  ASSERT_EQ(cm.msg_id, 38178);
  ASSERT_EQ(cm.msg_type, NS_COAP_MSG_CON);
  ASSERT(cm.options != 0);
  ASSERT_EQ(cm.options->number, 11);
  ASSERT_EQ(cm.options->value.len, 7);
  ASSERT_STREQ_NZ(cm.options->value.p, "storage");
  ASSERT(cm.options->next != 0);
  ASSERT_EQ(cm.options->next->number, 11);
  ASSERT_EQ(cm.options->next->value.len, 10);
  ASSERT_STREQ_NZ(cm.options->next->value.p, "myresource");
  ASSERT(cm.options->next->next == NULL);
  ASSERT_EQ(cm.token.len, 0);
  ASSERT_EQ(cm.payload.len, 6);
  ASSERT_STREQ_NZ(cm.payload.p, "mydata");
  res = ns_coap_compose(&cm, &packet_out);
  ASSERT_EQ(res, 0);
  ASSERT_EQ(packet_out.len, sizeof(coap_packet_5));
  ASSERT_EQ(memcmp(packet_out.buf, coap_packet_5, packet_out.len), 0);
  ns_coap_free_options(&cm);
  mbuf_free(&packet_out);

  packet_in.buf = (char *) coap_packet_6;
  packet_in.len = sizeof(coap_packet_6);
  res = ns_coap_parse(&packet_in, &cm);
  ASSERT((res & NS_COAP_ERROR) != 0);
  ns_coap_free_options(&cm);

  packet_in.buf = (char *) coap_packet_7;
  packet_in.len = sizeof(coap_packet_7);
  res = ns_coap_parse(&packet_in, &cm);
  ASSERT((res & NS_COAP_ERROR) != 0);
  ns_coap_free_options(&cm);

  {
    unsigned char coap_packet_2_broken[] = {0x6F, 0x00, 0xe9, 0x1b};
    packet_in.buf = (char *) coap_packet_2_broken;
    packet_in.len = sizeof(coap_packet_2_broken);
    res = ns_coap_parse(&packet_in, &cm);
    ASSERT((res & NS_COAP_FORMAT_ERROR) != 0);
  }

  {
    unsigned char coap_packet_2_broken[] = {0x65, 0x00, 0xe9, 0x1b};
    packet_in.buf = (char *) coap_packet_2_broken;
    packet_in.len = sizeof(coap_packet_2_broken);
    res = ns_coap_parse(&packet_in, &cm);
    ASSERT((res & NS_COAP_NOT_ENOUGH_DATA) != 0);
  }

  memset(&cm, 0, sizeof(cm));
  ns_coap_add_option(&cm, 10, 0, 0);
  ASSERT_EQ(cm.options->number, 10);
  ASSERT(cm.options->next == NULL);
  ns_coap_add_option(&cm, 5, 0, 0);
  ASSERT_EQ(cm.options->number, 5);
  ASSERT_EQ(cm.options->next->number, 10);
  ASSERT(cm.options->next->next == NULL);
  ns_coap_add_option(&cm, 7, 0, 0);
  ASSERT_EQ(cm.options->number, 5);
  ASSERT_EQ(cm.options->next->number, 7);
  ASSERT_EQ(cm.options->next->next->number, 10);
  ASSERT(cm.options->next->next->next == NULL);
  ns_coap_add_option(&cm, 1, 0, 0);
  ASSERT_EQ(cm.options->number, 1);
  ASSERT_EQ(cm.options->next->number, 5);
  ASSERT_EQ(cm.options->next->next->number, 7);
  ASSERT_EQ(cm.options->next->next->next->number, 10);
  ASSERT(cm.options->next->next->next->next == NULL);

  {
    unsigned char value16[] = {0xCC, 0xDD};
    packet_in.buf = (char *) coap_packet_4;
    packet_in.len = sizeof(coap_packet_4);
    res = ns_coap_parse(&packet_in, &cm);
    ASSERT_EQ((res & NS_COAP_ERROR), 0);
    ns_coap_add_option(&cm, 0xAABB, (char *) value16, sizeof(value16));
    res = ns_coap_compose(&cm, &packet_out);
    ns_coap_free_options(&cm);
    ASSERT_EQ(res, 0);
    res = ns_coap_parse(&packet_out, &cm);
    ASSERT_EQ((res & NS_COAP_ERROR), 0);
    ASSERT_EQ(cm.options->number, 0xAABB);
    ASSERT_EQ(cm.options->value.len, 2);
    ASSERT_EQ(memcmp(cm.options->value.p, value16, cm.options->value.len), 0);
    ns_coap_free_options(&cm);
    mbuf_free(&packet_out);
  }

  memset(&cm, 0, sizeof(cm));
  cm.msg_id = 1;
  cm.msg_type = NS_COAP_MSG_MAX + 1;
  res = ns_coap_compose(&cm, &packet_out);
  ASSERT((res & NS_COAP_ERROR) != 0 && (res & NS_COAP_MSG_TYPE_FIELD) != 0);

  cm.msg_type = NS_COAP_MSG_ACK;
  cm.token.len = 10000;
  res = ns_coap_compose(&cm, &packet_out);
  ASSERT((res & NS_COAP_ERROR) != 0 && (res & NS_COAP_TOKEN_FIELD) != 0);

  cm.token.len = 0;
  cm.code_class = 0xFF;
  res = ns_coap_compose(&cm, &packet_out);
  ASSERT((res & NS_COAP_ERROR) != 0 && (res & NS_COAP_CODE_CLASS_FIELD) != 0);

  cm.code_class = 0;
  cm.code_detail = 0xFF;
  res = ns_coap_compose(&cm, &packet_out);
  ASSERT((res & NS_COAP_ERROR) != 0 && (res & NS_COAP_CODE_DETAIL_FIELD) != 0);

  cm.code_detail = 0;
  ns_coap_add_option(&cm, 0xFFFFFFF, 0, 0);
  res = ns_coap_compose(&cm, &packet_out);
  ASSERT((res & NS_COAP_ERROR) != 0 && (res & NS_COAP_OPTIONS_FIELD) != 0);
  ns_coap_free_options(&cm);

  {
    struct ns_mgr mgr;
    struct ns_connection *nc;
    const char *address = "tcp://127.0.0.1:8686";

    ns_mgr_init(&mgr, 0);

    nc = ns_bind(&mgr, address, coap_handler_1);
    ASSERT(nc != NULL);
    ASSERT_EQ(ns_set_protocol_coap(nc), -1);

    ns_mgr_free(&mgr);
  }

  {
    struct results res;
    struct ns_mgr mgr;
    struct ns_connection *nc1, *nc2;
    const char *address = "udp://127.0.0.1:5683";

    ns_mgr_init(&mgr, 0);

    nc1 = ns_bind(&mgr, address, coap_handler_1);
    ns_set_protocol_coap(nc1);
    nc1->user_data = &res;

    nc2 = ns_connect(&mgr, address, coap_handler_1);
    ns_set_protocol_coap(nc2);
    nc2->user_data = &res;

    poll_until(&mgr, 10000, c_int_eq, &res.client, (void *) 3);

    ns_mgr_free(&mgr);

    ASSERT_EQ(res.server, 1);
    ASSERT_EQ(res.client, 3);
  }

  return NULL;
}
#endif

static const char *test_strcmp(void) {
  struct ns_str s1;

  s1.p = "aa";
  s1.len = strlen(s1.p);
  ASSERT_EQ(ns_vcasecmp(&s1, "aa"), 0);
  ASSERT_EQ(ns_vcmp(&s1, "aa"), 0);
  ASSERT(ns_vcasecmp(&s1, "ab") < 0);
  ASSERT(ns_vcmp(&s1, "ab") < 0);
  ASSERT(ns_vcasecmp(&s1, "abb") < 0);
  ASSERT(ns_vcmp(&s1, "abb") < 0);
  ASSERT(ns_vcasecmp(&s1, "b") < 0);
  ASSERT(ns_vcmp(&s1, "b") < 0);
  return NULL;
}

static const char *run_tests(const char *filter, double *total_elapsed) {
  RUN_TEST(test_mbuf);
  RUN_TEST(test_parse_address);
  RUN_TEST(test_check_ip_acl);
  RUN_TEST(test_connect_opts);
  RUN_TEST(test_connect_opts_error_string);
  RUN_TEST(test_to64);
  RUN_TEST(test_alloc_vprintf);
  RUN_TEST(test_socketpair);
#ifdef NS_ENABLE_THREADS
  RUN_TEST(test_thread);
#endif
  RUN_TEST(test_mgr);
  RUN_TEST(test_parse_http_message);
  RUN_TEST(test_get_http_var);
  RUN_TEST(test_http);
  RUN_TEST(test_http_errors);
  RUN_TEST(test_http_index);
  RUN_TEST(test_http_parse_header);
  RUN_TEST(test_ssi);
  RUN_TEST(test_cgi);
  RUN_TEST(test_http_rewrites);
  RUN_TEST(test_http_dav);
  RUN_TEST(test_http_range);
  RUN_TEST(test_websocket);
  RUN_TEST(test_websocket_big);
  RUN_TEST(test_rpc);
  RUN_TEST(test_http_chunk);
  RUN_TEST(test_mqtt_handshake);
  RUN_TEST(test_mqtt_publish);
  RUN_TEST(test_mqtt_subscribe);
  RUN_TEST(test_mqtt_unsubscribe);
  RUN_TEST(test_mqtt_connack);
  RUN_TEST(test_mqtt_suback);
  RUN_TEST(test_mqtt_simple_acks);
  RUN_TEST(test_mqtt_nullary);
  RUN_TEST(test_mqtt_parse_mqtt);
#ifdef NS_ENABLE_MQTT_BROKER
  RUN_TEST(test_mqtt_broker);
#endif
  RUN_TEST(test_dns_encode);
  RUN_TEST(test_dns_uncompress);
  RUN_TEST(test_dns_decode);
  RUN_TEST(test_dns_decode_truncated);
  RUN_TEST(test_dns_reply_encode);
#ifdef NS_ENABLE_DNS_SERVER
  RUN_TEST(test_dns_server);
#endif
  RUN_TEST(test_dns_resolve);
  RUN_TEST(test_dns_resolve_timeout);
  RUN_TEST(test_dns_resolve_hosts);
  RUN_TEST(test_buffer_limit);
  RUN_TEST(test_connection_errors);
  RUN_TEST(test_connect_fail);
#ifndef NO_DNS_TEST
  RUN_TEST(test_resolve);
#endif
  RUN_TEST(test_base64);
  RUN_TEST(test_sock_addr_to_str);
  RUN_TEST(test_hexdump);
  RUN_TEST(test_hexdump_file);
#ifdef NS_ENABLE_SSL
  RUN_TEST(test_ssl);
#endif
  RUN_TEST(test_udp);
#ifdef NS_ENABLE_COAP
  RUN_TEST(test_coap);
#endif
  RUN_TEST(test_strcmp);
  return NULL;
}

int __cdecl main(int argc, char *argv[]) {
  const char *fail_msg;
  const char *filter = argc > 1 ? argv[1] : "";
  double total_elapsed = 0.0;

  s_argv_0 = argv[0];
  fail_msg = run_tests(filter, &total_elapsed);
  printf("%s, run %d in %.3lfs\n", fail_msg ? "FAIL" : "PASS", num_tests,
         total_elapsed);
  return fail_msg == NULL ? EXIT_SUCCESS : EXIT_FAILURE;
}
