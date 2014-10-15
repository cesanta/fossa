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

// Net Skeleton unit test
// g++ -W -Wall -pedantic -g unit_test.c -lssl && ./a.out
// cl unit_test.c /MD

#ifndef _WIN32
#define NS_ENABLE_IPV6
#ifndef NS_ENABLE_SSL
#define NS_ENABLE_SSL
#endif
#endif

//#define NS_ENABLE_DEBUG
#include "../net_skeleton.c"

#define FAIL(str, line) do {                    \
  printf("%s:%d:1 [%s]\n", __FILE__, line, str); \
  return str;                                   \
} while (0)

#define ASSERT(expr) do {             \
  static_num_tests++;                 \
  if (!(expr)) FAIL(#expr, __LINE__); \
} while (0)

#define RUN_TEST(test) do { const char *msg = test(); \
  if (msg) return msg; } while (0)

#define HTTP_PORT "45772"
#define LOOPBACK_IP  "127.0.0.1"
#define LISTENING_ADDR LOOPBACK_IP ":" HTTP_PORT

static int static_num_tests = 0;
static const char *s_local_addr = "127.0.0.1:7777";

static const char *test_iobuf(void) {
  struct iobuf io;

  iobuf_init(&io, 0);
  ASSERT(io.buf == NULL && io.len == 0 && io.size == 0);
  iobuf_free(&io);
  ASSERT(io.buf == NULL && io.len == 0 && io.size == 0);

  iobuf_init(&io, 10);
  ASSERT(io.buf != NULL && io.len == 0 && io.size == 10);
  iobuf_free(&io);
  ASSERT(io.buf == NULL && io.len == 0 && io.size == 0);

  return NULL;
}

static void ev_handler(struct ns_connection *nc, int ev, void *p) {
  (void) p;
  switch (ev) {
    case NS_CONNECT:
      ns_printf(nc, "%d %s there", 17, "hi");
      break;
    case NS_RECV:
      if (nc->listener != NULL) {
        struct iobuf *io = &nc->recv_iobuf;
        ns_send(nc, io->buf, io->len); // Echo message back
        iobuf_remove(io, io->len);
      } else {
        struct iobuf *io = &nc->recv_iobuf;
        if (io->len == 11 && memcmp(io->buf, "17 hi there", 11) == 0) {
          sprintf((char *) nc->user_data, "%s", "ok!");
          nc->flags |= NSF_CLOSE_IMMEDIATELY;
        }
      }
      break;
    default:
      break;
  }
}

#define S_PEM  "server.pem"
#define C_PEM  "client.pem"
#define CA_PEM "ca.pem"

static const char *test_mgr_with_ssl(int use_ssl) {
  char addr[100], ip[sizeof(addr)], buf[100] = "";
  struct ns_mgr mgr;
  struct ns_connection *nc;
  int port, port2;

  ns_mgr_init(&mgr, NULL);
  mgr.hexdump_file = "/dev/stdout";

  if (use_ssl) {
    snprintf(addr, sizeof(addr), "ssl://%s:0:%s:%s", LOOPBACK_IP, S_PEM, CA_PEM);
  } else {
    snprintf(addr, sizeof(addr), "%s:0", LOOPBACK_IP);
  }
  nc = ns_bind(&mgr, addr, ev_handler, NULL);

  ASSERT(nc != NULL);
  port2 = htons(nc->sa.sin.sin_port);
  ASSERT(port2 > 0);

  ns_sock_to_str(nc->sock, addr, sizeof(addr), 3);
  ASSERT(sscanf(addr, "%[^:]:%d", ip, &port) == 2);
  ASSERT(strcmp(ip, "127.0.0.1") == 0);
  ASSERT(port == port2);

  if (use_ssl) {
    snprintf(addr, sizeof(addr), "ssl://%s:%d:%s:%s", LOOPBACK_IP, port,
             C_PEM, CA_PEM);
  } else {
    snprintf(addr, sizeof(addr), "tcp://%s:%d", LOOPBACK_IP, port);
  }

  ASSERT(ns_connect(&mgr, addr, ev_handler, buf) != NULL);
  { int i; for (i = 0; i < 50; i++) ns_mgr_poll(&mgr, 1); }

  ASSERT(strcmp(buf, "ok!") == 0);

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
  ASSERT(to64("0") == 0);
  ASSERT(to64("") == 0);
  ASSERT(to64("123") == 123);
  ASSERT(to64("-34") == -34);
  ASSERT(to64("3566626116") == 3566626116);
  return NULL;
}

static const char *test_parse_address(void) {
  static const char *valid[] = {
    "1", "1.2.3.4:1", "tcp://123", "udp://0.0.0.0:99", "ssl://17",
    "ssl://900:a.pem:b.pem", "ssl://1.2.3.4:9000:aa.pem",
#if defined(NS_ENABLE_IPV6)
    "udp://[::1]:123", "[3ffe:2a00:100:7031::1]:900",
#endif
    NULL
  };
  static const int protos[] = {SOCK_STREAM, SOCK_STREAM, SOCK_STREAM,
    SOCK_DGRAM, SOCK_STREAM, SOCK_STREAM, SOCK_STREAM, SOCK_DGRAM, SOCK_STREAM};
  static const int use_ssls[] = {0, 0, 0, 0, 1, 1, 1, 0, 0};
  static const char *invalid[] = {
    "99999", "1k", "1.2.3", "1.2.3.4:", "1.2.3.4:2p", "blah://12", NULL
  };
  union socket_address sa;
  char cert[100], ca[100];
  int i, proto, use_ssl;

  for (i = 0; valid[i] != NULL; i++) {
    ASSERT(ns_parse_address(valid[i], &sa, &proto, &use_ssl, cert, ca) != 0);
    ASSERT(proto == protos[i]);
    ASSERT(use_ssl == use_ssls[i]);
  }

  for (i = 0; invalid[i] != NULL; i++) {
    ASSERT(ns_parse_address(invalid[i], &sa, &proto, &use_ssl, cert, ca) == 0);
  }
  ASSERT(ns_parse_address("0", &sa, &proto, &use_ssl, cert, ca) != 0);

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

  ASSERT(avt(&p, sizeof(buf), "%d", 123) == 3);
  ASSERT(p == buf);
  ASSERT(strcmp(p, "123") == 0);

  ASSERT(avt(&p, sizeof(buf), "%d", 123456789) == 9);
  ASSERT(p != buf);
  ASSERT(strcmp(p, "123456789") == 0);
  free(p);

  return NULL;
}

static const char *test_socketpair(void) {
  sock_t sp[2];
  static const char foo[] = "hi there";
  char buf[20];

  ASSERT(ns_socketpair2(sp, SOCK_DGRAM) == 1);
  ASSERT(sizeof(foo) < sizeof(buf));

  // Send string in one direction
  ASSERT(send(sp[0], foo, sizeof(foo), 0) == sizeof(foo));
  ASSERT(recv(sp[1], buf, sizeof(buf), 0) == sizeof(foo));
  ASSERT(strcmp(buf, "hi there") == 0);

  // Now in opposite direction
  ASSERT(send(sp[1], foo, sizeof(foo), 0) == sizeof(foo));
  ASSERT(recv(sp[0], buf, sizeof(buf), 0) == sizeof(foo));
  ASSERT(strcmp(buf, "hi there") == 0);

  closesocket(sp[0]);
  closesocket(sp[1]);

  return NULL;
}

static void eh2(struct ns_connection *nc, int ev, void *p) {
  (void) p;
  switch (ev) {
    case NS_RECV:
      strcpy((char *) nc->user_data, nc->recv_iobuf.buf);
      break;
    default:
      break;
  }
}

static void *thread_func(void *param) {
  sock_t sock = * (sock_t *) param;
  send(sock, ":-)", 4, 0);
  return NULL;
}

static const char *test_thread(void) {
  struct ns_mgr mgr;
  struct ns_connection *nc;
  sock_t sp[2];
  char buf[20];

  ASSERT(ns_socketpair(sp) == 1);
  ns_start_thread(thread_func, &sp[1]);

  ns_mgr_init(&mgr, NULL);
  ASSERT((nc = ns_add_sock(&mgr, sp[0], eh2, buf)) != NULL);
  { int i; for (i = 0; i < 50; i++) ns_mgr_poll(&mgr, 1); }
  ASSERT(strcmp(buf, ":-)") == 0);
  ns_mgr_free(&mgr);

  return NULL;
}

static void eh3(struct ns_connection *nc, int ev, void *p) {
  struct iobuf *io = &nc->recv_iobuf;
  (void) p;

  if (ev == NS_RECV) {
    memcpy((char *) nc->mgr->user_data, io->buf, io->len);
  }
}

static const char *test_udp(void) {
  struct ns_mgr mgr;
  struct ns_connection *nc;
  const char *address = "udp://127.0.0.1:7878";
  char buf[20] = "";

  ns_mgr_init(&mgr, buf);
  ASSERT(ns_bind(&mgr, address, eh3, NULL) != NULL);
  ASSERT((nc = ns_connect(&mgr, address, eh3, NULL)) != NULL);
  ns_printf(nc, "%s", "boo!");

  { int i; for (i = 0; i < 50; i++) ns_mgr_poll(&mgr, 1); }
  ASSERT(memcmp(buf, "boo!", 4) == 0);
  ns_mgr_free(&mgr);

  return NULL;
}

static void poll_mgr(struct ns_mgr *mgr, int num_iterations) {
  while (num_iterations-- > 0) {
    ns_mgr_poll(mgr, 1);
  }
}

static const char *test_parse_http_message(void) {
  static const char *a = "GET / HTTP/1.0\n\n";
  static const char *b = "GET /blah HTTP/1.0\r\nFoo:  bar  \r\n\r\n";
  static const char *c = "get b c\nz:  k \nb: t\nvvv\n\n xx";
  static const char *d = "a b c\nContent-Length: 21 \nb: t\nvvv\n\n";
  struct ns_str *v;
  struct http_message req;

  ASSERT(parse_http("\b23", 3, &req) == -1);
  ASSERT(parse_http("get\n\n", 5, &req) == -1);
  ASSERT(parse_http(a, strlen(a) - 1, &req) == 0);
  ASSERT(parse_http(a, strlen(a), &req) == (int) strlen(a));

  ASSERT(parse_http(b, strlen(b), &req) == (int) strlen(b));
  ASSERT(req.header_names[0].len == 3);
  ASSERT(req.header_values[0].len == 3);
  ASSERT(req.header_names[1].p == NULL);

  ASSERT(parse_http(c, strlen(c), &req) == (int) strlen(c) - 3);
  ASSERT(req.header_names[2].p == NULL);
  ASSERT(req.header_names[0].p != NULL);
  ASSERT(req.header_names[1].p != NULL);
  ASSERT(memcmp(req.header_values[1].p, "t", 1) == 0);
  ASSERT(req.header_names[1].len == 1);
  ASSERT(req.body.len == 0);

  ASSERT(parse_http(d, strlen(d), &req) == (int) strlen(d));
  ASSERT(req.body.len == 21);
  ASSERT(req.message.len == 21 + strlen(d));
  ASSERT(get_http_header(&req, "foo") == NULL);
  ASSERT((v = get_http_header(&req, "contENT-Length")) != NULL);
  ASSERT(v->len == 2 && memcmp(v->p, "21", 2) == 0);

  return NULL;
}

static void cb1(struct ns_connection *nc, int ev, void *ev_data) {
  struct http_message *hm = (struct http_message *) ev_data;

  if (ev == NS_HTTP_REQUEST) {
    ns_printf(nc, "HTTP/1.0 200 OK\n\n[%.*s %d]",
              (int) hm->uri.len, hm->uri.p, (int) hm->body.len);
    nc->flags |= NSF_FINISHED_SENDING_DATA;
  }
}

static void cb2(struct ns_connection *nc, int ev, void *ev_data) {
  struct http_message *hm = (struct http_message *) ev_data;

  if (ev == NS_HTTP_REPLY) {
    memcpy(nc->user_data, hm->body.p, hm->body.len);
    nc->flags |= NSF_CLOSE_IMMEDIATELY;
  }
}

static const char *test_http(void) {
  struct ns_mgr mgr;
  struct ns_connection *nc, *nc2;
  char buf[20] = "";

  ns_mgr_init(&mgr, NULL);
  ASSERT(ns_bind_http(&mgr, s_local_addr, cb1, NULL) != NULL);

  // Valid HTTP request. Pass test buffer to the callback.
  ASSERT((nc = ns_connect_http(&mgr, s_local_addr, cb2, buf)) != NULL);
  ns_printf(nc, "%s", "POST /foo HTTP/1.0\nContent-Length: 10\n\n"
            "0123456789");

  // Invalid HTTP request
  ASSERT((nc2 = ns_connect_http(&mgr, s_local_addr, cb2, NULL)) != NULL);
  ns_printf(nc2, "%s", "bl\x03\n\n");
  poll_mgr(&mgr, 50);
  ns_mgr_free(&mgr);

  // Check that test buffer has been filled by the callback properly.
  ASSERT(strcmp(buf, "[/foo 10]") == 0);

  return NULL;
}

static void cb3(struct ns_connection *nc, int ev, void *ev_data) {
  struct websocket_message *wm = (struct websocket_message *) ev_data;

  if (ev == NS_WEBSOCKET_FRAME) {
    const char *reply = wm->size == 2 && !memcmp(wm->data, "hi", 2) ? "A": "B";
    ns_printf_websocket(nc, WEBSOCKET_OP_TEXT, "%s", reply);
  }
}

static void cb4(struct ns_connection *nc, int ev, void *ev_data) {
  struct websocket_message *wm = (struct websocket_message *) ev_data;

  if (ev == NS_WEBSOCKET_FRAME) {
    memcpy(nc->user_data, wm->data, wm->size);
    ns_send_websocket(nc, WEBSOCKET_OP_CLOSE, NULL, 0);
  } else if (ev == NS_WEBSOCKET_HANDSHAKE_DONE) {
    // Send "hi" to server. server must reply "A".
    ns_printf_websocket(nc, WEBSOCKET_OP_TEXT, "%s", "hi");
  }
}

static const char *test_websocket(void) {
  struct ns_mgr mgr;
  struct ns_connection *nc;
  char buf[20] = "";

  ns_mgr_init(&mgr, NULL);
  //mgr.hexdump_file = "/dev/stdout";
  ASSERT(ns_bind_http(&mgr, s_local_addr, cb3, NULL) != NULL);

  // Websocket request
  ASSERT((nc = ns_connect_websocket(&mgr, s_local_addr, cb4, buf,
         "/ws", NULL)) != NULL);
  poll_mgr(&mgr, 50);
  ns_mgr_free(&mgr);

  // Check that test buffer has been filled by the callback properly.
  ASSERT(strcmp(buf, "A") == 0);

  return NULL;
}

// This JSON-RPC handler function calculates sum of numeric parameters
static void rpc_handler_sum(struct ns_connection *nc, struct json_token *id,
                            struct json_token *params) {
  double sum = 0;
  int i;

  if (id == NULL) {
    ns_rpc_reply(nc, "{ s: s, s: N, s: s }",
                 "jsonrpc", "2.0", "id", "error", "id is expected");
    return;
  }

  for (i = 0; i < params->num_desc; i++) {
    if (params[i].type != JSON_TYPE_NUMBER) {
      ns_rpc_reply(nc, "{ s: s, s: N, s: s }",
                   "jsonrpc", "2.0", "id", "error", "List of Numbers expected");
      return;
    }
    sum += strtod(params[i].ptr, NULL);
  }

  ns_rpc_reply(nc, "{ s: s, s: v, s: f }",
               "jsonrpc", "2.0", "id", id->ptr, id->len, "result", sum);
}

static void rpc_server(struct ns_connection *nc, int ev, void *ev_data) {
  struct websocket_message *wm = (struct websocket_message *) ev_data;

  if (ev == NS_WEBSOCKET_FRAME) {
  }
}

static void rpc_client(struct ns_connection *nc, int ev, void *ev_data) {
  struct websocket_message *wm = (struct websocket_message *) ev_data;

  if (ev == NS_WEBSOCKET_FRAME) {
    //handle_rpc_reply(nc, wm->data, wm->size);
  } else if (ev == NS_WEBSOCKET_HANDSHAKE_DONE) {
    //ns_printf_rpc_request(nc, "sum", "[f,f,f]", 1.1, 2.2, 3.3);
  }
}

static const char *test_rpc(void) {
  struct ns_mgr mgr;
  struct ns_connection *nc;
  char buf[100];

  ns_mgr_init(&mgr, NULL);
  ns_bind_http(&mgr, s_local_addr, rpc_server, NULL);
  ns_connect_websocket(&mgr, s_local_addr, rpc_client, buf, "/ws", NULL);
  poll_mgr(&mgr, 50);
  ns_mgr_free(&mgr);

  return NULL;
}

static const char *run_all_tests(void) {
  RUN_TEST(test_iobuf);
  RUN_TEST(test_parse_address);
  RUN_TEST(test_to64);
  RUN_TEST(test_alloc_vprintf);
  RUN_TEST(test_socketpair);
  RUN_TEST(test_thread);
  RUN_TEST(test_mgr);
  RUN_TEST(test_parse_http_message);
  RUN_TEST(test_http);
  RUN_TEST(test_websocket);
  RUN_TEST(test_rpc);
#ifdef NS_ENABLE_SSL
  RUN_TEST(test_ssl);
#endif
  RUN_TEST(test_udp);
  return NULL;
}

int __cdecl main(void) {
  const char *fail_msg = run_all_tests();
  printf("%s, tests run: %d\n", fail_msg ? "FAIL" : "PASS", static_num_tests);
  return fail_msg == NULL ? EXIT_SUCCESS : EXIT_FAILURE;
}
