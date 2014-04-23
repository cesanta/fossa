// Unit test for the mongoose web server.
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
  printf("Fail on line %d: [%s]\n", line, str); \
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

static void ev_handler(struct ns_connection *conn, enum ns_event ev, void *p) {
  (void) p;
  switch (ev) {
    case NS_CONNECT:
      ns_printf(conn, "%d %s there", 17, "hi");
      break;
    case NS_RECV:
      if (conn->flags & NSF_ACCEPTED) {
        struct iobuf *io = &conn->recv_iobuf;
        ns_send(conn, io->buf, io->len); // Echo message back
        iobuf_remove(io, io->len);
      } else {
        struct iobuf *io = &conn->recv_iobuf;
        if (io->len == 11 && memcmp(io->buf, "17 hi there", 11) == 0) {
          sprintf((char *) conn->connection_data, "%s", "ok!");
          conn->flags |= NSF_CLOSE_IMMEDIATELY;
        }
      }
      break;
    default:
      break;
  }
}

static const char *test_server_with_ssl(const char *cert) {
  char addr[100], ip[sizeof(addr)], buf[100] = "";
  struct ns_server server;
  int port, port2;
  ns_server_init(&server, (void *) "foo", ev_handler);

  port = ns_bind(&server,  LOOPBACK_IP ":0");
  if (cert != NULL) ns_set_ssl_cert(&server, cert);
  ASSERT(port > 0);
  ns_sock_to_str(server.listening_sock, addr, sizeof(addr), 3);
  ASSERT(sscanf(addr, "%[^:]:%d", ip, &port2) == 2);
  ASSERT(strcmp(ip, "127.0.0.1") == 0);
  ASSERT(port == port2);

  ASSERT(ns_connect(&server, LOOPBACK_IP, port, cert != NULL, buf) != NULL);
  { int i; for (i = 0; i < 50; i++) ns_server_poll(&server, 1); }

  ASSERT(strcmp(buf, "ok!") == 0);

  ns_server_free(&server);
  return NULL;
}

static const char *test_server(void) {
  return test_server_with_ssl(NULL);
}

#ifdef NS_ENABLE_SSL
static const char *test_ssl(void) {
  return test_server_with_ssl("ssl_cert.pem");
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

static const char *test_parse_port_string(void) {
  static const char *valid[] = {
    "1", "1.2.3.4:1",
#if defined(USE_IPV6)
    "[::1]:123", "[3ffe:2a00:100:7031::1]:900",
#endif
    NULL
  };
  static const char *invalid[] = {
    "99999", "1k", "1.2.3", "1.2.3.4:", "1.2.3.4:2p", NULL
  };
  union socket_address sa;
  int i;

  for (i = 0; valid[i] != NULL; i++) {
    ASSERT(ns_parse_port_string(valid[i], &sa) != 0);
  }

  for (i = 0; invalid[i] != NULL; i++) {
    ASSERT(ns_parse_port_string(invalid[i], &sa) == 0);
  }
  ASSERT(ns_parse_port_string("0", &sa) != 0);

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

static const char *run_all_tests(void) {
  RUN_TEST(test_iobuf);
  RUN_TEST(test_server);
  RUN_TEST(test_to64);
  RUN_TEST(test_parse_port_string);
  RUN_TEST(test_alloc_vprintf);
  RUN_TEST(test_socketpair);
#ifdef NS_ENABLE_SSL
  RUN_TEST(test_ssl);
#endif
  return NULL;
}

int __cdecl main(void) {
  const char *fail_msg = run_all_tests();
  printf("%s, tests run: %d\n", fail_msg ? "FAIL" : "PASS", static_num_tests);
  return fail_msg == NULL ? EXIT_SUCCESS : EXIT_FAILURE;
}
