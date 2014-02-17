// Unit test for the mongoose web server.
// g++ -W -Wall -pedantic -g unit_test.c -lssl && ./a.out
// cl unit_test.c /MD

#ifndef _WIN32
#define NS_ENABLE_IPV6
#define NS_ENABLE_SSL
#endif

#define NS_ENABLE_HEXDUMP "**"
#define NS_ENABLE_DEBUG

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

static void ev_handler(struct ns_connection *conn, enum ns_event ev) {
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
  char buf[100] = "";
  struct ns_server server;
  int port;
  ns_server_init(&server, (void *) "foo", ev_handler);

  port = ns_bind_to(&server,  LOOPBACK_IP ":0", cert);
  ASSERT(port > 0);

  ASSERT(ns_connect(&server, LOOPBACK_IP, port, cert != NULL, buf) != NULL);
  { int i; for (i = 0; i < 50; i++) ns_server_poll(&server, 0); }

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

static const char *run_all_tests(void) {
  RUN_TEST(test_iobuf);
  RUN_TEST(test_server);
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
