// Unit test for the mongoose web server.
// g++ -W -Wall -pedantic -g unit_test.c -lssl && ./a.out
// cl unit_test.c /MD

#ifndef _WIN32
#define TS_ENABLE_IPV6
#define TS_ENABLE_SSL
#endif

#define TS_ENABLE_HEXDUMP "**"
#define TS_ENABLE_DEBUG

#include "tcp_skeleton.c"

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

static int ev_handler(struct ts_connection *conn, enum ts_event ev, void *p) {
  if (ev == TS_POLL) return 0;
  printf("ev_handler           %p, ev %d, data %p\n", conn, (int) ev, p);
  switch (ev) {
    case TS_CONNECT:
      ts_send(conn, "foo", 3);
      break;
    case TS_RECV:
      if (conn->flags & TSF_ACCEPTED) {
        struct iobuf *io = &conn->recv_iobuf;
        ts_send(conn, io->buf, io->len); // Echo message back
        iobuf_remove(io, io->len);
      } else {
        struct iobuf *io = &conn->recv_iobuf;
        if (io->len == 3 && memcmp(io->buf, "foo", 3) == 0) {
          sprintf((char *) conn->connection_data, "%s", "ok!");
          conn->flags |= TSF_CLOSE_IMMEDIATELY;
        }
      }
      break;
    default:
      break;
  }
  return 0;
}

static const char *test_server(void) {
  char buf[100];
  struct ts_server server;
  int port;
  ts_server_init(&server, (void *) "foo", ev_handler);

  port = ts_bind_to(&server,  LOOPBACK_IP ":0");
  ASSERT(port > 0);

  ASSERT(ts_connect(&server, LOOPBACK_IP, port, 0, buf) > 0);
  { int i; for (i = 0; i < 50; i++) ts_server_poll(&server, 0); }

  ts_server_free(&server);
  return NULL;
}

static const char *run_all_tests(void) {
  RUN_TEST(test_iobuf);
  RUN_TEST(test_server);
#ifdef TS_ENABLE_SSL
  //RUN_TEST(test_ssl);
#endif
  return NULL;
}

int __cdecl main(void) {
  const char *fail_msg = run_all_tests();
  printf("%s, tests run: %d\n", fail_msg ? "FAIL" : "PASS", static_num_tests);
  return fail_msg == NULL ? EXIT_SUCCESS : EXIT_FAILURE;
}
