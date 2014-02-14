#include "net_skeleton.h"

static void event_handler(struct ts_connection *conn, enum ts_event ev) {
  struct iobuf *io = &conn->recv_iobuf;

  switch (ev) {
    case TS_RECV:
      ts_send(conn, io->buf, io->len);  // Echo message back
      iobuf_remove(io, io->len);        // Discard message from recv buffer
    default:
      break;
  }
}

int main(void) {
  struct ts_server server;
  const char *port = "1234";

  ts_server_init(&server, NULL, event_handler);
  ts_bind_to(&server, port, NULL);

  printf("Starting echo server on port %s\n", port);
  for (;;) {
    ts_server_poll(&server, 1000);
  }
  ts_server_free(&server);

  return 0;
}
