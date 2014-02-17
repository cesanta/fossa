#include "net_skeleton.h"

static void event_handler(struct ns_connection *conn, enum ns_event ev) {
  struct iobuf *io = &conn->recv_iobuf;

  switch (ev) {
    case NS_RECV:
      ns_send(conn, io->buf, io->len);  // Echo message back
      iobuf_remove(io, io->len);        // Discard message from recv buffer
    default:
      break;
  }
}

int main(void) {
  struct ns_server server;
  const char *port = "1234";

  ns_server_init(&server, NULL, event_handler);
  ns_bind_to(&server, port, NULL);

  printf("Starting echo server on port %s\n", port);
  for (;;) {
    ns_server_poll(&server, 1000);
  }
  ns_server_free(&server);

  return 0;
}
