#include "net_skeleton.h"

static void ev_handler(struct ns_connection *conn, enum ns_event ev, void *p) {
  struct iobuf *io = &conn->recv_iobuf;
  (void) p;

  switch (ev) {
    case NS_RECV:
      ns_send(conn, io->buf, io->len);  // Echo message back
      iobuf_remove(io, io->len);        // Discard message from recv buffer
      break;
    default:
      break;
  }
}

int main(void) {
  struct ns_server server;
  const char *port1 = "1234", *port2 = "127.0.0.1:17000";

  ns_server_init(&server, NULL, ev_handler);
  ns_bind(&server, port1);
  ns_bind(&server, port2);

  printf("Starting echo server on ports %s, %s\n", port1, port2);
  for (;;) {
    ns_server_poll(&server, 1000);
  }
  ns_server_free(&server);

  return 0;
}
