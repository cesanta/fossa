#include "net_skeleton.h"

static void *stdin_thread(void *param) {
  int ch, sock = * (int *) param;
  while ((ch = getchar()) != EOF) {
    unsigned char c = (unsigned char) ch;
    send(sock, &c, 1, 0);  // Forward all types characters to the socketpair
  }
  return NULL;
}

static void broadcast(struct ns_connection *conn, enum ns_event ev, void *p) {
  if (ev == NS_POLL) {
    struct iobuf *io = (struct iobuf *) p;
    ns_send(conn, io->buf, io->len);
  }
}

static void server_handler(struct ns_connection *conn, enum ns_event ev,
                           void *p) {
  (void) p;
  if (ev == NS_RECV) {
    // Broadcast received message to all connections
    struct iobuf *io = &conn->recv_iobuf;
    ns_iterate(conn->server, broadcast, io);
    iobuf_remove(io, io->len);
  }
}

static void client_handler(struct ns_connection *conn, enum ns_event ev,
                           void *p) {
  struct iobuf *io = &conn->recv_iobuf;
  (void) p;

  if (ev == NS_CONNECT) {
    if (conn->flags & NSF_CLOSE_IMMEDIATELY) {
      printf("%s\n", "Error connecting to server!");
      exit(EXIT_FAILURE);
    }
    printf("%s\n", "Connected to server. Type a message and press enter.");
  } else if (ev == NS_RECV) {
    if (conn->flags & NSF_USER_1) {
      // Received data from the stdin, forward it to the server
      struct ns_connection *c = (struct ns_connection *) conn->connection_data;
      ns_send(c, io->buf, io->len);
      iobuf_remove(io, io->len);
    } else {
      // Received data from server connection, print it
      fwrite(io->buf, io->len, 1, stdout);
      iobuf_remove(io, io->len);
    }
  } else if (ev == NS_CLOSE) {
    // Connection has closed, most probably cause server has stopped
    exit(EXIT_SUCCESS);
  }
}

int main(int argc, char *argv[]) {
  struct ns_server server;

  if (argc != 3) {
    fprintf(stderr, "Usage: %s <port> <client|server>\n", argv[0]);
    exit(EXIT_FAILURE);
  } else if (strcmp(argv[2], "client") == 0) {
    int fds[2];
    struct ns_connection *ioconn, *server_conn;

    ns_server_init(&server, NULL, client_handler);

    // Connect to the pubsub server
    server_conn = ns_connect(&server, "127.0.0.1", atoi(argv[1]), 0, NULL);
    if (server_conn == NULL) {
      fprintf(stderr, "Cannot connect to port %s\n", argv[1]);
      exit(EXIT_FAILURE);
    }

    // Create a socketpair and give one end to the thread that reads stdin
    ns_socketpair(fds);
    ns_start_thread(stdin_thread, &fds[1]);

    // The other end of a pair goes inside the server
    ioconn = ns_add_sock(&server, fds[0], NULL);
    ioconn->flags |= NSF_USER_1;    // Mark this so we know this is a stdin
    ioconn->connection_data = server_conn;

  } else {
    // Server code path
    ns_server_init(&server, NULL, server_handler);
    ns_bind(&server, argv[1]);
    printf("Starting pubsub server on port %s\n", argv[1]);
  }

  for (;;) {
    ns_server_poll(&server, 1000);
  }
  ns_server_free(&server);

  return EXIT_SUCCESS;
}
