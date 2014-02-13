#include "tcp_skeleton.h"

static void *stdin_thread(void *param) {
  int ch, sock = * (int *) param;
  while ((ch = getchar()) != EOF) {
    unsigned char c = (unsigned char) ch;
    send(sock, &c, 1, 0);  // Forward all types characters to the socketpair
  }
  return NULL;
}

static void broadcast(struct ts_connection *conn, enum ts_event ev) {
  if (ev == TS_POLL) {
    struct iobuf *io = (struct iobuf *) conn->callback_param;
    ts_send(conn, io->buf, io->len);
  }
}

static void server_handler(struct ts_connection *conn, enum ts_event ev) {
  if (ev == TS_RECV) {
    // Broadcast received message to all connections
    struct iobuf *io = &conn->recv_iobuf;
    ts_iterate(conn->server, broadcast, io);
    iobuf_remove(io, io->len);
  }
}

static void client_handler(struct ts_connection *conn, enum ts_event ev) {
  struct iobuf *io = &conn->recv_iobuf;
  if (ev == TS_CONNECT) {
    if (conn->flags & TSF_CLOSE_IMMEDIATELY) {
      printf("%s\n", "Error connecting to server!");
      exit(EXIT_FAILURE);
    }
    printf("%s\n", "Connected to server. Type a message and press enter.");
  } else if (ev == TS_RECV) {
    if (conn->flags & TSF_USER_1) {
      // Received data from the stdin, forward it to the server
      struct ts_connection *c = (struct ts_connection *) conn->connection_data;
      ts_send(c, io->buf, io->len);
      iobuf_remove(io, io->len);
    } else {
      // Received data from server connection, print it
      fwrite(io->buf, io->len, 1, stdout);
      iobuf_remove(io, io->len);
    }
  }
}

int main(int argc, char *argv[]) {
  struct ts_server server;

  if (argc != 3) {
    fprintf(stderr, "Usage: %s <port> <client|server>\n", argv[0]);
    exit(EXIT_FAILURE);
  } else if (strcmp(argv[2], "client") == 0) {
    int fds[2];
    struct ts_connection *ioconn, *server_conn;

    ts_server_init(&server, NULL, client_handler);

    // Connect to the pubsub server
    server_conn = ts_connect(&server, "127.0.0.1", atoi(argv[1]), 0, NULL);
    if (server_conn == NULL) {
      fprintf(stderr, "Cannot connect to port %s\n", argv[1]);
      exit(EXIT_FAILURE);
    }

    // Create a socketpair and give one end to the thread that reads stdin
    ts_socketpair(fds);
    ts_start_thread(stdin_thread, &fds[1]);

    // The other end of a pair goes inside the server
    ioconn = ts_add_sock(&server, fds[0], NULL);
    ioconn->flags |= TSF_USER_1;    // Mark this so we know this is a stdin
    ioconn->connection_data = server_conn;

  } else {
    // Server code path
    ts_server_init(&server, NULL, server_handler);
    ts_bind_to(&server, argv[1], NULL);
    printf("Starting pubsub server on port %s\n", argv[1]);
  }

  for (;;) {
    ts_server_poll(&server, 1000);
  }
  ts_server_free(&server);

  return EXIT_SUCCESS;
}
