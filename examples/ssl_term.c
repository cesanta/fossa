// Copyright (c) 2014 by Cesanta Software
// This application implements SSL termination proxy.
// It listens for SSL connections, accepts them, and forwards all
// data to the other, non-SSL server, working as an SSL wrapper for any
// TCP server (Web, Mail, et cetera).

#include "net_skeleton.h"

static const char *s_listening_port = "8043";   // Listening SSL port
//static const char *s_target_host = "127.0.0.1";
//static const char *s_target_port = "8080";
static const char *s_target_host = "google.com";  // Target server IP
static const char *s_target_port = "80";    // Target server port
static const char *s_ssl_certificate = "ssl_cert.pem";

static void ev_handler(struct ns_connection *nc, enum ns_event ev, void *p) {
  struct ns_connection *pc = (struct ns_connection *) nc->connection_data;
  struct iobuf *io = &nc->recv_iobuf;

  switch (ev) {
    case NS_ACCEPT:
      // New SSL connection. Create a connection to the target, and link them
      nc->connection_data = ns_connect(nc->server, s_target_host,
                                       atoi(s_target_port), 0, nc);
      if (nc->connection_data == NULL) {
        nc->flags |= NSF_CLOSE_IMMEDIATELY;
      }
      break;
    case NS_CONNECT:
      // Connection to the target finished. If failed, close both
      if (* (int *) p != 0 && pc != NULL) {
        pc->flags |= NSF_CLOSE_IMMEDIATELY;
      }
      break;
    case NS_CLOSE:
      // If either connection closes, unlink them and shedule closing
      if (pc != NULL) {
        pc->flags |= NSF_FINISHED_SENDING_DATA;
        pc->connection_data = NULL;
      }
      nc->connection_data = NULL;
      break;
    case NS_RECV:
      // Forward arrived data to the other connection, and discard from buffer
      ns_send(pc, io->buf, io->len);
      iobuf_remove(io, io->len);
    default:
      break;
  }
}

int main(void) {
  struct ns_server server;

  ns_server_init(&server, NULL, ev_handler);
  if (ns_bind(&server, s_listening_port) < 0) {
    fprintf(stderr, "Error binding to %s\n", s_listening_port);
    exit(EXIT_FAILURE);
  } else if (ns_set_ssl_cert(&server, s_ssl_certificate) != 0) {
    fprintf(stderr, "SSL certificate error\n");
    exit(EXIT_FAILURE);
  }

  printf("Forwarding SSL port %s to %s:%s\n", s_listening_port,
         s_target_host, s_target_port);
  for (;;) {
    ns_server_poll(&server, 1000);
  }
  ns_server_free(&server);

  return EXIT_SUCCESS;
}
