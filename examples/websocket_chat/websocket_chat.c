/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#include "net_skeleton.h"

static int s_signal_received = 0;
static const char *s_http_port = "8000";
static struct ns_serve_http_opts s_http_server_opts = { "." };

static void signal_handler(int sig_num) {
  signal(sig_num, signal_handler);  // Reinstantiate signal handler
  s_signal_received = sig_num;
}

#if 0
static void handle_websocket_message(struct mg_connection *conn) {
  struct conn_data *d = (struct conn_data *) conn->connection_param;
  struct mg_connection *c;

  printf("[%.*s]\n", (int) conn->content_len, conn->content);
  if (conn->content_len > 5 && !memcmp(conn->content, "join ", 5)) {
    // Client joined new room
    d->room = conn->content[5];
  } else if (conn->content_len > 4 && !memcmp(conn->content, "msg ", 4) &&
             d->room != 0 && d->room != '?') {
    // Client has sent a message. Push this message to all clients
    // that are subscribed to the same room as client
    for (c = mg_next(s_server, NULL); c != NULL; c = mg_next(s_server, c)) {
      struct conn_data *d2 = (struct conn_data *) c->connection_param;
      if (!c->is_websocket || d2->room != d->room) continue;
      mg_websocket_printf(c, WEBSOCKET_OPCODE_TEXT, "msg %c %p %.*s",
                          (char) d->room, conn,
                          conn->content_len - 4, conn->content + 4);
    }
  }
}

static int ev_handler(struct mg_connection *conn, enum mg_event ev) {
  switch (ev) {
    case MG_REQUEST:
      if (conn->is_websocket) {
        handle_websocket_message(conn);
        return MG_TRUE;
      } else {
        mg_send_file(conn, "index.html", NULL);  // Return MG_MORE after!
        return MG_MORE;
      }
    case MG_WS_CONNECT:
      // New websocket connection. Send connection ID back to the client.
      conn->connection_param = calloc(1, sizeof(struct conn_data));
      mg_websocket_printf(conn, WEBSOCKET_OPCODE_TEXT, "id %p", conn);
      return MG_FALSE;
    case MG_CLOSE:
      free(conn->connection_param);
      return MG_TRUE;
    case MG_AUTH:
      return MG_TRUE;
    default:
      return MG_FALSE;
  }
}
#endif

static int is_websocket(const struct ns_connection *nc) {
  return nc->flags & NSF_USER_1;
}

static void broadcast(struct ns_connection *nc, const char *msg, size_t len) {
  struct ns_connection *c;
  char buf[500];

  snprintf(buf, sizeof(buf), "%p %.*s", nc, (int) len, msg);
  for (c = ns_next(nc->mgr, NULL); c != NULL; c = ns_next(nc->mgr, c)) {
    ns_send_websocket_frame(c, WEBSOCKET_OP_TEXT, buf, strlen(buf));
  }
}

static void ev_handler(struct ns_connection *nc, int ev, void *ev_data) {
  struct http_message *hm = (struct http_message *) ev_data;
  struct websocket_message *wm = (struct websocket_message *) ev_data;

  switch (ev) {
    case NS_HTTP_REQUEST:
      /* Usual HTTP request - serve static files */
      ns_serve_http(nc, hm, s_http_server_opts);
      nc->flags |= NSF_FINISHED_SENDING_DATA;
      break;
    case NS_WEBSOCKET_HANDSHAKE_DONE:
      /* New websocket connection. Tell everybody. */
      broadcast(nc, "joined", 6);
      break;
    case NS_WEBSOCKET_FRAME:
      /* New websocket message. Tell everybody. */
      broadcast(nc, (char *) wm->data, wm->size);
      break;
    case NS_CLOSE:
      /* Disconnect. Tell everybody. */
      if (is_websocket(nc)) {
        broadcast(nc, "left", 4);
      }
      break;
    default:
      break;
  }
}

int main(void) {
  struct ns_mgr mgr;
  struct ns_connection *nc;

  signal(SIGTERM, signal_handler);
  signal(SIGINT, signal_handler);

  ns_mgr_init(&mgr, NULL);

  nc = ns_bind(&mgr, s_http_port, ev_handler);
  ns_set_protocol_http_websocket(nc);

  printf("Started on port %s\n", s_http_port);
  while (s_signal_received == 0) {
    ns_mgr_poll(&mgr, 200);
  }
  ns_mgr_free(&mgr);

  return 0;
}
