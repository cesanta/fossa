/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#include "fossa.h"

static const char *s_http_port = "8000";
static struct ns_serve_http_opts s_http_server_opts = { "." };

static void handle_sum_call(struct ns_connection *nc, struct http_message *hm) {
  char n1[100], n2[100];
  double result;

  /* Get form variables */
  ns_get_http_var(&hm->body, "n1", n1, sizeof(n1));
  ns_get_http_var(&hm->body, "n2", n2, sizeof(n2));

  /* Send headers */
  ns_printf(nc, "%s", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");

  /* Compute the result and send it back as a JSON object */
  result = strtod(n1, NULL) + strtod(n2, NULL);
  ns_printf_http_chunk(nc, "{ \"result\": %lf }", result);
  ns_send_http_chunk(nc, "", 0);  /* Send empty chunk, the end of response */
}

static void ev_handler(struct ns_connection *nc, int ev, void *ev_data) {
  struct http_message *hm = (struct http_message *) ev_data;

  switch (ev) {
    case NS_HTTP_REQUEST:
      if (ns_vcmp(&hm->uri, "/api/v1/sum") == 0) {
        handle_sum_call(nc, hm);                    /* Handle RESTful call */
      } else {
        ns_serve_http(nc, hm, s_http_server_opts);  /* Serve static content */
      }
      break;
    default:
      break;
  }
}

int main(int argc, char *argv[]) {
  struct ns_mgr mgr;
  struct ns_connection *nc;

  ns_mgr_init(&mgr, NULL);
  nc = ns_bind(&mgr, s_http_port, ev_handler);
  ns_set_protocol_http_websocket(nc);
  mgr.hexdump_file = argc > 1 ? argv[1] : NULL;  /* Allow hexdump debug */

  printf("Starting RESTful server on port %s\n", s_http_port);
  for (;;) {
    ns_mgr_poll(&mgr, 1000);
  }
  ns_mgr_free(&mgr);

  return 0;
}
