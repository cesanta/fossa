// Copyright (c) 2015 Cesanta Software Limited
// All rights reserved

#include "fossa.h"

static const char *s_http_port = "8000";
static struct ns_serve_http_opts s_http_server_opts;

static void ev_handler(struct ns_connection *nc, int ev, void *p) {
  if (ev == NS_HTTP_REQUEST) {
    ns_serve_http(nc, p, s_http_server_opts);
  }
}

int main(void) {
  struct ns_mgr mgr;
  struct ns_connection *nc;

  ns_mgr_init(&mgr, NULL);
  nc = ns_bind(&mgr, s_http_port, ev_handler);

  // Set up HTTP server parameters
  ns_set_protocol_http_websocket(nc);
  s_http_server_opts.document_root = ".";  // Serve current directory
  s_http_server_opts.enable_directory_listing = "yes";

  printf("Starting web server on port %s\n", s_http_port);
  for (;;) {
    ns_mgr_poll(&mgr, 1000);
  }
  ns_mgr_free(&mgr);

  return 0;
}
