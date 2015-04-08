/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#include "db_plugin.h"

static const char *s_http_port = "8000";
static struct ns_serve_http_opts s_http_server_opts;
static int s_sig_num = 0;
static void *s_db_handle = NULL;
static const char *s_db_path = "api_server.db";
static const struct ns_str s_get_method = NS_STR("GET");
static const struct ns_str s_put_method = NS_STR("PUT");
static const struct ns_str s_delele_method = NS_STR("DELETE");

static void signal_handler(int sig_num) {
  signal(sig_num, signal_handler);
  s_sig_num = sig_num;
}

static int has_prefix(const struct ns_str *uri, const struct ns_str *prefix) {
  return uri->len > prefix->len && memcmp(uri->p, prefix->p, prefix->len) == 0;
}

static int is_equal(const struct ns_str *s1, const struct ns_str *s2) {
  return s1->len == s2->len && memcmp(s1->p, s2->p, s2->len) == 0;
}

static void ev_handler(struct ns_connection *nc, int ev, void *ev_data) {
  static const struct ns_str api_prefix = NS_STR("/api/v1");
  struct http_message *hm = (struct http_message *) ev_data;
  struct ns_str key;

  switch (ev) {
    case NS_HTTP_REQUEST:
      if (has_prefix(&hm->uri, &api_prefix)) {
        key.p = hm->uri.p + api_prefix.len;
        key.len = hm->uri.len - api_prefix.len;
        if (is_equal(&hm->method, &s_get_method)) {
          db_op(nc, hm, &key, s_db_handle, API_OP_GET);
        } else if (is_equal(&hm->method, &s_put_method)) {
          db_op(nc, hm, &key, s_db_handle, API_OP_SET);
        } else if (is_equal(&hm->method, &s_delele_method)) {
          db_op(nc, hm, &key, s_db_handle, API_OP_DEL);
        } else {
          ns_printf(nc, "%s",
                    "HTTP/1.0 501 Not Implemented\r\n"
                    "Content-Length: 0\r\n\r\n");
        }
      } else {
        ns_serve_http(nc, hm, s_http_server_opts); /* Serve static content */
      }
      break;
    default:
      break;
  }
}

int main(int argc, char *argv[]) {
  struct ns_mgr mgr;
  struct ns_connection *nc;
  int i;

  /* Open listening socket */
  ns_mgr_init(&mgr, NULL);
  nc = ns_bind(&mgr, s_http_port, ev_handler);
  ns_set_protocol_http_websocket(nc);
  s_http_server_opts.document_root = "web_root";

  /* Parse command line arguments */
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-D") == 0) {
      mgr.hexdump_file = argv[++i];
    } else if (strcmp(argv[i], "-f") == 0) {
      s_db_path = argv[++i];
    } else if (strcmp(argv[i], "-r") == 0) {
      s_http_server_opts.document_root = argv[++i];
    }
  }

  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  /* Open database */
  if ((s_db_handle = db_open(s_db_path)) == NULL) {
    fprintf(stderr, "Cannot open DB [%s]\n", s_db_path);
    exit(EXIT_FAILURE);
  }

  /* Run event loop until signal is received */
  printf("Starting RESTful server on port %s\n", s_http_port);
  while (s_sig_num == 0) {
    ns_mgr_poll(&mgr, 1000);
  }

  /* Cleanup */
  ns_mgr_free(&mgr);
  db_close(&s_db_handle);

  printf("Exiting on signal %d\n", s_sig_num);

  return 0;
}
