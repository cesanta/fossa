/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include "fossa.h"

struct device_settings {
  char setting1[100];
  char setting2[100];
};

static const char *s_http_port = "8000";
static struct ns_serve_http_opts s_http_server_opts;
static struct device_settings s_settings = { "value1", "value2" };

static void handle_save(struct ns_connection *nc, struct http_message *hm) {
  /* Get form variables and store settings values */
  ns_get_http_var(&hm->body, "setting1", s_settings.setting1,
                  sizeof(s_settings.setting1));
  ns_get_http_var(&hm->body, "setting2", s_settings.setting2,
                  sizeof(s_settings.setting2));

  /* Send response */
  ns_printf(nc, "HTTP/1.1 200 OK\r\nContent-Length: %lu\r\n\r\n%.*s",
            (unsigned long) hm->body.len, (int) hm->body.len, hm->body.p);
}

static void handle_ssi_call(struct ns_connection *nc, const char *param) {
  if (strcmp(param, "setting1") == 0) {
    ns_printf_html_escape(nc, "%s", s_settings.setting1);
  } else if (strcmp(param, "setting2") == 0) {
    ns_printf_html_escape(nc, "%s", s_settings.setting2);
  }
}

static void ev_handler(struct ns_connection *nc, int ev, void *ev_data) {
  struct http_message *hm = (struct http_message *) ev_data;

  switch (ev) {
    case NS_HTTP_REQUEST:
      if (ns_vcmp(&hm->uri, "/save") == 0) {
        handle_save(nc, hm);                    /* Handle RESTful call */
      } else {
        ns_serve_http(nc, hm, s_http_server_opts);  /* Serve static content */
      }
      break;
    case NS_SSI_CALL:
      handle_ssi_call(nc, ev_data);
      break;
    default:
      break;
  }
}

int main(int argc, char *argv[]) {
  struct ns_mgr mgr;
  struct ns_connection *nc;
  char *p, path[512];

  ns_mgr_init(&mgr, NULL);
  nc = ns_bind(&mgr, s_http_port, ev_handler);
  ns_set_protocol_http_websocket(nc);
  s_http_server_opts.document_root = "./web_root";
  s_http_server_opts.auth_domain = "example.com";
  //mgr.hexdump_file = "/dev/stdout";

  /* If our current directory */
  if (argc > 0 && (p = strrchr(argv[0], '/'))) {
    snprintf(path, sizeof(path), "%.*s/web_root", (int)(p - argv[0]), argv[0]);
    s_http_server_opts.document_root = path;
  }

  printf("Starting device configurator on port %s\n", s_http_port);
  for (;;) {
    ns_mgr_poll(&mgr, 1000);
  }
  ns_mgr_free(&mgr);

  return 0;
}
