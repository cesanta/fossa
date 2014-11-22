/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 *
 * This program fetches HTTP URLs.
 */

#include "fossa.h"

static int s_exit_flag = 0;
static int s_show_headers = 0;

static void ev_handler(struct ns_connection *nc, int ev, void *ev_data) {
  struct http_message *hm = (struct http_message *) ev_data;

  switch (ev) {
    case NS_CONNECT:
      if (* (int *) ev_data != 0) {
        fprintf(stderr, "connect() failed: %s\n", strerror(* (int *) ev_data));
        s_exit_flag = 1;
      }
      break;
    case NS_HTTP_REPLY:
      nc->flags |= NSF_CLOSE_IMMEDIATELY;
      if (s_show_headers) {
        fwrite(hm->message.p, 1, hm->message.len, stdout);
      } else {
        fwrite(hm->body.p, 1, hm->body.len, stdout);
      }
      putchar('\n');
      s_exit_flag = 1;
      break;
    default:
      break;
  }
}

int main(int argc, char *argv[]) {
  struct ns_mgr mgr;

  ns_mgr_init(&mgr, NULL);

  if (argc > 1 && strcmp(argv[1], "--show_headers") == 0) {
    s_show_headers = 1;
    argv++;
    argc--;
  }

  if (argc != 2) {
    fprintf(stderr, "Usage: [--show_headers] %s <URL>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  ns_connect_http(&mgr, ev_handler, argv[1], NULL);

  while (s_exit_flag == 0) {
    ns_mgr_poll(&mgr, 1000);
  }
  ns_mgr_free(&mgr);

  return 0;
}
