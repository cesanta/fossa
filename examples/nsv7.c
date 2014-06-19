// Copyright (c) 2014 Cesanta Software Limited
// All rights reserved
//
// This code is dual-licensed: you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation. For the terms of this
// license, see <http://www.gnu.org/licenses/>.
//
// You are free to use this code under the terms of the GNU General
// Public License, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// Alternatively, you can license this code under a commercial
// license, as set out in <http://cesanta.com/>.

// Universal network communication framework with Javascript scripting.
// This file provides Javascript binding to the Net Skeleton framework.  

#include "net_skeleton.h"
#include "v7.h"

static int s_received_signal = 0;

static void elog(int do_exit, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
  if (do_exit) exit(EXIT_FAILURE);
}

static void signal_handler(int sig_num) {
  signal(sig_num, signal_handler);
  s_received_signal = sig_num;
}

static struct ns_connection *get_nc(struct v7_val *obj) {
  struct v7_val key = v7_str_to_val("nc"), *p = v7_get(obj, &key);
  struct ns_connection *nc = NULL;
  if (p != NULL) {
    unsigned long num = (unsigned long) p->v.num;
    nc = (struct ns_connection *) num;
  }
  return nc;
}

static void js_write(struct v7 *v7, struct v7_val *obj,
                     struct v7_val *result,
                     struct v7_val *args, int num_args) {
  int i;
  struct ns_connection *nc = get_nc(obj);
  (void) v7;
  result->type = V7_NUM;
  result->v.num = 0;
  for (i = 0; i < num_args; i++) {
    if (args[i].type != V7_STR) continue;
    ns_send(nc, args[i].v.str.buf, args[i].v.str.len);
  }
}

static void js_close(struct v7 *v7, struct v7_val *obj,
                     struct v7_val *result,
                     struct v7_val *args, int num_args) {
  struct ns_connection *nc = get_nc(obj);
  (void) v7; (void) result; (void) args; (void) num_args;
  nc->flags |= NSF_CLOSE_IMMEDIATELY;
}

static void ev_handler(struct ns_connection *nc, enum ns_event ev, void *p) {
  struct v7 *v7 = (struct v7 *) nc->server->server_data;
  struct v7_val *jsconn;

  printf("C handler: %p %d\n", nc, ev);

  // Call javascript event handler
  v7_exec(v7, "ev_handler");
  jsconn = v7_push(v7, V7_OBJ);
  v7_push(v7, V7_NUM)->v.num = ev;
  v7_push(v7, V7_NUM)->v.num = (unsigned long) p;
  
  v7_set_num(jsconn, "nc", (unsigned long) nc);
  v7_set_str(jsconn, "recv_buf", nc->recv_iobuf.buf, nc->recv_iobuf.len);
  v7_set_str(jsconn, "send_buf", nc->send_iobuf.buf, nc->send_iobuf.len);
  v7_set_func(jsconn, "write", js_write);
  v7_set_func(jsconn, "close", js_close);

  v7_call(v7, v7_top(v7) - 4);
  
  // Exit if we receive string 'exit'
  if (ev == NS_RECV && (* (int *) p) == 4 &&
      memcmp(nc->recv_iobuf.buf + nc->recv_iobuf.len - 4, "exit", 4) == 0) {
    s_received_signal = 1;
  }
}

int main(int argc, char *argv[]) {
  const char *script = "nsv7.js", *port = "4000";
  struct ns_server server;
  struct v7 *v7;
  int i;
  
  // Parse command line options
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
      script = argv[++i];
    } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
      port = argv[++i];
    } else {
      elog(1, "Usage: %s [-f FILE] [-p PORT]", argv[0]);
    }
  }

  signal(SIGTERM, signal_handler);
  signal(SIGINT, signal_handler);

  // Initialize scripting engine
  v7 = v7_create();
  v7_init_stdlib(v7);
  if (v7_exec_file(v7, script) != V7_OK) {
    elog(1, "Error executing %s", script);
  }

  // Initialize server
  ns_server_init(&server, v7, ev_handler);
  ns_bind(&server, port);
  while (s_received_signal == 0) {
    ns_server_poll(&server, 1000);
  }
  printf("Existing on signal %d\n", s_received_signal);
  v7_destroy(&v7);
  ns_server_free(&server);

  return EXIT_SUCCESS;
}
