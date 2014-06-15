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

static void ev_handler(struct ns_connection *nc, enum ns_event ev, void *p) {
  struct v7 *v7 = (struct v7 *) nc->server->server_data;
  
  //printf("C handler: %p %d %p\n", nc, ev, p);
  // Call javascript event handler
  v7_exec(v7, "ev_handler");
  v7_push(v7, V7_NUM)->v.num = ev;
  v7_push(v7, V7_NUM)->v.num = (unsigned long) p;
  v7_call(v7, v7_top(v7) - 3, 2);
}

int main(int argc, char *argv[]) {
  const char *script = "nsv7.js";
  struct ns_server server;
  struct v7 *v7 = v7_create();
  int i;
  
  // Parse command line options
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
      script = argv[++i];
    } else {
      elog(1, "Usage: %s [-script FILE]", argv[0]);
    }
  }

  signal(SIGTERM, signal_handler);
  signal(SIGINT, signal_handler);

  v7_init_stdlib(v7);
  v7_exec_file(v7, script);

  ns_server_init(&server, v7, ev_handler);
  ns_bind(&server, "8080");
  while (s_received_signal == 0) {
    ns_server_poll(&server, 1000);
  }
  printf("Existing on signal %d\n", s_received_signal);
  ns_server_free(&server);

  return EXIT_SUCCESS;
}
