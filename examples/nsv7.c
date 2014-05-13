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

#ifndef NSV7_SCRIPT
#define NSV7_SCRIPT "nsv7.js"
#endif

static void ev_handler(struct ns_connection *nc, enum ns_event ev, void *p) {
  struct v7 *v7 = (struct v7 *) nc->server->server_data;

  // Push parameters then event handler on stack
  v7_push(v7, V7_NUM)->v.num = ev;
  v7_push(v7, V7_NUM)->v.num = (unsigned long) p;
  v7_exec(v7, "ns.ev_handler");

  // Call event handler
  v7_call(v7, v7_top(v7) - 3);
}

int main(void) {
  struct ns_server server;
  struct v7 *v7 = v7_create();

  v7_init_stdlib(v7);
  v7_exec_file(v7, NSV7_SCRIPT);

  ns_server_init(&server, v7, ev_handler);
  
  for (;;) {
    ns_server_poll(&server, 1000);
  }
  ns_server_free(&server);

  return EXIT_SUCCESS;
}
