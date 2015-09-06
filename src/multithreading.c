/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#include "internal.h"

#ifdef NS_ENABLE_THREADS

static void multithreaded_ev_handler(struct ns_connection *c, int ev, void *p);

/*
 * This thread function executes user event handler.
 * It runs an event manager that has only one connection, until that
 * connection is alive.
 */
static void *per_connection_thread_function(void *param) {
  struct ns_connection *c = (struct ns_connection *) param;
  struct ns_mgr m;

  ns_mgr_init(&m, NULL);
  ns_add_conn(&m, c);
  while (m.active_connections != NULL) {
    ns_mgr_poll(&m, 1000);
  }
  ns_mgr_free(&m);

  return param;
}

static void link_conns(struct ns_connection *c1, struct ns_connection *c2) {
  c1->priv_2 = c2;
  c2->priv_2 = c1;
}

static void unlink_conns(struct ns_connection *c) {
  struct ns_connection *peer = (struct ns_connection *) c->priv_2;
  if (peer != NULL) {
    peer->flags |= NSF_SEND_AND_CLOSE;
    peer->priv_2 = NULL;
  }
  c->priv_2 = NULL;
}

static void forwarder_ev_handler(struct ns_connection *c, int ev, void *p) {
  (void) p;
  if (ev == NS_RECV && c->priv_2) {
    ns_forward(c, c->priv_2);
  } else if (ev == NS_CLOSE) {
    unlink_conns(c);
  }
}

static void spawn_handling_thread(struct ns_connection *nc) {
  struct ns_mgr dummy = {};
  sock_t sp[2];
  struct ns_connection *c[2];

  /*
   * Create a socket pair, and wrap each socket into the connection with
   * dummy event manager.
   * c[0] stays in this thread, c[1] goes to another thread.
   */
  ns_socketpair(sp, SOCK_STREAM);
  c[0] = ns_add_sock(&dummy, sp[0], forwarder_ev_handler);
  c[1] = ns_add_sock(&dummy, sp[1], nc->listener->priv_1);

  /* Interlink client connection with c[0] */
  link_conns(c[0], nc);

  /*
   * Switch c[0] manager from the dummy one to the real one. c[1] manager
   * will be set in another thread, allocated on stack of that thread.
   */
  ns_add_conn(nc->mgr, c[0]);

  /*
   * Dress c[1] as nc.
   * TODO(lsm): code in accept_conn() looks similar. Refactor.
   */
  c[1]->listener = nc->listener;
  c[1]->proto_handler = nc->proto_handler;
  c[1]->proto_data = nc->proto_data;
  c[1]->user_data = nc->user_data;

  ns_start_thread(per_connection_thread_function, c[1]);
}

static void multithreaded_ev_handler(struct ns_connection *c, int ev, void *p) {
  (void) p;
  if (ev == NS_ACCEPT) {
    spawn_handling_thread(c);
    c->handler = forwarder_ev_handler;
  }
}

void ns_enable_multithreading(struct ns_connection *nc) {
  /* Wrap user event handler into our multithreaded_ev_handler */
  nc->priv_1 = nc->handler;
  nc->handler = multithreaded_ev_handler;
}
#endif
