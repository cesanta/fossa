/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 * This software is dual-licensed: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. For the terms of this
 * license, see <http://www.gnu.org/licenses/>.
 *
 * You are free to use this software under the terms of the GNU General
 * Public License, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * Alternatively, you can license this software under a commercial
 * license, as set out in <https://www.cesanta.com/license>.
 */

#include "../../fossa.h"

int main(void) {
  struct ns_mgr mgr;
  const char *address = "0.0.0.0:1883";
  struct ns_connection *nc;
  struct ns_mqtt_broker brk;

  ns_mgr_init(&mgr, NULL);
  ns_mqtt_broker_init(&brk, NULL);

  if ((nc = ns_bind(&mgr, address, ns_mqtt_broker)) == NULL) {
    fprintf(stderr, "ns_bind(%s) failed\n", address);
    exit(EXIT_FAILURE);
  }
  nc->user_data = &brk;

  /*
   * TODO: Add a HTTP status page that shows current sessions
   * and subscriptions
   */

  for(;;) {
    ns_mgr_poll(&mgr, 1000);
  }
}
