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

/*
 * === MQTT Broker
 */

#ifndef NS_MQTT_BROKER_HEADER_INCLUDED
#define NS_MQTT_BROKER_HEADER_INCLUDED

#ifdef NS_ENABLE_MQTT_BROKER

#include "mqtt.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define NS_MQTT_MAX_SESSION_SUBSCRIPTIONS 512;

struct ns_mqtt_broker;

/* MQTT session (Broker side). */
struct ns_mqtt_session {
  struct ns_mqtt_broker *brk;          /* Broker */
  struct ns_mqtt_session *next, *prev; /* ns_mqtt_broker::sessions linkage */
  struct ns_connection *nc;            /* Connection with the client */
  size_t num_subscriptions;            /* Size of `subscriptions` array */
  struct ns_mqtt_topic_expression *subscriptions;
  void *user_data; /* User data */
};

/* MQTT broker. */
struct ns_mqtt_broker {
  struct ns_mqtt_session *sessions; /* Session list */
  void *user_data;                  /* User data */
};

/* Initialize a MQTT broker. */
void ns_mqtt_broker_init(struct ns_mqtt_broker *, void *);

/*
 * Process a MQTT broker message.
 *
 * Listening connection expects a pointer to an initialized `ns_mqtt_broker`
 * structure in the `user_data` field.
 *
 * Basic usage:
 *
 * [source,c]
 * -----
 * ns_mqtt_broker_init(&brk, NULL);
 *
 * if ((nc = ns_bind(&mgr, address, ns_mqtt_broker)) == NULL) {
 *   // fail;
 * }
 * nc->user_data = &brk;
 * -----
 *
 * New incoming connections will receive a `ns_mqtt_session` structure
 * in the connection `user_data`. The original `user_data` will be stored
 * in the `user_data` field of the session structure. This allows the user
 * handler to store user data before `ns_mqtt_broker` creates the session.
 *
 * Since only the NS_ACCEPT message is processed by the listening socket,
 * for most events the `user_data` will thus point to a `ns_mqtt_session`.
 */
void ns_mqtt_broker(struct ns_connection *, int, void *);

/*
 * Iterate over all mqtt sessions connections. Example:
 *
 *    struct ns_mqtt_session *s;
 *    for (s = ns_mqtt_next(brk, NULL); s != NULL; s = ns_mqtt_next(brk, s)) {
 *       // Do something
 *    }
 */
struct ns_mqtt_session *ns_mqtt_next(struct ns_mqtt_broker *,
                                     struct ns_mqtt_session *);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* NS_ENABLE_MQTT_BROKER */
#endif /* NS_MQTT_HEADER_INCLUDED */
