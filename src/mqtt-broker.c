/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#include "internal.h"

#ifdef NS_ENABLE_MQTT_BROKER

static void ns_mqtt_session_init(struct ns_mqtt_broker *brk,
                                 struct ns_mqtt_session *s,
                                 struct ns_connection *nc) {
  s->brk = brk;
  s->subscriptions = NULL;
  s->num_subscriptions = 0;
  s->nc = nc;
}

static void ns_mqtt_add_session(struct ns_mqtt_session *s) {
  s->next = s->brk->sessions;
  s->brk->sessions = s;
  s->prev = NULL;
  if (s->next != NULL) s->next->prev = s;
}

static void ns_mqtt_remove_session(struct ns_mqtt_session *s) {
  if (s->prev == NULL) s->brk->sessions = s->next;
  if (s->prev) s->prev->next = s->next;
  if (s->next) s->next->prev = s->prev;
}

static void ns_mqtt_destroy_session(struct ns_mqtt_session *s) {
  size_t i;
  for (i = 0; i < s->num_subscriptions; i++) {
    NS_FREE((void *) s->subscriptions[i].topic);
  }
  NS_FREE(s);
}

static void ns_mqtt_close_session(struct ns_mqtt_session *s) {
  ns_mqtt_remove_session(s);
  ns_mqtt_destroy_session(s);
}

void ns_mqtt_broker_init(struct ns_mqtt_broker *brk, void *user_data) {
  brk->sessions = NULL;
  brk->user_data = user_data;
}

static void ns_mqtt_broker_handle_connect(struct ns_mqtt_broker *brk,
                                          struct ns_connection *nc) {
  struct ns_mqtt_session *s = (struct ns_mqtt_session *) malloc(sizeof *s);
  if (s == NULL) {
    /* LCOV_EXCL_START */
    ns_mqtt_connack(nc, NS_MQTT_CONNACK_SERVER_UNAVAILABLE);
    return;
    /* LCOV_EXCL_STOP */
  }

  /* TODO(mkm): check header (magic and version) */

  ns_mqtt_session_init(brk, s, nc);
  s->user_data = nc->user_data;
  nc->user_data = s;
  ns_mqtt_add_session(s);

  ns_mqtt_connack(nc, NS_MQTT_CONNACK_ACCEPTED);
}

static void ns_mqtt_broker_handle_subscribe(struct ns_connection *nc,
                                            struct ns_mqtt_message *msg) {
  struct ns_mqtt_session *ss = (struct ns_mqtt_session *) nc->user_data;
  uint8_t qoss[512];
  size_t qoss_len = 0;
  struct ns_str topic;
  uint8_t qos;
  int pos;
  struct ns_mqtt_topic_expression *te;

  for (pos = 0;
       (pos = ns_mqtt_next_subscribe_topic(msg, &topic, &qos, pos)) != -1;) {
    qoss[qoss_len++] = qos;
  }

  ss->subscriptions = (struct ns_mqtt_topic_expression *) realloc(
      ss->subscriptions, sizeof(*ss->subscriptions) * qoss_len);
  for (pos = 0;
       (pos = ns_mqtt_next_subscribe_topic(msg, &topic, &qos, pos)) != -1;
       ss->num_subscriptions++) {
    te = &ss->subscriptions[ss->num_subscriptions];
    te->topic = (char *) malloc(topic.len + 1);
    te->qos = qos;
    strncpy((char *) te->topic, topic.p, topic.len + 1);
  }

  ns_mqtt_suback(nc, qoss, qoss_len, msg->message_id);
}

/*
 * Matches a topic against a topic expression
 *
 * See http://goo.gl/iWk21X
 *
 * Returns 1 if it matches; 0 otherwise.
 */
static int ns_mqtt_match_topic_expression(const char *exp, const char *topic) {
  /* TODO(mkm): implement real matching */
  int len = strlen(exp);
  if (strchr(exp, '#')) {
    len -= 2;
  }
  return strncmp(exp, topic, len) == 0;
}

static void ns_mqtt_broker_handle_publish(struct ns_mqtt_broker *brk,
                                          struct ns_mqtt_message *msg) {
  struct ns_mqtt_session *s;
  size_t i;

  for (s = ns_mqtt_next(brk, NULL); s != NULL; s = ns_mqtt_next(brk, s)) {
    for (i = 0; i < s->num_subscriptions; i++) {
      if (ns_mqtt_match_topic_expression(s->subscriptions[i].topic,
                                         msg->topic)) {
        ns_mqtt_publish(s->nc, msg->topic, 0, 0, msg->payload.p,
                        msg->payload.len);
        break;
      }
    }
  }
}

void ns_mqtt_broker(struct ns_connection *nc, int ev, void *data) {
  struct ns_mqtt_message *msg = (struct ns_mqtt_message *) data;
  struct ns_mqtt_broker *brk;

  if (nc->listener) {
    brk = (struct ns_mqtt_broker *) nc->listener->user_data;
  } else {
    brk = (struct ns_mqtt_broker *) nc->user_data;
  }

  switch (ev) {
    case NS_ACCEPT:
      ns_set_protocol_mqtt(nc);
      break;
    case NS_MQTT_CONNECT:
      ns_mqtt_broker_handle_connect(brk, nc);
      break;
    case NS_MQTT_SUBSCRIBE:
      ns_mqtt_broker_handle_subscribe(nc, msg);
      break;
    case NS_MQTT_PUBLISH:
      ns_mqtt_broker_handle_publish(brk, msg);
      break;
    case NS_CLOSE:
      if (nc->listener) {
        ns_mqtt_close_session((struct ns_mqtt_session *) nc->user_data);
      }
      break;
  }
}

struct ns_mqtt_session *ns_mqtt_next(struct ns_mqtt_broker *brk,
                                     struct ns_mqtt_session *s) {
  return s == NULL ? brk->sessions : s->next;
}

#endif /* NS_ENABLE_MQTT_BROKER */
