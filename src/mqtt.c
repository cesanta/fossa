/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#ifndef NS_DISABLE_MQTT

#include "internal.h"

static int parse_mqtt(struct mbuf *io, struct ns_mqtt_message *mm) {
  uint8_t header;
  int cmd;
  size_t len = 0;
  int var_len = 0;
  char *vlen = &io->buf[1];

  if (io->len < 2) return -1;

  header = io->buf[0];
  cmd = header >> 4;

  /* decode mqtt variable length */
  do {
    len += (*vlen & 127) << 7 * (vlen - &io->buf[1]);
  } while ((*vlen++ & 128) != 0 && ((size_t)(vlen - io->buf) <= io->len));

  if (io->len < (size_t)(len - 1)) return -1;

  mbuf_remove(io, 1 + (vlen - &io->buf[1]));
  mm->cmd = cmd;
  mm->qos = NS_MQTT_GET_QOS(header);

  switch (cmd) {
    case NS_MQTT_CMD_CONNECT:
      /* TODO(mkm): parse keepalive and will */
      break;
    case NS_MQTT_CMD_CONNACK:
      mm->connack_ret_code = io->buf[1];
      var_len = 2;
      break;
    case NS_MQTT_CMD_PUBACK:
    case NS_MQTT_CMD_PUBREC:
    case NS_MQTT_CMD_PUBREL:
    case NS_MQTT_CMD_PUBCOMP:
    case NS_MQTT_CMD_SUBACK:
      mm->message_id = ntohs(*(uint16_t *) io->buf);
      var_len = 2;
      break;
    case NS_MQTT_CMD_PUBLISH: {
      uint16_t topic_len = ntohs(*(uint16_t *) io->buf);
      mm->topic = (char *) NS_MALLOC(topic_len + 1);
      mm->topic[topic_len] = 0;
      strncpy(mm->topic, io->buf + 2, topic_len);
      var_len = topic_len + 2;

      if (NS_MQTT_GET_QOS(header) > 0) {
        mm->message_id = ntohs(*(uint16_t *) io->buf);
        var_len += 2;
      }
    } break;
    case NS_MQTT_CMD_SUBSCRIBE:
      /*
       * topic expressions are left in the payload and can be parsed with
       * `ns_mqtt_next_subscribe_topic`
       */
      mm->message_id = ntohs(*(uint16_t *) io->buf);
      var_len = 2;
      break;
    default:
      printf("TODO: UNHANDLED COMMAND %d\n", cmd);
      break;
  }

  mbuf_remove(io, var_len);
  return len - var_len;
}

static void mqtt_handler(struct ns_connection *nc, int ev, void *ev_data) {
  int len;
  struct mbuf *io = &nc->recv_mbuf;
  struct ns_mqtt_message mm;
  memset(&mm, 0, sizeof(mm));

  nc->handler(nc, ev, ev_data);

  switch (ev) {
    case NS_RECV:
      len = parse_mqtt(io, &mm);
      if (len == -1) break; /* not fully buffered */
      mm.payload.p = io->buf;
      mm.payload.len = len;

      nc->handler(nc, NS_MQTT_EVENT_BASE + mm.cmd, &mm);

      if (mm.topic) {
        NS_FREE(mm.topic);
      }
      mbuf_remove(io, mm.payload.len);
      break;
  }
}

void ns_set_protocol_mqtt(struct ns_connection *nc) {
  nc->proto_handler = mqtt_handler;
}

void ns_send_mqtt_handshake(struct ns_connection *nc, const char *client_id) {
  static struct ns_send_mqtt_handshake_opts opts;
  ns_send_mqtt_handshake_opt(nc, client_id, opts);
}

void ns_send_mqtt_handshake_opt(struct ns_connection *nc, const char *client_id,
                                struct ns_send_mqtt_handshake_opts opts) {
  uint8_t header = NS_MQTT_CMD_CONNECT << 4;
  uint8_t rem_len;
  uint16_t keep_alive;
  uint16_t client_id_len;

  /*
   * 9: version_header(len, magic_string, version_number), 1: flags, 2:
   * keep-alive timer,
   * 2: client_identifier_len, n: client_id
   */
  rem_len = 9 + 1 + 2 + 2 + strlen(client_id);

  ns_send(nc, &header, 1);
  ns_send(nc, &rem_len, 1);
  ns_send(nc, "\00\06MQIsdp\03", 9);
  ns_send(nc, &opts.flags, 1);

  if (opts.keep_alive == 0) {
    opts.keep_alive = 60;
  }
  keep_alive = htons(opts.keep_alive);
  ns_send(nc, &keep_alive, 2);

  client_id_len = htons(strlen(client_id));
  ns_send(nc, &client_id_len, 2);
  ns_send(nc, client_id, strlen(client_id));
}

static void ns_mqtt_prepend_header(struct ns_connection *nc, uint8_t cmd,
                                   uint8_t flags, size_t len) {
  size_t off = nc->send_mbuf.len - len;
  uint8_t header = cmd << 4 | (uint8_t) flags;

  uint8_t buf[1 + sizeof(size_t)];
  uint8_t *vlen = &buf[1];

  assert(nc->send_mbuf.len >= len);

  buf[0] = header;

  /* mqtt variable length encoding */
  do {
    *vlen = len % 0x80;
    len /= 0x80;
    if (len > 0) *vlen |= 0x80;
    vlen++;
  } while (len > 0);

  mbuf_insert(&nc->send_mbuf, off, buf, vlen - buf);
}

void ns_mqtt_publish(struct ns_connection *nc, const char *topic,
                     uint16_t message_id, int flags, const void *data,
                     size_t len) {
  size_t old_len = nc->send_mbuf.len;

  uint16_t topic_len = htons(strlen(topic));
  uint16_t message_id_net = htons(message_id);

  ns_send(nc, &topic_len, 2);
  ns_send(nc, topic, strlen(topic));
  if (NS_MQTT_GET_QOS(flags) > 0) {
    ns_send(nc, &message_id_net, 2);
  }
  ns_send(nc, data, len);

  ns_mqtt_prepend_header(nc, NS_MQTT_CMD_PUBLISH, flags,
                         nc->send_mbuf.len - old_len);
}

void ns_mqtt_subscribe(struct ns_connection *nc,
                       const struct ns_mqtt_topic_expression *topics,
                       size_t topics_len, uint16_t message_id) {
  size_t old_len = nc->send_mbuf.len;

  uint16_t message_id_n = htons(message_id);
  size_t i;

  ns_send(nc, (char *) &message_id_n, 2);
  for (i = 0; i < topics_len; i++) {
    uint16_t topic_len_n = htons(strlen(topics[i].topic));
    ns_send(nc, &topic_len_n, 2);
    ns_send(nc, topics[i].topic, strlen(topics[i].topic));
    ns_send(nc, &topics[i].qos, 1);
  }

  ns_mqtt_prepend_header(nc, NS_MQTT_CMD_SUBSCRIBE, NS_MQTT_QOS(1),
                         nc->send_mbuf.len - old_len);
}

int ns_mqtt_next_subscribe_topic(struct ns_mqtt_message *msg,
                                 struct ns_str *topic, uint8_t *qos, int pos) {
  unsigned char *buf = (unsigned char *) msg->payload.p + pos;
  if ((size_t) pos >= msg->payload.len) {
    return -1;
  }

  topic->len = buf[0] << 8 | buf[1];
  topic->p = (char *) buf + 2;
  *qos = buf[2 + topic->len];
  return pos + 2 + topic->len + 1;
}

void ns_mqtt_unsubscribe(struct ns_connection *nc, char **topics,
                         size_t topics_len, uint16_t message_id) {
  size_t old_len = nc->send_mbuf.len;

  uint16_t message_id_n = htons(message_id);
  size_t i;

  ns_send(nc, (char *) &message_id_n, 2);
  for (i = 0; i < topics_len; i++) {
    uint16_t topic_len_n = htons(strlen(topics[i]));
    ns_send(nc, &topic_len_n, 2);
    ns_send(nc, topics[i], strlen(topics[i]));
  }

  ns_mqtt_prepend_header(nc, NS_MQTT_CMD_UNSUBSCRIBE, NS_MQTT_QOS(1),
                         nc->send_mbuf.len - old_len);
}

void ns_mqtt_connack(struct ns_connection *nc, uint8_t return_code) {
  uint8_t unused = 0;
  ns_send(nc, &unused, 1);
  ns_send(nc, &return_code, 1);
  ns_mqtt_prepend_header(nc, NS_MQTT_CMD_CONNACK, 0, 2);
}

/*
 * Sends a command which contains only a `message_id` and a QoS level of 1.
 *
 * Helper function.
 */
static void ns_send_mqtt_short_command(struct ns_connection *nc, uint8_t cmd,
                                       uint16_t message_id) {
  uint16_t message_id_net = htons(message_id);
  ns_send(nc, &message_id_net, 2);
  ns_mqtt_prepend_header(nc, cmd, NS_MQTT_QOS(1), 2);
}

void ns_mqtt_puback(struct ns_connection *nc, uint16_t message_id) {
  ns_send_mqtt_short_command(nc, NS_MQTT_CMD_PUBACK, message_id);
}

void ns_mqtt_pubrec(struct ns_connection *nc, uint16_t message_id) {
  ns_send_mqtt_short_command(nc, NS_MQTT_CMD_PUBREC, message_id);
}

void ns_mqtt_pubrel(struct ns_connection *nc, uint16_t message_id) {
  ns_send_mqtt_short_command(nc, NS_MQTT_CMD_PUBREL, message_id);
}

void ns_mqtt_pubcomp(struct ns_connection *nc, uint16_t message_id) {
  ns_send_mqtt_short_command(nc, NS_MQTT_CMD_PUBCOMP, message_id);
}

void ns_mqtt_suback(struct ns_connection *nc, uint8_t *qoss, size_t qoss_len,
                    uint16_t message_id) {
  size_t i;
  uint16_t message_id_net = htons(message_id);
  ns_send(nc, &message_id_net, 2);
  for (i = 0; i < qoss_len; i++) {
    ns_send(nc, &qoss[i], 1);
  }
  ns_mqtt_prepend_header(nc, NS_MQTT_CMD_SUBACK, NS_MQTT_QOS(1), 2 + qoss_len);
}

void ns_mqtt_unsuback(struct ns_connection *nc, uint16_t message_id) {
  ns_send_mqtt_short_command(nc, NS_MQTT_CMD_UNSUBACK, message_id);
}

void ns_mqtt_ping(struct ns_connection *nc) {
  ns_mqtt_prepend_header(nc, NS_MQTT_CMD_PINGREQ, 0, 0);
}

void ns_mqtt_pong(struct ns_connection *nc) {
  ns_mqtt_prepend_header(nc, NS_MQTT_CMD_PINGRESP, 0, 0);
}

void ns_mqtt_disconnect(struct ns_connection *nc) {
  ns_mqtt_prepend_header(nc, NS_MQTT_CMD_DISCONNECT, 0, 0);
}

#endif /* NS_DISABLE_MQTT */
