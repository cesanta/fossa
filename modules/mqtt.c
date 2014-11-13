/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

/*
 * == MQTT
 */

#ifndef NS_DISABLE_MQTT

#include "fossa.h"
#include "internal.h"

static int parse_mqtt(struct iobuf *io, struct ns_mqtt_message *mm) {
  uint8_t header;
  int cmd;
  uint8_t len;
  int var_len;

  if (io->len < 2) return -1;

  header = io->buf[0];
  cmd = header >> 4;
  len = io->buf[1];  /* TODO(mkm) implement variable length decoding */
  var_len = 0;

  if (io->len < (size_t)(len - 1)) return -1;

  iobuf_remove(io, 2);
  mm->cmd = cmd;
  mm->qos = NS_MQTT_GET_QOS(header);

  switch (cmd) {
    case NS_MQTT_CMD_CONNACK:
      mm->connack_ret_code = io->buf[1];
      var_len = 2;
      break;
    case NS_MQTT_CMD_PUBACK:
    case NS_MQTT_CMD_PUBREC:
    case NS_MQTT_CMD_PUBREL:
    case NS_MQTT_CMD_PUBCOMP:
    case NS_MQTT_CMD_SUBACK:
      mm->message_id = ntohs(*(uint16_t*)io->buf);
      var_len = 2;
      break;
    case NS_MQTT_CMD_PUBLISH:
      {
        uint16_t topic_len = ntohs(*(uint16_t*)io->buf);
        mm->topic = (char *) NS_MALLOC(topic_len + 1);
        mm->topic[topic_len] = 0;
        strncpy(mm->topic, io->buf + 2, topic_len);
        var_len = topic_len + 2;

        /*
         * TODO(mkm) it's not clear if this can happen
         * The PUBLISH cmd is used for both client->server
         * and server->client, but the message id seems to be only
         * legal client->server while here we are parsing server->client.
         */
        if (NS_MQTT_GET_QOS(header) > 0) {
          mm->message_id = ntohs(*(uint16_t*)io->buf);
          var_len += 2;
        }
      }
      break;
    default:
      printf("TODO: UNHANDLED COMMAND %d\n", cmd);
      break;
  }

  iobuf_remove(io, var_len);
  return len - var_len;
}

static void mqtt_handler(struct ns_connection *nc, int ev, void *ev_data) {
  struct iobuf *io = &nc->recv_iobuf;
  struct ns_mqtt_message mm;
  memset(&mm, 0, sizeof(mm));

  nc->handler(nc, ev, ev_data);

  switch (ev) {
    case NS_RECV:
      mm.payload_len = parse_mqtt(io, &mm);
      if (mm.payload_len == -1) break; /* not fully buffered */

      nc->handler(nc, NS_MQTT_EVENT_BASE + mm.cmd, &mm);

      if (mm.topic) {
        NS_FREE(mm.topic);
      }
      iobuf_remove(io, mm.payload_len);
      break;
    default:
      break;
  }
}

/*
 * Attach built-in MQTT event handler to the given connection.
 *
 * The user-defined event handler will receive following extra events:
 *
 * - NS_MQTT_CONNACK
 * - NS_MQTT_PUBLISH
 * - NS_MQTT_PUBACK
 * - NS_MQTT_PUBREC
 * - NS_MQTT_PUBREL
 * - NS_MQTT_PUBCOMP
 * - NS_MQTT_SUBACK
*/
void ns_set_protocol_mqtt(struct ns_connection *nc) {
  nc->proto_handler = mqtt_handler;
}

/* Send MQTT handshake. */
void ns_send_mqtt_handshake(struct ns_connection *nc, const char *client_id) {
  static struct ns_send_mqtt_handshake_opts opts;
  ns_send_mqtt_handshake_opt(nc, client_id, opts);
}

void ns_send_mqtt_handshake_opt(struct ns_connection *nc, const char *client_id, struct ns_send_mqtt_handshake_opts opts) {
  uint8_t header = NS_MQTT_CMD_CONNECT << 4;
  uint8_t rem_len;
  uint16_t keep_alive;
  uint16_t client_id_len;

  /*
   * 9: version_header(len, magic_string, version_number), 1: flags, 2: keep-alive timer,
   * 2: client_identifier_len, n: client_id
   */
  rem_len = 9+1+2+2+strlen(client_id);

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

/* Publish a message to a given channel. */
void ns_mqtt_publish(struct ns_connection *nc, const char *topic,
                     uint16_t message_id, int flags,
                     const void *data, size_t len) {
  uint8_t header = NS_MQTT_CMD_PUBLISH << 4 | (uint8_t)flags;
  uint8_t rem_len = len + strlen(topic) + 2;
  uint16_t topic_len = htons(strlen(topic));
  uint16_t message_id_n = htons(message_id);

  uint8_t qos = NS_MQTT_GET_QOS(flags);
  if (qos > 0) rem_len += 2;

  ns_send(nc, &header, 1);
  ns_send(nc, &rem_len, 1); /* TODO(mkm) implement variable length encoding */
  ns_send(nc, &topic_len, 2);
  ns_send(nc, topic, strlen(topic));

  if (qos > 0)
    ns_send(nc, &message_id_n, 2);

  ns_send(nc, data, len);
}

/* Subscribe to a given channel. */
void ns_mqtt_subscribe(struct ns_connection *nc,
                       const struct ns_mqtt_topic_expression *topics,
                       size_t topics_len, uint16_t message_id) {
  uint8_t header = NS_MQTT_CMD_SUBSCRIBE << 4 | NS_MQTT_QOS(1);
  uint8_t rem_len = 2;
  uint16_t message_id_n = htons(message_id);
  uint16_t topic_len_n;

  size_t i;
  for (i=0; i<topics_len; i++)
    rem_len += 2 + strlen(topics[i].topic) + 1;

  ns_send(nc, &header, 1);
  ns_send(nc, &rem_len, 1); /* TODO(mkm) implement variable length encoding */
  ns_send(nc, &message_id_n, 2);

  for (i=0; i<topics_len; i++) {
    topic_len_n = htons(strlen(topics[i].topic));
    ns_send(nc, &topic_len_n, 2);
    ns_send(nc, topics[i].topic, strlen(topics[i].topic));
    ns_send(nc, &topics[i].qos, 1);
  }
}

#endif  /* NS_DISABLE_MQTT */
