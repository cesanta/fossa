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
 * license, as set out in <http://cesanta.com/>.
 */

#ifndef NS_MQTT_HEADER_INCLUDED
#define NS_MQTT_HEADER_INCLUDED

struct ns_mqtt_message {
  int cmd;
  int payload_len;
  int qos;
  uint8_t connack_ret_code; /* connack */
  uint16_t message_id;      /* puback */
  char *topic;
};

struct ns_mqtt_topic_expression {
  const char *topic;
  uint8_t qos;
};

struct ns_send_mqtt_handshake_opts {
  unsigned char flags; /* connection flags */
  uint16_t keep_alive;
  const char *will_topic;
  const char *will_message;
  const char *user_name;
  const char *password;
};

/* Message types */
#define NS_MQTT_CMD_CONNECT   1
#define NS_MQTT_CMD_CONNACK   2
#define NS_MQTT_CMD_PUBLISH   3
#define NS_MQTT_CMD_PUBACK    4
#define NS_MQTT_CMD_PUBREC    5
#define NS_MQTT_CMD_PUBREL    6
#define NS_MQTT_CMD_PUBCOMP   7
#define NS_MQTT_CMD_SUBSCRIBE 8
#define NS_MQTT_CMD_SUBACK    9

/* MQTT event types */
#define NS_MQTT_EVENT_BASE 200
#define NS_MQTT_CONNECT (NS_MQTT_EVENT_BASE + NS_MQTT_CMD_CONNECT)
#define NS_MQTT_CONNACK (NS_MQTT_EVENT_BASE + NS_MQTT_CMD_CONNACK)
#define NS_MQTT_PUBLISH (NS_MQTT_EVENT_BASE + NS_MQTT_CMD_PUBLISH)
#define NS_MQTT_PUBACK  (NS_MQTT_EVENT_BASE + NS_MQTT_CMD_PUBACK)
#define NS_MQTT_PUBREC  (NS_MQTT_EVENT_BASE + NS_MQTT_CMD_PUBREC)
#define NS_MQTT_PUBREL  (NS_MQTT_EVENT_BASE + NS_MQTT_CMD_PUBREL)
#define NS_MQTT_PUBCOMP (NS_MQTT_EVENT_BASE + NS_MQTT_CMD_PUBCOMP)
#define NS_MQTT_SUBSCRIBE (NS_MQTT_EVENT_BASE + NS_MQTT_CMD_SUBSCRIBE)
#define NS_MQTT_SUBACK (NS_MQTT_EVENT_BASE + NS_MQTT_CMD_SUBACK)

/* Message flags */
#define NS_MQTT_RETAIN 0x1
#define NS_MQTT_DUP 0x4
#define NS_MQTT_QOS(qos) ((qos) << 1)
#define NS_MQTT_GET_QOS(flags) (((flags) & 0x6) >> 1)
#define NS_MQTT_SET_QOS(flags, qos) (flags) = ((flags) & ~0x6) | ((qos) << 1)

/* Connection flags */
#define NS_MQTT_CLEAN_SESSION 0x02
#define NS_MQTT_HAS_WILL      0x04
#define NS_MQTT_WILL_RETAIN   0x20
#define NS_MQTT_HAS_PASSWORD  0x40
#define NS_MQTT_HAS_USER_NAME 0x80
#define NS_MQTT_GET_WILL_QOS(flags) (((flags) & 0x18) >> 3)
#define NS_MQTT_SET_WILL_QOS(flags, qos) (flags) = \
      ((flags) & ~0x18) | ((qos) << 3)

/* CONNACK return codes */
#define NS_MQTT_CONNACK_ACCEPTED             0
#define NS_MQTT_CONNACK_UNACCEPTABLE_VERSION 1
#define NS_MQTT_CONNACK_IDENTIFIER_REJECTED  2
#define NS_MQTT_CONNACK_SERVER_UNAVAILABLE   3
#define NS_MQTT_CONNACK_BAD_AUTH             4
#define NS_MQTT_CONNACK_NOT_AUTHORIZED       5

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

void ns_set_protocol_mqtt(struct ns_connection *);
void ns_send_mqtt_handshake(struct ns_connection *, const char *);
void ns_send_mqtt_handshake_opt(struct ns_connection *, const char *,
                                struct ns_send_mqtt_handshake_opts);

void ns_mqtt_publish(struct ns_connection *, const char *, uint16_t, int,
                     const void *, size_t);
void ns_mqtt_subscribe(struct ns_connection *,
                       const struct ns_mqtt_topic_expression *, size_t,
                       uint16_t);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* NS_MQTT_HEADER_INCLUDED */
