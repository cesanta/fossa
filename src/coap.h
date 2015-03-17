/*
 * Copyright (c) 2015 Cesanta Software Limited
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

#ifndef NS_COAP_HEADER_INCLUDED
#define NS_COAP_HEADER_INCLUDED

#ifdef NS_ENABLE_COAP

#include "internal.h"

#define NS_COAP_MSG_TYPE_FIELD 0x2
#define NS_COAP_CODE_CLASS_FIELD 0x4
#define NS_COAP_CODE_DETAIL_FIELD 0x8
#define NS_COAP_MSG_ID_FIELD 0x10
#define NS_COAP_TOKEN_FIELD 0x20
#define NS_COAP_OPTIONS_FIELD 0x40
#define NS_COAP_PAYLOAD_FIELD 0x80

#define NS_COAP_ERROR 0x10000
#define NS_COAP_FORMAT_ERROR (NS_COAP_ERROR | 0x20000)
#define NS_COAP_IGNORE (NS_COAP_ERROR | 0x40000)
#define NS_COAP_NOT_ENOUGH_DATA (NS_COAP_ERROR | 0x80000)
#define NS_COAP_NETWORK_ERROR (NS_COAP_ERROR | 0x100000)

#define NS_COAP_MSG_CON 0
#define NS_COAP_MSG_NOC 1
#define NS_COAP_MSG_ACK 2
#define NS_COAP_MSG_RST 3
#define NS_COAP_MSG_MAX 3

#define NS_COAP_CODECLASS_REQUEST 0
#define NS_COAP_CODECLASS_RESP_OK 2
#define NS_COAP_CODECLASS_CLIENT_ERR 4
#define NS_COAP_CODECLASS_SRV_ERR 5

#define NS_COAP_EVENT_BASE 300
#define NS_COAP_CON (NS_COAP_EVENT_BASE + NS_COAP_MSG_CON)
#define NS_COAP_NOC (NS_COAP_EVENT_BASE + NS_COAP_MSG_NOC)
#define NS_COAP_ACK (NS_COAP_EVENT_BASE + NS_COAP_MSG_ACK)
#define NS_COAP_RST (NS_COAP_EVENT_BASE + NS_COAP_MSG_RST)

/*
 * CoAP options.
 * Use ns_coap_add_option and ns_coap_free_options
 * for creation and destruction.
 */
struct ns_coap_option {
  struct ns_coap_option *next;
  uint32_t number;
  struct ns_str value;
};

/* CoAP message. See RFC 7252 for details. */
struct ns_coap_message {
  uint32_t flags;
  uint8_t msg_type;
  uint8_t code_class;
  uint8_t code_detail;
  uint16_t msg_id;
  struct ns_str token;
  struct ns_coap_option *options;
  struct ns_str payload;
  struct ns_coap_option *options_tail;
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

void ns_coap_free_options(struct ns_coap_message *cm);
struct ns_coap_option *ns_coap_add_option(struct ns_coap_message *cm,
                                          uint32_t number, char *value,
                                          size_t len);
int ns_set_protocol_coap(struct ns_connection *nc);
uint32_t ns_coap_send_ack(struct ns_connection *nc, uint16_t msg_id);
uint32_t ns_coap_send_message(struct ns_connection *nc,
                              struct ns_coap_message *cm);

uint32_t ns_coap_parse(struct iobuf *io, struct ns_coap_message *cm);
uint32_t ns_coap_compose(struct ns_coap_message *cm, struct iobuf *io);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* NS_ENABLE_COAP */

#endif /* NS_COAP_HEADER_INCLUDED */
