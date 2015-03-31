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

/*
 * == CoAP
 */

#include "internal.h"

#ifdef NS_ENABLE_COAP

/*
 * CoAP implementation.
 *
 * General CoAP message format:
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
 * |Ver| T | TKL | Code | Message ID | Token (if any, TKL bytes) ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
 * | Options (if any) ...            |1 1 1 1 1 1 1 1| Payload (if any) ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
 */

#include "internal.h"
#include "iobuf.h"
#include "coap.h"

/*
 * Frees the memory allocated for options,
 * if cm paramater doesn't contain any option does nothing.
 */
void ns_coap_free_options(struct ns_coap_message *cm) {
  while (cm->options != NULL) {
    struct ns_coap_option *next = cm->options->next;
    NS_FREE(cm->options);
    cm->options = next;
  }
}

/*
 * Adds new option to ns_coap_message structure.
 * Returns pointer to the newly created option.
 */
struct ns_coap_option *ns_coap_add_option(struct ns_coap_message *cm,
                                          uint32_t number, char *value,
                                          size_t len) {
  struct ns_coap_option *new_option =
      (struct ns_coap_option *) NS_CALLOC(1, sizeof(*new_option));

  new_option->number = number;
  new_option->value.p = value;
  new_option->value.len = len;

  if (cm->options == NULL) {
    cm->options = cm->options_tail = new_option;
  } else {
    /*
     * A very simple attention to help clients to compose options:
     * CoAP wants to see options ASC ordered.
     * Could be change by using sort in coap_compose
     */
    if (cm->options_tail->number <= new_option->number) {
      /* if option is already ordered just add it */
      cm->options_tail = cm->options_tail->next = new_option;
    } else {
      /* looking for appropriate position */
      struct ns_coap_option *current_opt = cm->options;
      struct ns_coap_option *prev_opt = 0;

      while (current_opt != NULL) {
        if (current_opt->number > new_option->number) {
          break;
        }
        prev_opt = current_opt;
        current_opt = current_opt->next;
      }

      if (prev_opt != NULL) {
        prev_opt->next = new_option;
        new_option->next = current_opt;
      } else {
        /* insert new_option to the beginning */
        new_option->next = cm->options;
        cm->options = new_option;
      }
    }
  }

  return new_option;
}

/*
 * Fills CoAP header in ns_coap_message.
 *
 * Helper function.
 */
static char *coap_parse_header(char *ptr, struct iobuf *io,
                               struct ns_coap_message *cm) {
  if (io->len < sizeof(uint32_t)) {
    cm->flags |= NS_COAP_NOT_ENOUGH_DATA;
    return NULL;
  }

  /*
   * Version (Ver):  2-bit unsigned integer.  Indicates the CoAP version
   * number.  Implementations of this specification MUST set this field
   * to 1 (01 binary).  Other values are reserved for future versions.
   * Messages with unknown version numbers MUST be silently ignored.
   */
  if (((uint8_t) *ptr >> 6) != 1) {
    cm->flags |= NS_COAP_IGNORE;
    return NULL;
  }

  /*
   * Type (T):  2-bit unsigned integer.  Indicates if this message is of
   * type Confirmable (0), Non-confirmable (1), Acknowledgement (2), or
   * Reset (3).
   */
  cm->msg_type = ((uint8_t) *ptr & 0x30) >> 4;
  cm->flags |= NS_COAP_MSG_TYPE_FIELD;

  /*
   * Token Length (TKL):  4-bit unsigned integer.  Indicates the length of
   * the variable-length Token field (0-8 bytes).  Lengths 9-15 are
   * reserved, MUST NOT be sent, and MUST be processed as a message
   * format error.
   */
  cm->token.len = *ptr & 0x0F;
  if (cm->token.len > 8) {
    cm->flags |= NS_COAP_FORMAT_ERROR;
    return NULL;
  }

  ptr++;

  /*
   * Code:  8-bit unsigned integer, split into a 3-bit class (most
   * significant bits) and a 5-bit detail (least significant bits)
   */
  cm->code_class = (uint8_t) *ptr >> 5;
  cm->code_detail = *ptr & 0x1F;
  cm->flags |= (NS_COAP_CODE_CLASS_FIELD | NS_COAP_CODE_DETAIL_FIELD);

  ptr++;

  /* Message ID:  16-bit unsigned integer in network byte order. */
  cm->msg_id = (uint8_t) *ptr << 8 | (uint8_t) * (ptr + 1);
  cm->flags |= NS_COAP_MSG_ID_FIELD;

  ptr += 2;

  return ptr;
}

/*
 * Fills token information in ns_coap_message.
 *
 * Helper function.
 */
static char *coap_get_token(char *ptr, struct iobuf *io,
                            struct ns_coap_message *cm) {
  if (cm->token.len != 0) {
    if (ptr + cm->token.len > io->buf + io->len) {
      cm->flags |= NS_COAP_NOT_ENOUGH_DATA;
      return NULL;
    } else {
      cm->token.p = ptr;
      ptr += cm->token.len;
      cm->flags |= NS_COAP_TOKEN_FIELD;
    }
  }

  return ptr;
}

/*
 * Returns Option Delta or Length.
 *
 * Helper function.
 */
static int coap_get_ext_opt(char *ptr, struct iobuf *io, uint16_t *opt_info) {
  int ret = 0;

  if (*opt_info == 13) {
    /*
     * 13:  An 8-bit unsigned integer follows the initial byte and
     * indicates the Option Delta/Length minus 13.
     */
    if (ptr < io->buf + io->len) {
      *opt_info = (uint8_t) *ptr + 13;
      ret = sizeof(uint8_t);
    } else {
      ret = -1; /* LCOV_EXCL_LINE */
    }
  } else if (*opt_info == 14) {
    /*
     * 14:  A 16-bit unsigned integer in network byte order follows the
     * initial byte and indicates the Option Delta/Length minus 269.
     */
    if (ptr + sizeof(uint8_t) < io->buf + io->len) {
      *opt_info = ((uint8_t) *ptr << 8 | (uint8_t) * (ptr + 1)) + 269;
      ret = sizeof(uint16_t);
    } else {
      ret = -1; /* LCOV_EXCL_LINE */
    }
  }

  return ret;
}

/*
 * Fills options in ns_coap_message.
 *
 * Helper function.
 *
 * General options format:
 * +---------------+---------------+
 * | Option Delta  | Option Length |  1 byte
 * +---------------+---------------+
 * \    Option Delta (extended)    \  0-2 bytes
 * +-------------------------------+
 * / Option Length  (extended)     \  0-2 bytes
 * +-------------------------------+
 * \         Option Value          \  0 or more bytes
 * +-------------------------------+
 */
static char *coap_get_options(char *ptr, struct iobuf *io,
                              struct ns_coap_message *cm) {
  uint16_t prev_opt = 0;

  if (ptr == io->buf + io->len) {
    /* end of packet, ok */
    return NULL;
  }

  /* 0xFF is payload marker */
  while (ptr < io->buf + io->len && (uint8_t) *ptr != 0xFF) {
    uint16_t option_delta, option_lenght;
    int optinfo_len;

    /* Option Delta:  4-bit unsigned integer */
    option_delta = ((uint8_t) *ptr & 0xF0) >> 4;
    /* Option Length:  4-bit unsigned integer */
    option_lenght = *ptr & 0x0F;

    if (option_delta == 15 || option_lenght == 15) {
      /*
       * 15:  Reserved for future use.  If the field is set to this value,
       * it MUST be processed as a message format error
       */
      cm->flags |= NS_COAP_FORMAT_ERROR;
      break;
    }

    ptr++;

    /* check for extended option delta */
    optinfo_len = coap_get_ext_opt(ptr, io, &option_delta);
    if (optinfo_len == -1) {
      cm->flags |= NS_COAP_NOT_ENOUGH_DATA; /* LCOV_EXCL_LINE */
      break;                                /* LCOV_EXCL_LINE */
    }

    ptr += optinfo_len;

    /* check or extended option lenght */
    optinfo_len = coap_get_ext_opt(ptr, io, &option_lenght);
    if (optinfo_len == -1) {
      cm->flags |= NS_COAP_NOT_ENOUGH_DATA; /* LCOV_EXCL_LINE */
      break;                                /* LCOV_EXCL_LINE */
    }

    ptr += optinfo_len;

    /*
     * Instead of specifying the Option Number directly, the instances MUST
     * appear in order of their Option Numbers and a delta encoding is used
     * between them.
     */
    option_delta += prev_opt;

    ns_coap_add_option(cm, option_delta, ptr, option_lenght);

    prev_opt = option_delta;

    if (ptr + option_lenght > io->buf + io->len) {
      cm->flags |= NS_COAP_NOT_ENOUGH_DATA; /* LCOV_EXCL_LINE */
      break;                                /* LCOV_EXCL_LINE */
    }

    ptr += option_lenght;
  }

  if ((cm->flags & NS_COAP_ERROR) != 0) {
    ns_coap_free_options(cm);
    return NULL;
  }

  cm->flags |= NS_COAP_OPTIONS_FIELD;

  if (ptr == io->buf + io->len) {
    /* end of packet, ok */
    return NULL;
  }

  ptr++;

  return ptr;
}

/*
 * Parses COAP message and fills ns_coap_message and returns cm->flags.
 *
 * Note: usually CoAP work over UDP, so
 * lack of data means format error,
 * but in theory it is possible to use CoAP over TCP
 * (behind its RFC)
 * Caller have to check results and
 * threat COAP_NOT_ENOUGH_DATA according to
 * underlying protocol:
 * in case of UDP COAP_NOT_ENOUGH_DATA means COAP_FORMAT_ERROR,
 * in case of TCP client can try to recieve more data
 *
 * Helper function.
 */
uint32_t ns_coap_parse(struct iobuf *io, struct ns_coap_message *cm) {
  char *ptr;

  memset(cm, 0, sizeof(*cm));

  if ((ptr = coap_parse_header(io->buf, io, cm)) == NULL) {
    return cm->flags;
  }

  if ((ptr = coap_get_token(ptr, io, cm)) == NULL) {
    return cm->flags;
  }

  if ((ptr = coap_get_options(ptr, io, cm)) == NULL) {
    return cm->flags;
  }

  /* the rest is payload */
  cm->payload.len = io->len - (ptr - io->buf);
  if (cm->payload.len != 0) {
    cm->payload.p = ptr;
    cm->flags |= NS_COAP_PAYLOAD_FIELD;
  }

  return cm->flags;
}

/*
 * Calculates extended size of given Opt Number/Length in coap message.
 *
 * Helper function.
 */
static size_t coap_get_ext_opt_size(uint32_t value) {
  int ret = 0;

  if (value >= 13 && value <= 0xFF + 13) {
    ret = sizeof(uint8_t);
  } else if (value > 0xFF + 13 && value <= 0xFFFF + 269) {
    ret = sizeof(uint16_t);
  }

  return ret;
}

/*
 * Splits given Opt Number/Length into base and ext values.
 *
 * Helper function.
 */
static int coap_split_opt(uint32_t value, uint8_t *base, uint16_t *ext) {
  int ret = 0;

  if (value < 13) {
    *base = value;
  } else if (value >= 13 && value <= 0xFF + 13) {
    *base = 13;
    *ext = value - 13;
    ret = sizeof(uint8_t);
  } else if (value > 0xFF + 13 && value <= 0xFFFF + 269) {
    *base = 14;
    *ext = value - 269;
    ret = sizeof(uint16_t);
  }

  return ret;
}

/*
 * Puts uint16_t (in network order) into given char stream.
 *
 * Helper function.
 */
static char *coap_add_uint16(char *ptr, uint16_t val) {
  *ptr = val >> 8;
  ptr++;
  *ptr = val & 0x00FF;
  ptr++;
  return ptr;
}

/*
 * Puts extended value of Opt Number/Length into given char stream.
 *
 * Helper function.
 */
static char *coap_add_opt_info(char *ptr, uint16_t val, size_t len) {
  if (len == sizeof(uint8_t)) {
    *ptr = val;
    ptr++;
  } else if (len == sizeof(uint16_t)) {
    ptr = coap_add_uint16(ptr, val);
  }

  return ptr;
}

/*
 * Verifies given ns_coap_message and calculates message size for it.
 *
 * Helper function.
 */
static uint32_t coap_calculate_packet_size(struct ns_coap_message *cm,
                                           size_t *len) {
  struct ns_coap_option *opt;
  uint32_t prev_opt_number;

  *len = 4; /* header */
  if (cm->msg_type > NS_COAP_MSG_MAX) {
    return NS_COAP_ERROR | NS_COAP_MSG_TYPE_FIELD;
  }
  if (cm->token.len > 8) {
    return NS_COAP_ERROR | NS_COAP_TOKEN_FIELD;
  }
  if (cm->code_class > 7) {
    return NS_COAP_ERROR | NS_COAP_CODE_CLASS_FIELD;
  }
  if (cm->code_detail > 31) {
    return NS_COAP_ERROR | NS_COAP_CODE_DETAIL_FIELD;
  }

  *len += cm->token.len;
  if (cm->payload.len != 0) {
    *len += cm->payload.len + 1; /* ... + 1; add payload marker */
  }

  opt = cm->options;
  prev_opt_number = 0;
  while (opt != NULL) {
    *len += 1; /* basic delta/length */
    *len += coap_get_ext_opt_size(opt->number);
    *len += coap_get_ext_opt_size((uint32_t) opt->value.len);
    /*
     * Current implementation performs check if
     * option_number > previous option_number and produces an error
     * TODO(alashkin): write design doc with limitations
     * May be resorting is more suitable solution.
     */
    if ((opt->next != NULL && opt->number > opt->next->number) ||
        opt->value.len > 0xFFFF + 269 ||
        opt->number - prev_opt_number > 0xFFFF + 269) {
      return NS_COAP_ERROR | NS_COAP_OPTIONS_FIELD;
    }
    *len += opt->value.len;
    opt = opt->next;
  }

  return 0;
}

/*
 * Composes CoAP message from ns_coap_message structure.
 * Returns 0 on success or bit mask with wrong field.
 *
 * Helper function.
 */
uint32_t ns_coap_compose(struct ns_coap_message *cm, struct iobuf *io) {
  struct ns_coap_option *opt;
  uint32_t res, prev_opt_number;
  size_t prev_io_len, packet_size;
  char *ptr;

  res = coap_calculate_packet_size(cm, &packet_size);
  if (res != 0) {
    return res;
  }

  /* saving previous lenght to handle non-empty iobuf */
  prev_io_len = io->len;
  iobuf_append(io, NULL, packet_size);
  ptr = io->buf + prev_io_len;

  /*
   * since cm is verified, it is possible to use bits shift operator
   * without additional zeroing of unused bits
   */

  /* ver: 2 bits, msg_type: 2 bits, toklen: 4 bits */
  *ptr = (1 << 6) | (cm->msg_type << 4) | (cm->token.len);
  ptr++;

  /* code class: 3 bits, code detail: 5 bits */
  *ptr = (cm->code_class << 5) | (cm->code_detail);
  ptr++;

  ptr = coap_add_uint16(ptr, cm->msg_id);

  if (cm->token.len != 0) {
    memcpy(ptr, cm->token.p, cm->token.len);
    ptr += cm->token.len;
  }

  opt = cm->options;
  prev_opt_number = 0;
  while (opt != NULL) {
    uint8_t delta_base = 0, length_base = 0;
    uint16_t delta_ext, length_ext;

    size_t opt_delta_len =
        coap_split_opt(opt->number - prev_opt_number, &delta_base, &delta_ext);
    size_t opt_lenght_len =
        coap_split_opt((uint32_t) opt->value.len, &length_base, &length_ext);

    *ptr = (delta_base << 4) | length_base;
    ptr++;

    ptr = coap_add_opt_info(ptr, delta_ext, opt_delta_len);
    ptr = coap_add_opt_info(ptr, length_ext, opt_lenght_len);

    if (opt->value.len != 0) {
      memcpy(ptr, opt->value.p, opt->value.len);
      ptr += opt->value.len;
    }

    prev_opt_number = opt->number;
    opt = opt->next;
  }

  if (cm->payload.len != 0) {
    *ptr = 0xFF;
    ptr++;
    memcpy(ptr, cm->payload.p, cm->payload.len);
  }

  return 0;
}

/*
 * Composes CoAP message from ns_coap_message
 * and sends it into 'nc' connection.
 */
uint32_t ns_coap_send_message(struct ns_connection *nc,
                              struct ns_coap_message *cm) {
  struct iobuf packet_out;
  int send_res;
  uint32_t compose_res;

  iobuf_init(&packet_out, 0);
  compose_res = ns_coap_compose(cm, &packet_out);
  if (compose_res != 0) {
    return compose_res; /* LCOV_EXCL_LINE */
  }

  send_res = ns_send(nc, packet_out.buf, (int) packet_out.len);
  iobuf_free(&packet_out);

  if (send_res == 0) {
    /*
     * in case of UDP ns_send tries to send immediately
     * and could return an error.
     */
    return NS_COAP_NETWORK_ERROR; /* LCOV_EXCL_LINE */
  }

  return 0;
}

/*
 * Composes CoAP acknolegement from ns_coap_message
 * and sends it into 'nc' connection.
 */
uint32_t ns_coap_send_ack(struct ns_connection *nc, uint16_t msg_id) {
  struct ns_coap_message cm;
  memset(&cm, 0, sizeof(cm));
  cm.msg_type = NS_COAP_MSG_ACK;
  cm.msg_id = msg_id;

  return ns_coap_send_message(nc, &cm);
}

static void coap_handler(struct ns_connection *nc, int ev, void *ev_data) {
  struct iobuf *io = &nc->recv_iobuf;
  struct ns_coap_message cm;
  uint32_t parse_res;

  memset(&cm, 0, sizeof(cm));

  nc->handler(nc, ev, ev_data);

  switch (ev) {
    case NS_RECV:
      parse_res = ns_coap_parse(io, &cm);
      if ((parse_res & NS_COAP_IGNORE) == 0) {
        if ((cm.flags & NS_COAP_NOT_ENOUGH_DATA) != 0) {
          /*
           * Since we support UDP only
           * NS_COAP_NOT_ENOUGH_DATA == NS_COAP_FORMAT_ERROR
           */
          cm.flags |= NS_COAP_FORMAT_ERROR; /* LCOV_EXCL_LINE */
        }                                   /* LCOV_EXCL_LINE */
        nc->handler(nc, NS_COAP_EVENT_BASE + cm.msg_type, &cm);
      }

      ns_coap_free_options(&cm);
      iobuf_remove(io, io->len);
      break;
  }
}
/*
 * Attach built-in CoAP event handler to the given connection.
 *
 * The user-defined event handler will receive following extra events:
 *
 * - NS_COAP_CON
 * - NS_COAP_NOC
 * - NS_COAP_ACK
 * - NS_COAP_RST
 */
int ns_set_protocol_coap(struct ns_connection *nc) {
  /* supports UDP only */
  if ((nc->flags & NSF_UDP) == 0) {
    return -1;
  }

  nc->proto_handler = coap_handler;

  return 0;
}

#endif /* NS_DISABLE_COAP */
