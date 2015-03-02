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

/* TODO(alashkin): remove this #include after dev completion */
#include <stdlib.h>
#include "internal.h"
#include "coap.h"

/* Options memory management functions */
void ns_coap_free_options(struct ns_coap_message *cm) {
  while (cm->options != NULL) {
    struct ns_coap_option *next = cm->options->next;
    NS_FREE(cm->options);
    cm->options = next;
  }
}

void ns_coap_add_option(struct ns_coap_message *cm,
                        uint16_t number, char* value, size_t len) {
  struct ns_coap_option *option =
      (struct ns_coap_option *)NS_CALLOC(1, sizeof(*option));

  option->number = number;
  option->value.p = value;
  option->value.len = len;

  if (cm->options == NULL) {
    cm->options = cm->options_tail = option;
  } else {
    cm->options_tail = cm->options_tail->next = option;
  }
}

/* Fills CoAP header in cm. */
static char *coap_parse_header(char* ptr, struct iobuf *io,
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
  if (((uint8_t)*ptr >> 6) != 1) {
    cm->flags |= NS_COAP_IGNORE;
    return NULL;
  }

  /*
   * Type (T):  2-bit unsigned integer.  Indicates if this message is of
   * type Confirmable (0), Non-confirmable (1), Acknowledgement (2), or
   * Reset (3).
   */
  cm->msg_type = ((uint8_t)*ptr & 0x30) >> 4;
  if (cm->msg_type > NS_COAP_MSG_MAX) {
    cm->flags |= NS_COAP_FORMAT_ERROR;
    return NULL;
  }
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
  cm->code_class = (uint8_t)*ptr >> 5;
  cm->code_detail = *ptr & 0x1F;
  cm->flags |= (NS_COAP_CODE_CLASS_FIELD | NS_COAP_CODE_DETAIL_FIELD);

  ptr++;

  /* Message ID:  16-bit unsigned integer in network byte order. */
  cm->msg_id = (uint8_t)*ptr << 8 | (uint8_t)*(ptr + 1);
  cm->flags |= NS_COAP_MSG_ID_FIELD;

  ptr += 2;

  return ptr;
}

/* Fulls token information in cm */
static char *coap_get_token(char *ptr, struct iobuf *io,
                            struct ns_coap_message *cm) {
  if (cm->token.len != 0) {
    if (ptr + cm->token.len > io->buf + io->len ) {
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

/* Returns Option Delta or Length. Helper function. */
static int coap_get_ext_opt(char* ptr, struct iobuf *io, uint16_t* opt_info) {
  int ret = 0;

  if (*opt_info == 13) {
    /*
     * 13:  An 8-bit unsigned integer follows the initial byte and
     * indicates the Option Delta/Length minus 13.
     */
    if (ptr < io->buf + io->len) {
      *opt_info = (uint8_t)*ptr + 13;
      ret = sizeof(uint8_t);
    } else {
      ret = -1;
    }
  } else if (*opt_info == 14) {
    /*
     * 14:  A 16-bit unsigned integer in network byte order follows the
     * initial byte and indicates the Option Delta/Length minus 269.
     */
    if (ptr + sizeof(uint8_t) < io->buf + io->len) {
      *opt_info = ((uint8_t)*ptr << 8 | (uint8_t)*(ptr + 1)) + 269;
      ret = sizeof(uint16_t);
    } else {
      ret = -1;
    }
  }

  return ret;
}

/* 
 * Fills options in cm.
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
static char *coap_get_options(char* ptr, struct iobuf *io,
                              struct ns_coap_message *cm) {
  uint16_t prev_opt = 0;

  if (ptr == io->buf + io->len) {
    /* end of packet, ok */
    return NULL;
  }

  /* 0xFF is payload marker */
  while ((uint8_t)*ptr != 0xFF && ptr < io->buf + io->len) {
    uint16_t option_delta, option_lenght;
    int optinfo_len;

    /* Option Delta:  4-bit unsigned integer */
    option_delta = ((uint8_t)*ptr & 0xF0) >> 4;
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
      cm->flags |= NS_COAP_NOT_ENOUGH_DATA;
      break;
    }

    ptr += optinfo_len;

    /* check or extended option lenght */
    optinfo_len = coap_get_ext_opt(ptr, io, &option_lenght);
    if (optinfo_len == -1) {
      cm->flags |= NS_COAP_NOT_ENOUGH_DATA;
      break;
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
      cm->flags |= NS_COAP_NOT_ENOUGH_DATA;
      break;
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
 * Parses COAP message and fills cm and returns cm->flags.
 *
 * Note: usually CoAP work over UDP, so
 * lack of data means format error,
 * but in theory it is possible to use CoAP over TCP
 * (behind its RFC)
 * Caller have to check results and
 * threat COAP_NOT_ENOUGH_DATA according to
 * underlaying protocol
 * in case of UDP COAP_NOT_ENOUGH_DATA means COAP_FORMAT_ERROR
 * in case of TCP client can try to recieve more data
 */
NS_INTERNAL uint32_t coap_parse(struct iobuf *io, struct ns_coap_message *cm) {
  char* ptr;

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

#endif  /* NS_ENABLE_COAP */
