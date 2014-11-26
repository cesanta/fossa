/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

/*
 * == DNS API
 */

#ifndef NS_DISABLE_DNS

#include "internal.h"

#define MAX_DNS_PACKET_LEN  2048

static int ns_dns_tid = 0xa0;

struct ns_dns_header {
  uint16_t transaction_id;
  uint16_t flags;
  uint16_t num_questions;
  uint16_t num_answers;
  uint16_t num_authority_prs;
  uint16_t num_other_prs;
};

/*
 * Low-level: send a dns query to the remote end
 */
void ns_send_dns_query(struct ns_connection* nc, const char *name,
                       int query_type) {
  struct ns_dns_header header;
  const char *s;
  int n, name_len;
  uint16_t num;
  struct iobuf pkt;

  iobuf_init(&pkt, MAX_DNS_PACKET_LEN);

  memset(&header, 0, sizeof(header));
  header.transaction_id = ++ns_dns_tid;
  header.flags = htons(0x100);  /* recursion allowed */
  header.num_questions = htons(1);

  iobuf_append(&pkt, &header, sizeof(header));

  name_len = strlen(name);
  do {
    if ((s = strchr(name, '.')) == NULL)
      s = name + name_len;

    n = s - name;              /* chunk length */
    iobuf_append(&pkt, &n, 1); /* send length */
    iobuf_append(&pkt, name, n);

    if (*s == '.')
      n++;

    name += n;
    name_len -= n;
  } while (*s != '\0');
  iobuf_append(&pkt, "\0", 1);  /* Mark end of host name */

  num = htons(query_type);
  iobuf_append(&pkt, &num, 2);
  num = htons(0x0001);  /* Class: inet */
  iobuf_append(&pkt, &num, 2);

  /* TCP DNS requires messages to be prefixed with len */
  if (!(nc->flags & NSF_UDP)) {
    uint16_t len = htons(pkt.len);
    iobuf_prepend(&pkt, &len, 2);
  }

  ns_send(nc, pkt.buf, pkt.len);
  iobuf_free(&pkt);
}

static unsigned char *ns_parse_dns_resource_record(
    unsigned char *data, struct ns_dns_resource_record *rr, int reply) {
  unsigned char *name = data;
  int chunk_len, data_len;

  while((chunk_len = *data)) {
    if (((unsigned char *)data)[0] & 0xc0) {
      data += 1;
      break;
    }
    data += chunk_len + 1;
  }

  rr->name.p = (char *) name;
  rr->name.len = data-name+1;

  data++;

  rr->rtype = data[0] << 8 | data[1];
  data += 2;

  rr->rclass = data[0] << 8 | data[1];
  data += 2;

  if (reply) {
    rr->ttl = data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3];
    data += 4;

    data_len = *data << 8 | *(data+1);
    data += 2;

    rr->rdata.p = (char *) data;
    rr->rdata.len = data_len;
    data += data_len;
  }
  return data;
}

/* Low-level: parses a DNS response. */
int ns_parse_dns(const char *buf, int len, struct ns_dns_message *msg) {
  struct ns_dns_header *header = (struct ns_dns_header *) buf;
  unsigned char *data = (unsigned char *) buf + sizeof(*header);
  int i;
  msg->pkt = buf;

  if (len < (int)sizeof(*header)) {
    return -1;  /* LCOV_EXCL_LINE */
  }

  msg->num_questions = ntohs(header->num_questions);
  msg->num_answers = ntohs(header->num_answers);

  /* TODO(mkm): check bounds */

  for (i = 0; i < msg->num_questions
           && i < (int)ARRAY_SIZE(msg->questions); i++) {
    data = ns_parse_dns_resource_record(data, &msg->questions[i], 0);
  }

  for (i = 0; i < msg->num_answers
           && i < (int)ARRAY_SIZE(msg->answers); i++) {
    data = ns_parse_dns_resource_record(data, &msg->answers[i], 1);
  }

  return 0;
}

/*
 * Uncompress a DNS compressed name.
 *
 * The containing dns message is required because the compressed encoding
 * and reference suffixes present elsewhere in the packet.
 *
 * If name is less than `dst_len` characters long, the remainder
 * of `dst` is terminated with `\0' characters. Otherwise, `dst` is not terminated.
 *
 * If `dst_len` is 0 `dst` can be NULL.
 * Returns the uncompressed name length.
 */
size_t ns_dns_uncompress_name(struct ns_dns_message *msg, struct ns_str *name,
                              char *dst, int dst_len) {
  int chunk_len;
  char *old_dst = dst;
  const unsigned char *data = (unsigned char *) name->p;

  while((chunk_len = *data++)) {
    int leeway = dst_len - (dst - old_dst);
    if (chunk_len & 0xc0) {
      uint16_t off = (data[-1] & (~0xc0)) << 8 | data[0];
      data = (unsigned char *)msg->pkt + off;
      continue;
    }
    if (chunk_len > leeway) {
      chunk_len = leeway;
    }

    memcpy(dst, data, chunk_len);
    data += chunk_len;
    dst += chunk_len;
    leeway -= chunk_len;
    if (leeway == 0) {
      return dst - old_dst;
    }
    *dst++ = '.';
  }
  *--dst = 0;
  return dst - old_dst;
}

#endif  /* NS_DISABLE_DNS */
