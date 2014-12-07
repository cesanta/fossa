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

struct ns_dns_resource_record *ns_dns_next_record(
    struct ns_dns_message *msg, int query,
    struct ns_dns_resource_record *prev) {
  struct ns_dns_resource_record *rr;

  for (rr = (prev == NULL ? msg->answers : prev + 1);
       rr - msg->answers < msg->num_answers; rr++) {
    if (rr->rtype == query) {
      return rr;
    }
  }
  return NULL;
}

/*
 * Parses the record data from a DNS resource record.
 *
 *  - A:     struct in_addr *ina
 *  - AAAA:  struct in6_addr *ina
 *  - CNAME: char buffer
 *
 * Returns -1 on error.
 *
 * TODO(mkm): MX
 */
int ns_dns_parse_record_data(struct ns_dns_message *msg,
                             struct ns_dns_resource_record *rr,
                             void *data, size_t data_len) {
  switch (rr->rtype) {
    case NS_DNS_A_RECORD:
      if (data_len < sizeof(struct in_addr)) {
        return -1;
      }
      memcpy(data, rr->rdata.p, data_len);
      return 0;
#ifdef NS_ENABLE_IPV6
    case NS_DNS_AAAA_RECORD:
      if (data_len < sizeof(struct in6_addr)) {
        return -1;  /* LCOV_EXCL_LINE */
      }
      memcpy(data, rr->rdata.p, data_len);
      return 0;
#endif
    case NS_DNS_CNAME_RECORD:
      ns_dns_uncompress_name(msg, &rr->rdata, (char *) data, data_len);
      return 0;
  }

  return -1;
}

/*
 * Insert a DNS header to an IO buffer.
 *
 * Returns number of bytes inserted.
 */
int ns_dns_insert_header(struct iobuf *io, size_t pos,
                         struct ns_dns_message *msg) {
  struct ns_dns_header header;

  memset(&header, 0, sizeof(header));
  header.transaction_id = msg->transaction_id;
  header.flags = htons(msg->flags);
  header.num_questions = htons(msg->num_questions);
  header.num_answers = htons(msg->num_answers);

  return iobuf_insert(io, pos, &header, sizeof(header));
}

/*
 * Append already encoded body from an existing message.
 *
 * This is useful when generating a DNS reply message which includes
 * all question records.
 *
 * Returns number of appened bytes.
 */
int ns_dns_copy_body(struct iobuf *io, struct ns_dns_message *msg) {
  return iobuf_append(io, msg->pkt.p + sizeof(struct ns_dns_header),
                      msg->pkt.len - sizeof(struct ns_dns_header));
}

static int ns_dns_encode_name(struct iobuf *io, const char *name, size_t len) {
  const char *s;
  unsigned char n;
  size_t pos = io->len;

  do {
    if ((s = strchr(name, '.')) == NULL) {
      s = name + len;
    }

    if (s - name > 127) {
      return -1;  /* TODO(mkm) cover */
    }
    n = s - name;            /* chunk length */
    iobuf_append(io, &n, 1); /* send length */
    iobuf_append(io, name, n);

    if (*s == '.') {
      n++;
    }

    name += n;
    len -= n;
  } while (*s != '\0');
  iobuf_append(io, "\0", 1);  /* Mark end of host name */

  return io->len - pos;
}

/*
 * Encode and append a DNS resource record to an IO buffer.
 *
 * The record metadata is taken from the `rr` parameter, while the name and data
 * are taken from the parameters, encoded in the appropriate format depending on
 * record type, and stored in the IO buffer. The encoded values might contain
 * offsets within the IO buffer. It's thus important that the IO buffer doesn't
 * get trimmed while a sequence of records are encoded while preparing a DNS reply.
 *
 * This function doesn't update the `name` and `rdata` pointers in the `rr` struct
 * because they might be invalidated as soon as the IO buffer grows again.
 *
 * Returns the number of bytes appened or -1 in case of error.
 */
int ns_dns_encode_record(struct iobuf *io, struct ns_dns_resource_record *rr,
                         const char *name, size_t nlen, void *rdata, size_t rlen) {
  size_t pos = io->len;
  uint16_t u16;
  uint32_t u32;

  if (rr->kind == NS_DNS_INVALID_RECORD) {
    return -1;  /* LCOV_EXCL_LINE */
  }

  if (ns_dns_encode_name(io, name, nlen) == -1) {
    return -1;
  }

  u16 = htons(rr->rtype);
  iobuf_append(io, &u16, 2);
  u16 = htons(rr->rclass);
  iobuf_append(io, &u16, 2);

  if (rr->kind == NS_DNS_ANSWER) {
    u32 = htonl(rr->ttl);
    iobuf_append(io, &u32, 4);

    if (rr->rtype == NS_DNS_CNAME_RECORD) {
      int clen;
      /* fill size after encoding */
      size_t off = io->len;
      iobuf_append(io, &u16, 2);
      if ((clen = ns_dns_encode_name(io, (const char *) rdata, rlen)) == -1) {
        return -1;
      }
      u16 = clen;
      io->buf[off] = u16 >> 8;
      io->buf[off+1] = u16 & 0xff;
    } else {
      u16 = htons(rlen);
      iobuf_append(io, &u16, 2);
      iobuf_append(io, rdata, rlen);
    }
  }

  return io->len - pos;
}

/*
 * Send a DNS query to the remote end.
 */
void ns_send_dns_query(struct ns_connection* nc, const char *name,
                       int query_type) {
  struct ns_dns_message msg;
  struct iobuf pkt;
  struct ns_dns_resource_record *rr = &msg.questions[0];

  iobuf_init(&pkt, MAX_DNS_PACKET_LEN);
  memset(&msg, 0, sizeof(msg));

  msg.transaction_id = ++ns_dns_tid;
  msg.flags = 0x100;
  msg.num_questions = 1;

  ns_dns_insert_header(&pkt, 0, &msg);

  rr->rtype = query_type;
  rr->rclass = 1; /* Class: inet */
  rr->kind = NS_DNS_QUESTION;

  if (ns_dns_encode_record(&pkt, rr, name, strlen(name), NULL, 0) == -1) {
    /* TODO(mkm): return an error code */
    return; /* LCOV_EXCL_LINE */
  }

  /* TCP DNS requires messages to be prefixed with len */
  if (!(nc->flags & NSF_UDP)) {
    uint16_t len = htons(pkt.len);
    iobuf_insert(&pkt, 0, &len, 2);
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

  rr->kind = reply ? NS_DNS_ANSWER : NS_DNS_QUESTION;
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
  msg->pkt.p = buf;
  msg->pkt.len = len;

  if (len < (int)sizeof(*header)) {
    return -1;  /* LCOV_EXCL_LINE */
  }

  msg->transaction_id = header->transaction_id;
  msg->flags = ntohs(header->flags);
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
      data = (unsigned char *)msg->pkt.p + off;
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

static void dns_handler(struct ns_connection *nc, int ev, void *ev_data) {
  struct iobuf *io = &nc->recv_iobuf;
  struct ns_dns_message msg;

  /* Pass low-level events to the user handler */
  nc->handler(nc, ev, ev_data);

  switch (ev) {
    case NS_RECV:
      if (ns_parse_dns(nc->recv_iobuf.buf, nc->recv_iobuf.len, &msg) == -1) {
        /* reply + recursion allowed + format error */
        msg.flags |= 0x8081;
        ns_dns_insert_header(io, 0, &msg);
        ns_send(nc, io->buf, io->len);
      } else {
        /* Call user handler with parsed message */
        nc->handler(nc, NS_DNS_MESSAGE, &msg);
      }
      iobuf_remove(io, io->len);
      break;
  }
}

/*
 * Attach built-in DNS event handler to the given listening connection.
 *
 * DNS event handler parses incoming UDP packets, treating them as DNS
 * requests. If incoming packet gets successfully parsed by the DNS event
 * handler, a user event handler will receive `NS_DNS_REQUEST` event, with
 * `ev_data` pointing to the parsed `struct ns_dns_message`.
 *
 * See https://github.com/cesanta/fossa/tree/master/examples/captive_dns_server[captive_dns_server]
 * example on how to handle DNS request and send DNS reply.
 */
void ns_set_protocol_dns(struct ns_connection *nc) {
  nc->proto_handler = dns_handler;
}

#endif  /* NS_DISABLE_DNS */
