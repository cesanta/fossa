/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#ifdef NS_ENABLE_DNS_SERVER

#include "internal.h"

struct ns_dns_reply ns_dns_create_reply(struct mbuf *io,
                                        struct ns_dns_message *msg) {
  struct ns_dns_reply rep;
  rep.msg = msg;
  rep.io = io;
  rep.start = io->len;

  /* reply + recursion allowed */
  msg->flags |= 0x8080;
  ns_dns_copy_body(io, msg);

  msg->num_answers = 0;
  return rep;
}

int ns_dns_send_reply(struct ns_connection *nc, struct ns_dns_reply *r) {
  size_t sent = r->io->len - r->start;
  ns_dns_insert_header(r->io, r->start, r->msg);
  if (!(nc->flags & NSF_UDP)) {
    uint16_t len = htons(sent);
    mbuf_insert(r->io, r->start, &len, 2);
  }

  if (&nc->send_mbuf != r->io || nc->flags & NSF_UDP) {
    sent = ns_send(nc, r->io->buf + r->start, r->io->len - r->start);
    r->io->len = r->start;
  }
  return sent;
}

int ns_dns_reply_record(struct ns_dns_reply *reply,
                        struct ns_dns_resource_record *question,
                        const char *name, int rtype, int ttl, const void *rdata,
                        size_t rdata_len) {
  struct ns_dns_message *msg = (struct ns_dns_message *) reply->msg;
  char rname[512];
  struct ns_dns_resource_record *ans = &msg->answers[msg->num_answers];
  if (msg->num_answers >= NS_MAX_DNS_ANSWERS) {
    return -1; /* LCOV_EXCL_LINE */
  }

  if (name == NULL) {
    name = rname;
    rname[511] = 0;
    ns_dns_uncompress_name(msg, &question->name, rname, sizeof(rname) - 1);
  }

  *ans = *question;
  ans->kind = NS_DNS_ANSWER;
  ans->rtype = rtype;
  ans->ttl = ttl;

  if (ns_dns_encode_record(reply->io, ans, name, strlen(name), rdata,
                           rdata_len) == -1) {
    return -1; /* LCOV_EXCL_LINE */
  };

  msg->num_answers++;
  return 0;
}

#endif /* NS_ENABLE_DNS_SERVER */
