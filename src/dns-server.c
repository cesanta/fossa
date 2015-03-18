/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

/*
 * == DNS server API
 *
 * Disabled by default; enable with `-DNS_ENABLE_DNS_SERVER`.
 */

#ifdef NS_ENABLE_DNS_SERVER

#include "internal.h"

/*
 * Creates a DNS reply.
 *
 * The reply will be based on an existing query message `msg`.
 * The query body will be appended to the output buffer.
 * "reply + recusions allowed" will be added to the message flags and
 * message's num_answers will be set to 0.
 *
 * Anwer records can be appended with `ns_dns_send_reply` or by lower
 * level function defined in the DNS API.
 *
 * In order to send the reply use `ns_dns_send_reply`.
 * It's possible to use a connection's send buffer as reply buffers,
 * and it will work for both UDP and TCP connections.
 *
 * Example:
 *
 * [source,c]
 * -----
 * reply = ns_dns_create_reply(&nc->send_iobuf, msg);
 * for (i = 0; i < msg->num_questions; i++) {
 *   rr = &msg->questions[i];
 *   if (rr->rtype == NS_DNS_A_RECORD) {
 *     ns_dns_reply_record(&reply, rr, 3600, &dummy_ip_addr, 4);
 *   }
 * }
 * ns_dns_send_reply(nc, &reply);
 * -----
 */
struct ns_dns_reply ns_dns_create_reply(struct iobuf *io,
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

/*
 * Sends a DNS reply through a connection.
 *
 * The DNS data is stored in an IO buffer pointed by reply structure in `r`.
 * This function mutates the content of that buffer in order to ensure that
 * the DNS header reflects size and flags of the mssage, that might have been
 * updated either with `ns_dns_reply_record` or by direct manipulation of
 * `r->message`.
 *
 * Once sent, the IO buffer will be trimmed unless the reply IO buffer
 * is the connection's send buffer and the connection is not in UDP mode.
 */
int ns_dns_send_reply(struct ns_connection *nc, struct ns_dns_reply *r) {
  size_t sent = r->io->len - r->start;
  ns_dns_insert_header(r->io, r->start, r->msg);
  if (!(nc->flags & NSF_UDP)) {
    uint16_t len = htons(sent);
    iobuf_insert(r->io, r->start, &len, 2);
  }

  if (&nc->send_iobuf != r->io || nc->flags & NSF_UDP) {
    sent = ns_send(nc, r->io->buf + r->start, r->io->len - r->start);
    r->io->len = r->start;
  }
  return sent;
}

/*
 * Append a DNS reply record to the IO buffer and to the DNS message.
 *
 * The message num_answers field will be incremented. It's caller's duty
 * to ensure num_answers is propertly initialized.
 *
 * Returns -1 on error.
 */
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
