/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

/*
 * === DNS server
 *
 * Disabled by default; enable with `-DNS_ENABLE_DNS_SERVER`.
 */

#ifndef NS_DNS_SERVER_HEADER_DEFINED
#define NS_DNS_SERVER_HEADER_DEFINED

#ifdef NS_ENABLE_DNS_SERVER

#include "dns.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define NS_DNS_SERVER_DEFAULT_TTL 3600

struct ns_dns_reply {
  struct ns_dns_message *msg;
  struct mbuf *io;
  size_t start;
};

/*
 * Create a DNS reply.
 *
 * The reply will be based on an existing query message `msg`.
 * The query body will be appended to the output buffer.
 * "reply + recursion allowed" will be added to the message flags and
 * message's num_answers will be set to 0.
 *
 * Answer records can be appended with `ns_dns_send_reply` or by lower
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
 * reply = ns_dns_create_reply(&nc->send_mbuf, msg);
 * for (i = 0; i < msg->num_questions; i++) {
 *   rr = &msg->questions[i];
 *   if (rr->rtype == NS_DNS_A_RECORD) {
 *     ns_dns_reply_record(&reply, rr, 3600, &dummy_ip_addr, 4);
 *   }
 * }
 * ns_dns_send_reply(nc, &reply);
 * -----
 */
struct ns_dns_reply ns_dns_create_reply(struct mbuf *, struct ns_dns_message *);

/*
 * Append a DNS reply record to the IO buffer and to the DNS message.
 *
 * The message num_answers field will be incremented. It's caller's duty
 * to ensure num_answers is propertly initialized.
 *
 * Returns -1 on error.
 */
int ns_dns_reply_record(struct ns_dns_reply *, struct ns_dns_resource_record *,
                        const char *, int, int, const void *, size_t);

/*
 * Send a DNS reply through a connection.
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
int ns_dns_send_reply(struct ns_connection *, struct ns_dns_reply *);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* NS_ENABLE_DNS_SERVER */
#endif /* NS_HTTP_HEADER_DEFINED */
