/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
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
  struct iobuf *io;
  size_t start;
};

struct ns_dns_reply ns_dns_create_reply(struct iobuf *,
                                        struct ns_dns_message *);
int ns_dns_send_reply(struct ns_connection *, struct ns_dns_reply *);
int ns_dns_reply_record(struct ns_dns_reply *, struct ns_dns_resource_record *,
                        const char *, int, int, const void *, size_t);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* NS_ENABLE_DNS_SERVER */
#endif /* NS_HTTP_HEADER_DEFINED */
