/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#ifndef NS_RESOLV_HEADER_DEFINED
#define NS_RESOLV_HEADER_DEFINED

#include "dns.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef void (*ns_resolve_callback_t)(struct ns_dns_message *, void *);

/* Options for `ns_resolve_async_opt`. */
struct ns_resolve_async_opts {
  const char *nameserver_url;
  int max_retries;    /* defaults to 2 if zero */
  int timeout;        /* in seconds; defaults to 5 if zero */
  int accept_literal; /* pseudo-resolve literal ipv4 and ipv6 addrs */
  int only_literal;   /* only resolves literal addrs; sync cb invocation */
};

int ns_resolve_async(struct ns_mgr *mgr, const char *, int,
                   ns_resolve_callback_t, void *);
int ns_resolve_async_opt(struct ns_mgr *mgr, const char *, int,
                       ns_resolve_callback_t, void *,
                       struct ns_resolve_async_opts opts);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif  /* NS_RESOLV_HEADER_DEFINED */
