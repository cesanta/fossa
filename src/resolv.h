/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

/*
 * === Asynchronouns DNS resolver
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

/* See `ns_resolve_async_opt()` */
int ns_resolve_async(struct ns_mgr *, const char *, int, ns_resolve_callback_t,
                     void *data);

/*
 * Resolved a DNS name asynchronously.
 *
 * Upon successful resolution, the user callback will be invoked
 * with the full DNS response message and a pointer to the user's
 * context `data`.
 *
 * In case of timeout while performing the resolution the callback
 * will receive a NULL `msg`.
 *
 * The DNS answers can be extracted with `ns_next_record` and
 * `ns_dns_parse_record_data`:
 *
 * [source,c]
 * ----
 * struct in_addr ina;
 * struct ns_dns_resource_record *rr = ns_next_record(msg, NS_DNS_A_RECORD,
 *   NULL);
 * ns_dns_parse_record_data(msg, rr, &ina, sizeof(ina));
 * ----
 */
int ns_resolve_async_opt(struct ns_mgr *, const char *, int,
                         ns_resolve_callback_t, void *data,
                         struct ns_resolve_async_opts opts);

/*
 * Resolve a name from `/etc/hosts`.
 *
 * Returns 0 on success, -1 on failure.
 */
int ns_resolve_from_hosts_file(const char *host, union socket_address *usa);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* NS_RESOLV_HEADER_DEFINED */
