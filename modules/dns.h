/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#ifndef NS_DNS_HEADER_DEFINED
#define NS_DNS_HEADER_DEFINED

#include "net.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define NS_DNS_A_RECORD     0x01  /* Lookup IP address */
#define NS_DNS_CNAME_RECORD 0x05  /* Lookup CNAME */
#define NS_DNS_AAAA_RECORD  0x1c  /* Lookup IPv6 address */
#define NS_DNS_MX_RECORD    0x0f  /* Lookup mail server for domain */

struct ns_dns_message;

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

struct ns_dns_resource_record *ns_dns_next_record(
    struct ns_dns_message *, int, struct ns_dns_resource_record *);

int ns_dns_parse_record_data(struct ns_dns_message *,
                             struct ns_dns_resource_record *, void *, size_t);

/* low-level */
#define NS_MAX_DNS_QUESTIONS 32
#define NS_MAX_DNS_ANSWERS   32

/* DNS resource record. */
struct ns_dns_resource_record {
  struct ns_str name;  /* buffer with compressed name */
  int rtype;
  int rclass;
  int ttl;
  struct ns_str rdata;  /* protocol data (can be a compressed name) */
};

/* DNS message (request and response). */
struct ns_dns_message {
  const char *pkt;  /* packet body */
  int num_questions;
  int num_answers;
  struct ns_dns_resource_record questions[NS_MAX_DNS_QUESTIONS];
  struct ns_dns_resource_record answers[NS_MAX_DNS_ANSWERS];
};

void ns_send_dns_query(struct ns_connection*, const char *, int);
int ns_parse_dns(const char *, int, struct ns_dns_message *);

size_t ns_dns_uncompress_name(struct ns_dns_message *, struct ns_str *,
                              char *, int);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif  /* NS_HTTP_HEADER_DEFINED */
