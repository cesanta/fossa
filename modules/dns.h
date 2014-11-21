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

/* low-level */
#define NS_MAX_DNS_QUESTIONS 32
#define NS_MAX_DNS_ANSWERS   32

struct ns_dns_resource_record {
  struct ns_str name;  /* buffer with compressed name */
  int rtype;
  int rclass;
  int ttl;
  struct ns_str rdata;  /* protocol data (can be a compressed name) */
};

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
