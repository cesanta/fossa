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

#define NS_MAX_DNS_QUESTIONS 32
#define NS_MAX_DNS_ANSWERS   32

#define NS_DNS_MESSAGE      100   /* High-level DNS message event */

enum ns_dns_resource_record_kind {
  NS_DNS_INVALID_RECORD = 0,
  NS_DNS_QUESTION,
  NS_DNS_ANSWER
};

/* DNS resource record. */
struct ns_dns_resource_record {
  struct ns_str name;  /* buffer with compressed name */
  int rtype;
  int rclass;
  int ttl;
  enum ns_dns_resource_record_kind kind;
  struct ns_str rdata;  /* protocol data (can be a compressed name) */
};

/* DNS message (request and response). */
struct ns_dns_message {
  struct ns_str pkt;  /* packet body */
  uint16_t flags;
  uint16_t transaction_id;
  int num_questions;
  int num_answers;
  struct ns_dns_resource_record questions[NS_MAX_DNS_QUESTIONS];
  struct ns_dns_resource_record answers[NS_MAX_DNS_ANSWERS];
};

struct ns_dns_resource_record *ns_dns_next_record(
    struct ns_dns_message *, int, struct ns_dns_resource_record *);

int ns_dns_parse_record_data(struct ns_dns_message *,
                             struct ns_dns_resource_record *, void *, size_t);

void ns_send_dns_query(struct ns_connection*, const char *, int);
int ns_dns_insert_header(struct iobuf *, size_t, struct ns_dns_message *);
int ns_dns_copy_body(struct iobuf *, struct ns_dns_message *);
int ns_dns_encode_record(struct iobuf *, struct ns_dns_resource_record *,
                         const char *, size_t, const void *, size_t);
int ns_parse_dns(const char *, int, struct ns_dns_message *);

size_t ns_dns_uncompress_name(struct ns_dns_message *, struct ns_str *,
                              char *, int);
void ns_set_protocol_dns(struct ns_connection *);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif  /* NS_HTTP_HEADER_DEFINED */
