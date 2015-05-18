/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

/*
 * === DNS
 */

#ifndef NS_DNS_HEADER_DEFINED
#define NS_DNS_HEADER_DEFINED

#include "net.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define NS_DNS_A_RECORD 0x01     /* Lookup IP address */
#define NS_DNS_CNAME_RECORD 0x05 /* Lookup CNAME */
#define NS_DNS_AAAA_RECORD 0x1c  /* Lookup IPv6 address */
#define NS_DNS_MX_RECORD 0x0f    /* Lookup mail server for domain */

#define NS_MAX_DNS_QUESTIONS 32
#define NS_MAX_DNS_ANSWERS 32

#define NS_DNS_MESSAGE 100 /* High-level DNS message event */

enum ns_dns_resource_record_kind {
  NS_DNS_INVALID_RECORD = 0,
  NS_DNS_QUESTION,
  NS_DNS_ANSWER
};

/* DNS resource record. */
struct ns_dns_resource_record {
  struct ns_str name; /* buffer with compressed name */
  int rtype;
  int rclass;
  int ttl;
  enum ns_dns_resource_record_kind kind;
  struct ns_str rdata; /* protocol data (can be a compressed name) */
};

/* DNS message (request and response). */
struct ns_dns_message {
  struct ns_str pkt; /* packet body */
  uint16_t flags;
  uint16_t transaction_id;
  int num_questions;
  int num_answers;
  struct ns_dns_resource_record questions[NS_MAX_DNS_QUESTIONS];
  struct ns_dns_resource_record answers[NS_MAX_DNS_ANSWERS];
};

struct ns_dns_resource_record *ns_dns_next_record(
    struct ns_dns_message *, int, struct ns_dns_resource_record *);

/*
 * Parse the record data from a DNS resource record.
 *
 *  - A:     struct in_addr *ina
 *  - AAAA:  struct in6_addr *ina
 *  - CNAME: char buffer
 *
 * Returns -1 on error.
 *
 * TODO(mkm): MX
 */
int ns_dns_parse_record_data(struct ns_dns_message *,
                             struct ns_dns_resource_record *, void *, size_t);

/*
 * Send a DNS query to the remote end.
 */
void ns_send_dns_query(struct ns_connection *, const char *, int);

/*
 * Insert a DNS header to an IO buffer.
 *
 * Return number of bytes inserted.
 */
int ns_dns_insert_header(struct mbuf *, size_t, struct ns_dns_message *);

/*
 * Append already encoded body from an existing message.
 *
 * This is useful when generating a DNS reply message which includes
 * all question records.
 *
 * Return number of appened bytes.
 */
int ns_dns_copy_body(struct mbuf *, struct ns_dns_message *);

/*
 * Encode and append a DNS resource record to an IO buffer.
 *
 * The record metadata is taken from the `rr` parameter, while the name and data
 * are taken from the parameters, encoded in the appropriate format depending on
 * record type, and stored in the IO buffer. The encoded values might contain
 * offsets within the IO buffer. It's thus important that the IO buffer doesn't
 * get trimmed while a sequence of records are encoded while preparing a DNS
 *reply.
 *
 * This function doesn't update the `name` and `rdata` pointers in the `rr`
 *struct
 * because they might be invalidated as soon as the IO buffer grows again.
 *
 * Return the number of bytes appened or -1 in case of error.
 */
int ns_dns_encode_record(struct mbuf *, struct ns_dns_resource_record *,
                         const char *, size_t, const void *, size_t);

/* Low-level: parses a DNS response. */
int ns_parse_dns(const char *, int, struct ns_dns_message *);

/*
 * Uncompress a DNS compressed name.
 *
 * The containing dns message is required because the compressed encoding
 * and reference suffixes present elsewhere in the packet.
 *
 * If name is less than `dst_len` characters long, the remainder
 * of `dst` is terminated with `\0' characters. Otherwise, `dst` is not
 *terminated.
 *
 * If `dst_len` is 0 `dst` can be NULL.
 * Return the uncompressed name length.
 */
size_t ns_dns_uncompress_name(struct ns_dns_message *, struct ns_str *, char *,
                              int);

/*
 * Attach built-in DNS event handler to the given listening connection.
 *
 * DNS event handler parses incoming UDP packets, treating them as DNS
 * requests. If incoming packet gets successfully parsed by the DNS event
 * handler, a user event handler will receive `NS_DNS_REQUEST` event, with
 * `ev_data` pointing to the parsed `struct ns_dns_message`.
 *
 * See
 * https://github.com/cesanta/fossa/tree/master/examples/captive_dns_server[captive_dns_server]
 * example on how to handle DNS request and send DNS reply.
 */
void ns_set_protocol_dns(struct ns_connection *);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* NS_HTTP_HEADER_DEFINED */
