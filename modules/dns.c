/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

/*
 * == DNS API
 */

#ifndef NS_DISABLE_DNS

#include "internal.h"

#define MAX_DNS_PACKET_LEN  2048

static const char *ns_default_dns_server = "udp://8.8.8.8:53";
NS_INTERNAL char ns_dns_server[256];

static int ns_dns_tid = 0xa0;

struct ns_dns_header {
  uint16_t transaction_id;
  uint16_t flags;
  uint16_t num_questions;
  uint16_t num_answers;
  uint16_t num_authority_prs;
  uint16_t num_other_prs;
};

struct ns_resolve_async_request {
  char name[1024];
  int query;
  ns_resolve_callback_t callback;
  void *data;
  time_t timeout;
  int max_retries;

  /* state */
  time_t last_time;
  int retries;
};

/*
 * Find what nameserver to use.
 *
 * Return 0 if OK, -1 if error
 */
static int ns_get_ip_address_of_nameserver(char *name, size_t name_len) {
  int  ret = 0;

#ifdef _WIN32
  int  i;
  LONG  err;
  HKEY  hKey, hSub;
  char  subkey[512], dhcpns[512], ns[512], value[128], *key =
  "SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces";

  if ((err = RegOpenKey(HKEY_LOCAL_MACHINE,
      key, &hKey)) != ERROR_SUCCESS) {
    fprintf(stderr, "cannot open reg key %s: %d\n", key, err);
    ret--;
  } else {
    for (ret--, i = 0; RegEnumKey(hKey, i, subkey,
        sizeof(subkey)) == ERROR_SUCCESS; i++) {
      DWORD type, len = sizeof(value);
      if (RegOpenKey(hKey, subkey, &hSub) == ERROR_SUCCESS &&
          (RegQueryValueEx(hSub, "NameServer", 0,
          &type, value, &len) == ERROR_SUCCESS ||
          RegQueryValueEx(hSub, "DhcpNameServer", 0,
          &type, value, &len) == ERROR_SUCCESS)) {
        strncpy(name, value, name_len);
        ret++;
        RegCloseKey(hSub);
        break;
      }
    }
    RegCloseKey(hKey);
  }
#else
  FILE  *fp;
  char  line[512];

  if ((fp = fopen("/etc/resolv.conf", "r")) == NULL) {
    ret--;
  } else {
    /* Try to figure out what nameserver to use */
    for (ret--; fgets(line, sizeof(line), fp) != NULL; ) {
      char buf[256];
      if (sscanf(line, "nameserver %256[^\n]s", buf) == 1) {
        snprintf(name, name_len, "udp://%s:53", buf);
        ret++;
        break;
      }
    }
    (void) fclose(fp);
  }
#endif /* _WIN32 */

  return ret;
}

/*
 * Resolve a name from `/etc/hosts`.
 *
 * Returns 0 on success, -1 on failure.
 */
NS_INTERNAL int ns_dns_resolve_hosts(const char *name, struct in_addr *ina) {
  /* TODO(mkm) cache /etc/hosts */
  FILE *fp;
  char line[1024];
  char *p;
  char alias[256];
  unsigned int a, b, c, d;
  int len = 0;

  if ((fp = fopen("/etc/hosts", "r")) == NULL) {
    return -1;
  }

  for (; fgets(line, sizeof(line), fp) != NULL; ) {
    if (line[0] == '#') continue;

    if (sscanf(line, "%u.%u.%u.%u%n", &a, &b, &c, &d, &len) == 0) {
      /* TODO(mkm): handle ipv6 */
      continue;
    }
    for (p = line + len; sscanf(p, "%s%n", alias, &len) == 1; p += len) {
      if (strcmp(alias, name) == 0) {
        ina->s_addr = htonl(a << 24 | b << 16 | c << 8 | d);
        return 0;
      }
    }
  }

  return -1;
}

NS_INTERNAL int ns_resolve_async_local(const char *name, int query,
                   ns_resolve_callback_t cb, void *data) {
  struct in_addr ina;
  struct ns_dns_message msg;

  /* TODO(mkm) handle IPV6 */
  if (query != NS_DNS_A_RECORD) {
    return -1;
  }

  if (ns_dns_resolve_hosts(name, &ina) == -1) {
    return -1;
  }

  memset(&msg, 0, sizeof(msg));
  msg.num_questions = 1;
  msg.num_answers = 1;

  msg.questions[0].name.p = name;
  msg.questions[0].name.len = strlen(name);
  msg.questions[0].rtype = query;
  msg.questions[0].rclass = 1;
  msg.questions[0].ttl = 0;

  msg.answers[0] = msg.questions[0];
  msg.answers[0].rdata.p = (char *)&ina;

  cb(&msg, data);
  return 0;
}

static void ns_resolve_async_eh(struct ns_connection *nc, int ev, void *data) {
  time_t now = time(NULL);
  struct ns_resolve_async_request *req;
  req = (struct ns_resolve_async_request *) nc->user_data;

  (void) data;
  switch (ev) {
    case NS_POLL:
      if (req->retries > req->max_retries) {
        req->callback(NULL, req->data);
        nc->flags |= NSF_CLOSE_IMMEDIATELY;
        break;
      }
      if (now - req->last_time > req->timeout) {
        ns_send_dns_query(nc, req->name, req->query);
        req->last_time = now;
        req->retries++;
      }
      break;
    case NS_RECV:
      {
        struct ns_dns_message msg;
        ns_parse_dns(nc->recv_iobuf.buf, * (int *) data, &msg);

        req->callback(&msg, req->data);

        nc->flags |= NSF_CLOSE_IMMEDIATELY;
      }
      break;
  }
}

/* See `ns_resolve_async_opt` */
int ns_resolve_async(struct ns_mgr *mgr, const char *name, int query,
                   ns_resolve_callback_t cb, void *data) {
  static struct ns_resolve_async_opts opts;
  return ns_resolve_async_opt(mgr, name, query, cb, data, opts);
}

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
 * struct ns_dns_resource_record *rr = ns_next_record(msg, NS_DNS_A_RECORD, NULL);
 * ns_dns_parse_record_data(msg, rr, &ina, sizeof(ina));
 * ----
 */
int ns_resolve_async_opt(struct ns_mgr *mgr, const char *name, int query,
                       ns_resolve_callback_t cb, void *data,
                       struct ns_resolve_async_opts opts) {
  struct ns_resolve_async_request * req;
  struct ns_connection *nc;
  const char *nameserver = opts.nameserver_url;

  /* resolve local name first */

  if (ns_resolve_async_local(name, query, cb, data) == 0) {
    return 0;
  }

  /* resolve with DNS */

  req = (struct ns_resolve_async_request *) calloc(1, sizeof(*req));

  strncpy(req->name, name, sizeof(req->name));
  req->query = query;
  req->callback = cb;
  req->data = data;
  /* TODO(mkm): parse defaults out of resolve.conf */
  req->max_retries = opts.max_retries ? opts.max_retries : 2;
  req->timeout = opts.timeout ? opts.timeout : 5;

  /* Lazily initialize dns server */
  if (!nameserver && ns_dns_server[0] == 0) {
    if (ns_get_ip_address_of_nameserver(ns_dns_server,
                                        sizeof(ns_dns_server)) == -1) {
      strncpy(ns_dns_server, ns_default_dns_server, sizeof(ns_dns_server));
    }
  }
  if (!nameserver) {
    nameserver = ns_dns_server;
  }

  nc = ns_connect(mgr, nameserver, ns_resolve_async_eh);
  if (nc == NULL) {
    return -1;
  }
  nc->user_data = req;
  return 0;
}

struct ns_dns_resource_record *ns_dns_next_record(
    struct ns_dns_message *msg, int query,
    struct ns_dns_resource_record *prev) {
  struct ns_dns_resource_record *rr;

  for (rr = (prev == NULL ? msg->answers : prev + 1);
       rr - msg->answers < msg->num_answers; rr++) {
    if (rr->rtype == query) {
      return rr;
    }
  }
  return NULL;
}

/*
 * Parses the record data from a DNS resource record.
 *
 *  - A:     struct in_addr *ina
 *  - CNAME: char buffer
 *
 * Returns -1 on error.
 *
 * TODO(mkm): MX, AAAA
 */
int ns_dns_parse_record_data(struct ns_dns_message *msg,
                             struct ns_dns_resource_record *rr,
                             void *data, size_t data_len) {
  struct in_addr *ina = (struct in_addr *) data;

  switch (rr->rtype) {
    case NS_DNS_A_RECORD:
      if (data_len < sizeof(*ina)) {
        return -1;
      }
      memcpy(ina, rr->rdata.p, data_len);
      return 0;
    case NS_DNS_CNAME_RECORD:
      ns_dns_uncompress_name(msg, &rr->rdata, (char *) data, data_len);
      return 0;
  }

  return -1;
}

/*
 * Low-level: send a dns query to the remote end
 */
void ns_send_dns_query(struct ns_connection* nc, const char *name,
                       int query_type) {
  struct ns_dns_header header;
  const char *s;
  int n, name_len;
  uint16_t num;
  struct iobuf pkt;

  iobuf_init(&pkt, MAX_DNS_PACKET_LEN);

  memset(&header, 0, sizeof(header));
  header.transaction_id = ++ns_dns_tid;
  header.flags = htons(0x100);  /* recursion allowed */
  header.num_questions = htons(1);

  iobuf_append(&pkt, &header, sizeof(header));

  name_len = strlen(name);
  do {
    if ((s = strchr(name, '.')) == NULL)
      s = name + name_len;

    n = s - name;              /* chunk length */
    iobuf_append(&pkt, &n, 1); /* send length */
    iobuf_append(&pkt, name, n);

    if (*s == '.')
      n++;

    name += n;
    name_len -= n;
  } while (*s != '\0');
  iobuf_append(&pkt, "\0", 1);  /* Mark end of host name */

  num = htons(query_type);
  iobuf_append(&pkt, &num, 2);
  num = htons(0x0001);  /* Class: inet */
  iobuf_append(&pkt, &num, 2);

  /* TCP DNS requires messages to be prefixed with len */
  if (!(nc->flags & NSF_UDP)) {
    uint16_t len = htons(pkt.len);
    iobuf_prepend(&pkt, &len, 2);
  }

  ns_send(nc, pkt.buf, pkt.len);
  iobuf_free(&pkt);
}

static unsigned char *ns_parse_dns_resource_record(
    unsigned char *data, struct ns_dns_resource_record *rr, int reply) {
  unsigned char *name = data;
  int chunk_len, data_len;

  while((chunk_len = *data)) {
    if (((unsigned char *)data)[0] & 0xc0) {
      data += 1;
      break;
    }
    data += chunk_len + 1;
  }

  rr->name.p = (char *) name;
  rr->name.len = data-name+1;

  data++;

  rr->rtype = data[0] << 8 | data[1];
  data += 2;

  rr->rclass = data[0] << 8 | data[1];
  data += 2;

  if (reply) {
    rr->ttl = data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3];
    data += 4;

    data_len = *data << 8 | *(data+1);
    data += 2;

    rr->rdata.p = (char *) data;
    rr->rdata.len = data_len;
    data += data_len;
  }
  return data;
}

/* Low-level: parses a DNS response. */
int ns_parse_dns(const char *buf, int len, struct ns_dns_message *msg) {
  struct ns_dns_header *header = (struct ns_dns_header *) buf;
  unsigned char *data = (unsigned char *) buf + sizeof(*header);
  int i;
  msg->pkt = buf;

  if (len < (int)sizeof(*header)) {
    return -1;  /* LCOV_EXCL_LINE */
  }

  msg->num_questions = ntohs(header->num_questions);
  msg->num_answers = ntohs(header->num_answers);

  /* TODO(mkm): check bounds */

  for (i = 0; i < msg->num_questions
           && i < (int)ARRAY_SIZE(msg->questions); i++) {
    data = ns_parse_dns_resource_record(data, &msg->questions[i], 0);
  }

  for (i = 0; i < msg->num_answers
           && i < (int)ARRAY_SIZE(msg->answers); i++) {
    data = ns_parse_dns_resource_record(data, &msg->answers[i], 1);
  }

  return 0;
}

/*
 * Uncompress a DNS compressed name.
 *
 * The containing dns message is required because the compressed encoding
 * and reference suffixes present elsewhere in the packet.
 *
 * If name is less than `dst_len` characters long, the remainder
 * of `dst` is terminated with `\0' characters. Otherwise, `dst` is not terminated.
 *
 * If `dst_len` is 0 `dst` can be NULL.
 * Returns the uncompressed name length.
 */
size_t ns_dns_uncompress_name(struct ns_dns_message *msg, struct ns_str *name,
                              char *dst, int dst_len) {
  int chunk_len;
  char *old_dst = dst;
  const unsigned char *data = (unsigned char *) name->p;

  while((chunk_len = *data++)) {
    int leeway = dst_len - (dst - old_dst);
    if (chunk_len & 0xc0) {
      uint16_t off = (data[-1] & (~0xc0)) << 8 | data[0];
      data = (unsigned char *)msg->pkt + off;
      continue;
    }
    if (chunk_len > leeway) {
      chunk_len = leeway;
    }

    memcpy(dst, data, chunk_len);
    data += chunk_len;
    dst += chunk_len;
    leeway -= chunk_len;
    if (leeway == 0) {
      return dst - old_dst;
    }
    *dst++ = '.';
  }
  *--dst = 0;
  return dst - old_dst;
}

#endif  /* NS_DISABLE_DNS */
