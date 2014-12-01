/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

/*
 * == Name resolver
 */

#ifndef NS_DISABLE_RESOLVER

#include "internal.h"
#include "resolv-internal.h"

static const char *ns_default_dns_server = "udp://8.8.8.8:53";
NS_INTERNAL char ns_dns_server[256];

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
NS_INTERNAL int ns_resolve_etc_hosts(const char *name, struct in_addr *ina) {
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

NS_INTERNAL void ns_dns_make_syntetic_message(const char *name, int query,
                                              void *rdata,
                                              size_t rdata_len,
                                              struct ns_dns_message *msg) {
  memset(msg, 0, sizeof(*msg));
  msg->num_questions = 1;
  msg->num_answers = 1;

  msg->questions[0].name.p = name;
  msg->questions[0].name.len = strlen(name);
  msg->questions[0].rtype = query;
  msg->questions[0].rclass = 1;
  msg->questions[0].ttl = 0;

  msg->answers[0] = msg->questions[0];
  msg->answers[0].rdata.p = (char *) rdata;
  msg->answers[0].rdata.len = rdata_len;
}

NS_INTERNAL int ns_resolve_async_local(const char *name, int query,
                   ns_resolve_callback_t cb, void *data) {
  struct in_addr ina;
  struct ns_dns_message msg;

  /* TODO(mkm) handle IPV6 */
  if (query != NS_DNS_A_RECORD) {
    return -1;
  }

  if (ns_resolve_etc_hosts(name, &ina) == -1) {
    return -1;
  }

  ns_dns_make_syntetic_message(name, query, &ina, sizeof(ina), &msg);
  cb(&msg, data);
  return 0;
}

NS_INTERNAL int ns_resolve_literal_address(const char *name,
                                           ns_resolve_callback_t cb,
                                           void *data) {
  unsigned int a, b, c, d;
  struct ns_dns_message msg;
  struct in_addr ina;
#ifdef NS_ENABLE_IPV6
  struct in6_addr ina6;
  char buf[100];
#endif

  if (sscanf(name, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
    ina.s_addr = htonl(a << 24 | b << 16 | c << 8 | d);
    ns_dns_make_syntetic_message(name, NS_DNS_A_RECORD, &ina, sizeof(ina),
                                 &msg);
#ifdef NS_ENABLE_IPV6
  } else if (sscanf(name, "%99s", buf) == 1 &&
             inet_pton(AF_INET6, buf, &ina6)) {
    ns_dns_make_syntetic_message(name, NS_DNS_AAAA_RECORD, &ina6, sizeof(ina6),
                                 &msg);
#endif
  } else {
    return -1;
  }

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

  if ((opts.accept_literal || opts.only_literal) &&
      ns_resolve_literal_address(name, cb, data) == 0) {
    return 0;
  }

  /* resolve local name */

  if (ns_resolve_async_local(name, query, cb, data) == 0) {
    return 0;
  }

  if (opts.only_literal) {
    return -1;
  }

  /* resolve with DNS */

  req = (struct ns_resolve_async_request *) NS_CALLOC(1, sizeof(*req));

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

#endif  /* NS_DISABLE_RESOLVE */
