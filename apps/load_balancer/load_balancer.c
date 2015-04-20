/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#include "../../fossa.h"

struct http_backend {
  const char *vhost;      /* NULL if any host */
  const char *uri_prefix; /* URI prefix, e.g. "/api/v1/", "/static/" */
  const char *uri_prefix_replacement; /* if not NULL, will replace uri_prefix in
                                         requests to backends */
  const char *host_port;              /* Backend address */
  int redirect;                       /* if true redirect instead of proxy */
  int usage_counter; /* Number of times this backend was chosen */
};

struct peer {
  struct ns_connection *nc;
  int64_t body_len;           /* Size of the HTTP body to forward */
  int64_t body_sent;          /* Number of bytes already forwarded */
};

struct conn_data {
  struct http_backend *be;    /* Chosen backend */
  struct peer client;         /* Client peer */
  struct peer backend;        /* Backend peer */
};

static const char *s_error_500 = "HTTP/1.1 500 Failed\r\n";
static const char *s_content_len_0 = "Content-Length: 0\r\n";
static const char *s_connection_close = "Connection: close\r\n";
static const char *s_http_port = "8000";
static struct http_backend s_http_backends[100];
static int s_num_http_backends = 0;
static int s_sig_num = 0;
static FILE *s_log_file = NULL;
#ifdef NS_ENABLE_SSL
const char *s_ssl_cert = NULL;
#endif

static void ev_handler(struct ns_connection *nc, int ev, void *ev_data);

static void signal_handler(int sig_num) {
  signal(sig_num, signal_handler);
  s_sig_num = sig_num;
}

static void send_http_err(struct ns_connection *nc, const char *err_line) {
  ns_printf(nc, "%s%s%s\r\n", err_line, s_content_len_0, s_connection_close);
}

static int has_prefix(const struct ns_str *uri, const char *prefix) {
  size_t prefix_len = strlen(prefix);
  return uri->len >= prefix_len && memcmp(uri->p, prefix, prefix_len) == 0;
}

static int matches_vhost(const struct ns_str *host, const char *vhost) {
  size_t vhost_len;
  if (vhost == NULL) {
    return 1;
  }
  vhost_len = strlen(vhost);
  return host->len == vhost_len && memcmp(host->p, vhost, vhost_len) == 0;
}

static void write_log(const char *fmt, ...) {
  va_list ap;
  if (s_log_file != NULL) {
    va_start(ap, fmt);
    vfprintf(s_log_file, fmt, ap);
    fflush(s_log_file);
    va_end(ap);
  }
}

static void disconnect_backend(struct ns_connection *nc) {
  struct conn_data *data = (struct conn_data *) nc->user_data;
  if (data != NULL) {
    data->backend.nc->flags |= NSF_SEND_AND_CLOSE;
    data->client.nc->user_data = data->backend.nc->user_data = NULL;
    free(data);
  }
}

static struct http_backend *choose_backend(struct http_message *hm) {
  int i, chosen = -1;
  struct ns_str vhost = *ns_get_http_header(hm, "host");
  const char *vhost_end = vhost.p;

  while (vhost_end < vhost.p + vhost.len && *vhost_end != ':') {
    vhost_end++;
  }
  vhost.len = vhost_end - vhost.p;

  for (i = 0; i < s_num_http_backends; i++) {
    if (has_prefix(&hm->uri, s_http_backends[i].uri_prefix) &&
        matches_vhost(&vhost, s_http_backends[i].vhost) &&
        (chosen == -1 ||
         /* Prefer most specific URI prefixes */
         strlen(s_http_backends[i].uri_prefix) >
             strlen(s_http_backends[chosen].uri_prefix) ||
         /* Among prefixes of the same length chose the least used. */
         (strlen(s_http_backends[i].uri_prefix) ==
              strlen(s_http_backends[chosen].uri_prefix) &&
          s_http_backends[i].usage_counter <
              s_http_backends[chosen].usage_counter))) {
      chosen = i;
    }
  }

  return chosen < 0 ? NULL : &s_http_backends[chosen];
}

static void forward_body(struct ns_connection *src, struct ns_connection *dst) {
  struct conn_data *data = (struct conn_data *) src->user_data;
  struct iobuf *io = &src->recv_iobuf;
  struct peer *peer = src == data->client.nc ? &data->client : &data->backend;

  if (peer->body_sent < peer->body_len) {
    size_t to_send = peer->body_len - peer->body_sent;
    if (io->len < to_send) {
      to_send = io->len;
    }
    ns_send(dst, io->buf, to_send);
    peer->body_sent += to_send;
  }

  if (peer->body_sent == peer->body_len) {
    disconnect_backend(src);
  }
}

static void start_forwarding(struct http_message *hm, struct ns_connection *src,
                             struct ns_connection *dst) {
  struct conn_data *data = (struct conn_data *) src->user_data;
  struct iobuf *io = &src->recv_iobuf;
  int i, is_request = src == data->client.nc;

  if (is_request) {
    /* Write rewritten request line. */
    size_t trim_len = strlen(data->be->uri_prefix);
    ns_printf(dst, "%.*s%s%.*s\r\n", (int) (hm->uri.p - io->buf),
              io->buf, data->be->uri_prefix_replacement,
              (int) (hm->proto.p + hm->proto.len - (hm->uri.p + trim_len)),
              hm->uri.p + trim_len);
  } else {
    /* Reply line goes without modification */
    ns_printf(dst, "%.*s %.*s %.*s\r\n", (int)hm->method.len, hm->method.p,
              (int)hm->uri.len, hm->uri.p, (int)hm->proto.len, hm->proto.p);
  }

  /* Headers. */
  for (i = 0; i < NS_MAX_HTTP_HEADERS && hm->header_names[i].len > 0; i++) {

#ifdef NS_ENABLE_SSL
    /*
     * If we terminate SSL and backend redirects to local HTTP port,
     * strip protocol to let client use HTTPS.
     * TODO(lsm): web page content may also contain local HTTP references,
     * they need to be rewritten too.
     */
    if (ns_vcasecmp(&hm->header_names[i], "Location") == 0 &&
        s_ssl_cert != NULL) {
      size_t hlen = strlen(data->be->host_port);
      const char *hp = data->be->host_port, *p = memchr(hp, ':', hlen);
      const struct ns_str *v = &hm->header_values[i];

      if (p == NULL) {
        p = hp + hlen;
      }

      if (ns_ncasecmp(v->p, "http://", 7) == 0 &&
          ns_ncasecmp(v->p + 7, hp, (p - hp)) == 0) {
        ns_printf(dst, "Location: %.*s\r\n", (int)(v->len - (7 + (p - hp))),
                  v->p + 7 + (p - hp));
        continue;
      }
    }
#endif

    ns_printf(dst, "%.*s: %.*s\r\n",
              (int) hm->header_names[i].len, hm->header_names[i].p,
              (int) hm->header_values[i].len, hm->header_values[i].p);
  }
  ns_printf(dst, "%s", "\r\n");

  iobuf_remove(io, hm->body.p - hm->message.p); /* We've forwarded headers */
  forward_body(src, dst);
}

/*
 * choose_backend parses incoming HTTP request and routes it to the appropriate
 * backend. It assumes that clients don't do HTTP pipelining, handling only
 * one request request for each connection. To give a hint to backend about
 * this it inserts "Connection: close" header into each forwarded request.
 */
static void connect_backend(struct ns_connection *nc, struct http_message *hm) {
  struct conn_data *data = NULL;
  struct http_backend *be = choose_backend(hm);

  write_log("%.*s %.*s backend=%d\n", (int) hm->method.len, hm->method.p,
            (int) hm->uri.len, hm->uri.p, (int) (be - s_http_backends));

  if (be == NULL) {
    /* No backend with given uri_prefix found, bail out */
    send_http_err(nc, s_error_500);
  } else if (be->redirect != 0) {
    ns_printf(nc, "HTTP/1.1 302 Found\r\nLocation: %s\r\n\r\n", be->host_port);
  } else if ((data = (struct conn_data *) calloc(1, sizeof(*data))) == NULL) {
    send_http_err(nc->user_data, s_error_500);
  } else if ((data->backend.nc =
                  ns_connect(nc->mgr, be->host_port, ev_handler)) == NULL) {
    write_log("Connection to [%s] failed\n", be->host_port);
    free(data);
    send_http_err(nc->user_data, s_error_500);
  } else {
    be->usage_counter++;
    data->be = be;
    data->client.nc = nc;
    data->client.body_len = hm->body.len;
    nc->user_data = data->backend.nc->user_data = data;
    ns_set_protocol_http_websocket(data->backend.nc);
    start_forwarding(hm, nc, data->backend.nc);
  }
}

static void ev_handler(struct ns_connection *nc, int ev, void *ev_data) {
  struct conn_data *data = (struct conn_data *) nc->user_data;

  switch (ev) {
    case NS_CONNECT:
      if (* (int *) ev_data != 0) {
        /* TODO(lsm): mark backend as defunct, try it later on */
        if (data != NULL) {
          send_http_err(data->client.nc, s_error_500);
        }
        disconnect_backend(nc);
      }
      break;
    case NS_HTTP_REQUEST:
      connect_backend(nc, ev_data);
      break;
    case NS_HTTP_REPLY:
      if (data != NULL) {
        data->backend.body_len = ((struct http_message *) ev_data)->body.len;
        start_forwarding(ev_data, nc, data->client.nc);
      }
      break;
    case NS_RECV:
      if (data != NULL) {
        forward_body(
            nc, nc == data->client.nc ? data->backend.nc : data->client.nc);
      }
      break;
    case NS_CLOSE:
      disconnect_backend(nc);
      break;
  }
}

static void print_usage_and_exit(const char *prog_name) {
  fprintf(stderr,
          "Usage: %s [-D debug_dump_file] [-p http_port] [-l log] "
#if NS_ENABLE_SSL
          "[-s ssl_cert] "
#endif
          "<[-r] [-v vhost] -b uri_prefix[=replacement] host_port> ... \n",
          prog_name);
  exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
  struct ns_mgr mgr;
  struct ns_connection *nc;
  int i, redirect = 0;
  const char *vhost = NULL;

  ns_mgr_init(&mgr, NULL);

  /* Parse command line arguments */
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-D") == 0) {
      mgr.hexdump_file = argv[i + 1];
      i++;
    } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
      s_log_file = fopen(argv[i + 1], "a");
      if (s_log_file == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
      }
      i++;
    } else if (strcmp(argv[i], "-p") == 0) {
      s_http_port = argv[i + 1];
      i++;
    } else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
      redirect = 1;
    } else if (strcmp(argv[i], "-v") == 0 && i + 1 < argc) {
      vhost = argv[i + 1];
      i++;
    } else if (strcmp(argv[i], "-b") == 0 && i + 2 < argc) {
      struct http_backend *be = &s_http_backends[s_num_http_backends];
      char *r = NULL;
      be->vhost = vhost;
      be->uri_prefix = argv[i + 1];
      be->host_port = argv[i + 2];
      be->redirect = redirect;
      be->uri_prefix_replacement = be->uri_prefix;
      if ((r = strchr(be->uri_prefix, '=')) != NULL) {
        *r = '\0';
        be->uri_prefix_replacement = r + 1;
      }
      printf(
          "Adding backend %d for %s%s : %s "
          "[redirect=%d,prefix_replacement=%s]\n",
          s_num_http_backends, be->vhost == NULL ? "" : be->vhost,
          be->uri_prefix, be->host_port, be->redirect,
          be->uri_prefix_replacement);
      vhost = NULL;
      redirect = 0;
      s_num_http_backends++;
      i += 2;
#ifdef NS_ENABLE_SSL
    } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
      s_ssl_cert = argv[++i];
#endif
    } else {
      print_usage_and_exit(argv[0]);
    }
  }

  /* Open listening socket */
  if ((nc = ns_bind(&mgr, s_http_port, ev_handler)) == NULL) {
    fprintf(stderr, "ns_bind(%s) failed\n", s_http_port);
    exit(EXIT_FAILURE);
  }

#if NS_ENABLE_SSL
  if (s_ssl_cert != NULL) {
    const char *err_str = ns_set_ssl(nc, s_ssl_cert, NULL);
    if (err_str != NULL) {
      fprintf(stderr, "Error loading SSL cert: %s\n", err_str);
      exit(1);
    }
  }
#endif
  ns_set_protocol_http_websocket(nc);

  if (s_num_http_backends == 0) {
    print_usage_and_exit(argv[0]);
  }

  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  /* Run event loop until signal is received */
  printf("Starting LB on port %s\n", s_http_port);
  while (s_sig_num == 0) {
    ns_mgr_poll(&mgr, 1000);
  }

  /* Cleanup */
  ns_mgr_free(&mgr);

  printf("Exiting on signal %d\n", s_sig_num);

  return EXIT_SUCCESS;
}
