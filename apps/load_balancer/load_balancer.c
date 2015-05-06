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
  int64_t body_len;  /* Size of the HTTP body to forward */
  int64_t body_sent; /* Number of bytes already forwarded */
  struct {
    /* Headers have been sent, no more headers. */
    unsigned int headers_sent : 1;
  } flags;
};

struct conn_data {
  struct http_backend *be; /* Chosen backend */
  struct peer client;      /* Client peer */
  struct peer backend;     /* Backend peer */
};

static const char *s_error_500 = "HTTP/1.1 500 Failed\r\n";
static const char *s_content_len_0 = "Content-Length: 0\r\n";
static const char *s_connection_close = "Connection: close\r\n";
static const char *s_http_port = "8000";
static struct http_backend s_vhost_backends[100], s_default_backends[100];
static int s_num_vhost_backends = 0, s_num_default_backends = 0;
static int s_sig_num = 0;
static FILE *s_log_file = NULL;
#ifdef NS_ENABLE_SSL
const char *s_ssl_cert = NULL;
#endif

static void ev_handler(struct ns_connection *nc, int ev, void *ev_data);
static void write_log(const char *fmt, ...);

static void signal_handler(int sig_num) {
  signal(sig_num, signal_handler);
  s_sig_num = sig_num;
}

static void send_http_err(struct ns_connection *nc, const char *err_line) {
  ns_printf(nc, "%s%s%s\r\n", err_line, s_content_len_0, s_connection_close);
}

static void respond_with_error(struct conn_data *conn, const char *err_line) {
  struct ns_connection *nc = conn->client.nc;
  int headers_sent = conn->client.flags.headers_sent;
#ifdef DEBUG
  write_log("conn=%p nc=%p respond_with_error %d\n", conn, nc, headers_sent);
#endif
  if (nc == NULL) return;
  if (!headers_sent) {
    send_http_err(nc, err_line);
    conn->client.flags.headers_sent = 1;
  }
  nc->flags |= NSF_SEND_AND_CLOSE;
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

static struct http_backend *choose_backend_from_list(
    struct http_message *hm, struct http_backend *backends, int num_backends) {
  int i;
  struct ns_str vhost = {"", 0};
  const struct ns_str *host = ns_get_http_header(hm, "host");
  if (host != NULL) vhost = *host;

  const char *vhost_end = vhost.p;

  while (vhost_end < vhost.p + vhost.len && *vhost_end != ':') {
    vhost_end++;
  }
  vhost.len = vhost_end - vhost.p;

  struct http_backend *chosen = NULL;
  for (i = 0; i < num_backends; i++) {
    struct http_backend *be = &backends[i];
    if (has_prefix(&hm->uri, be->uri_prefix) &&
        matches_vhost(&vhost, be->vhost) &&
        (chosen == NULL ||
         /* Prefer most specific URI prefixes */
         strlen(be->uri_prefix) > strlen(chosen->uri_prefix) ||
         /* Among prefixes of the same length chose the least used. */
         (strlen(be->uri_prefix) == strlen(chosen->uri_prefix) &&
          be->usage_counter < chosen->usage_counter))) {
      chosen = be;
    }
  }

  return chosen;
}

static struct http_backend *choose_backend(struct http_message *hm) {
  struct http_backend *chosen =
      choose_backend_from_list(hm, s_vhost_backends, s_num_vhost_backends);

  /* Nothing was chosen for this vhost, look for vhost == NULL backends. */
  if (chosen == NULL) {
    chosen = choose_backend_from_list(hm, s_default_backends,
                                      s_num_default_backends);
  }

  if (chosen != NULL) chosen->usage_counter++;

  return chosen;
}

static void forward_body(struct peer *src, struct peer *dst) {
  struct mbuf *src_io = &src->nc->recv_mbuf;
  if (src->body_sent < src->body_len) {
    size_t to_send = src->body_len - src->body_sent;
    if (src_io->len < to_send) {
      to_send = src_io->len;
    }
    ns_send(dst->nc, src_io->buf, to_send);
    src->body_sent += to_send;
  }
#ifdef DEBUG
  write_log("forward_body %p -> %p sent %d of %d\n", src->nc, dst->nc,
            src->body_sent, src->body_len);
#endif
}

static void forward(struct http_message *hm, struct peer *src_peer,
                    struct peer *dst_peer) {
  struct ns_connection *src = src_peer->nc;
  struct ns_connection *dst = dst_peer->nc;
  struct conn_data *data = (struct conn_data *) src->user_data;
  struct mbuf *io = &src->recv_mbuf;
  int i;
  int is_request = (src_peer == &data->client);
  src_peer->body_len = hm->body.len;

  if (is_request) {
    /* Write rewritten request line. */
    size_t trim_len = strlen(data->be->uri_prefix);
    ns_printf(dst, "%.*s%s%.*s\r\n", (int) (hm->uri.p - io->buf), io->buf,
              data->be->uri_prefix_replacement,
              (int) (hm->proto.p + hm->proto.len - (hm->uri.p + trim_len)),
              hm->uri.p + trim_len);
  } else {
    /* Reply line goes without modification */
    ns_printf(dst, "%.*s %.*s %.*s\r\n", (int) hm->method.len, hm->method.p,
              (int) hm->uri.len, hm->uri.p, (int) hm->proto.len, hm->proto.p);
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
        ns_printf(dst, "Location: %.*s\r\n", (int) (v->len - (7 + (p - hp))),
                  v->p + 7 + (p - hp));
        continue;
      }
    }
#endif

    ns_printf(dst, "%.*s: %.*s\r\n", (int) hm->header_names[i].len,
              hm->header_names[i].p, (int) hm->header_values[i].len,
              hm->header_values[i].p);
  }
  ns_printf(dst, "%s", "\r\n");

  mbuf_remove(io, hm->body.p - hm->message.p); /* We've forwarded headers */
  dst_peer->flags.headers_sent = 1;

  forward_body(src_peer, dst_peer);
}

/*
 * choose_backend parses incoming HTTP request and routes it to the appropriate
 * backend. It assumes that clients don't do HTTP pipelining, handling only
 * one request request for each connection. To give a hint to backend about
 * this it inserts "Connection: close" header into each forwarded request.
 */
static int connect_backend(struct conn_data *conn, struct http_message *hm) {
  struct ns_connection *nc = conn->client.nc;
  struct http_backend *be = choose_backend(hm);

  write_log("%.*s %.*s backend=%s\n", (int) hm->method.len, hm->method.p,
            (int) hm->uri.len, hm->uri.p, be->host_port);

  if (be == NULL) return 0;
  if (be->redirect != 0) {
    ns_printf(nc, "HTTP/1.1 302 Found\r\nLocation: %s\r\n\r\n", be->host_port);
    return 1;
  }
  conn->backend.nc = ns_connect(nc->mgr, be->host_port, ev_handler);
  if (conn->backend.nc == NULL) {
    write_log("Connection to [%s] failed\n", be->host_port);
    return 0;
  }
  conn->be = be;
  conn->backend.nc->user_data = conn;
  ns_set_protocol_http_websocket(conn->backend.nc);
  return 1;
}

static void ev_handler(struct ns_connection *nc, int ev, void *ev_data) {
  struct conn_data *conn = (struct conn_data *) nc->user_data;
#ifdef DEBUG
  write_log("conn=%p nc=%p ev=%d data=%p data=%p\n", conn, nc, ev, ev_data);
#endif

  if (conn == NULL) {
    if (ev == NS_ACCEPT) {
      conn = calloc(1, sizeof(*conn));
      if (conn == NULL) {
        send_http_err(nc, s_error_500);
      } else {
        memset(conn, 0, sizeof(*conn));
        nc->user_data = conn;
        conn->client.body_len = -1;
        conn->backend.body_len = -1;
      }
      return;
    } else {
      nc->flags |= NSF_CLOSE_IMMEDIATELY;
      return;
    }
  }

  switch (ev) {
    case NS_HTTP_REQUEST: { /* From client */
      assert(conn != NULL);
      struct http_message *hm = (struct http_message *) ev_data;
      conn->client.nc = nc;

      if (!connect_backend(conn, hm)) {
        respond_with_error(conn, s_error_500);
        break;
      }

      if (conn->backend.nc == NULL) {
        /* This is a redirect, we're done. */
        conn->client.nc->flags |= NSF_SEND_AND_CLOSE;
        break;
      }

      forward(hm, &conn->client, &conn->backend);
      break;
    }

    case NS_CONNECT: { /* To backend */
      assert(conn != NULL);
      int status = *(int *) ev_data;
      if (status != 0) {
        /* TODO(lsm): mark backend as defunct, try it later on */
        respond_with_error(conn, s_error_500);
      }
      break;
    }

    case NS_HTTP_REPLY: { /* From backend */
      assert(conn != NULL);
      struct http_message *hm = (struct http_message *) ev_data;
      forward(hm, &conn->backend, &conn->client);
      /* TODO(rojer): Keepalive. */
      conn->client.nc->flags |= NSF_SEND_AND_CLOSE;
      break;
    }

    case NS_CLOSE: {
      assert(conn != NULL);
      if (nc == conn->client.nc) {
#ifdef DEBUG
        write_log("conn=%p nc=%p client closed, body_sent=%d\n", conn, nc,
                  conn->backend.body_sent);
#endif
        conn->client.nc = NULL;
        if (conn->backend.nc != NULL) {
          conn->backend.nc->flags |= NSF_CLOSE_IMMEDIATELY;
        }
      } else if (nc == conn->backend.nc) {
        conn->backend.nc = NULL;
        if (conn->client.nc != NULL &&
            (conn->backend.body_len < 0 ||
             conn->backend.body_sent < conn->backend.body_len)) {
          respond_with_error(conn, s_error_500);
        }
      }
      if (conn->client.nc == NULL && conn->backend.nc == NULL) {
        free(conn);
      }
      break;
    }
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
      if (strcmp(argv[i + 1], "-") == 0) {
        s_log_file = stdout;
      } else {
        s_log_file = fopen(argv[i + 1], "a");
        if (s_log_file == NULL) {
          perror("fopen");
          exit(EXIT_FAILURE);
        }
      }
      i++;
    } else if (strcmp(argv[i], "-p") == 0) {
      s_http_port = argv[i + 1];
      i++;
    } else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
      redirect = 1;
    } else if (strcmp(argv[i], "-v") == 0 && i + 1 < argc) {
      if (strcmp(argv[i + 1], "") == 0) {
        vhost = NULL;
      } else {
        vhost = argv[i + 1];
      }
      i++;
    } else if (strcmp(argv[i], "-b") == 0 && i + 2 < argc) {
      struct http_backend *be =
          vhost != NULL ? &s_vhost_backends[s_num_vhost_backends++]
                        : &s_default_backends[s_num_default_backends++];
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
          "Adding backend for %s%s : %s "
          "[redirect=%d,prefix_replacement=%s]\n",
          be->vhost == NULL ? "" : be->vhost, be->uri_prefix, be->host_port,
          be->redirect, be->uri_prefix_replacement);
      vhost = NULL;
      redirect = 0;
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

  if (s_num_vhost_backends + s_num_default_backends == 0) {
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
