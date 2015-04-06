/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#include "../../fossa.h"

struct http_backend {
  const char *vhost;        /* NULL if any host */
  const char *uri_prefix;   /* URI prefix, e.g. "/api/v1/", "/static/" */
  const char *uri_prefix_replacement; /* if not NULL, will replace uri_prefix in requests to backends */
  const char *host_port;    /* Backend address */
  int redirect;              /* if true redirect instead of proxy */
  int usage_counter;        /* Number of times this backend was chosen */
};

static const char *s_error_500 = "HTTP/1.1 500 Failed\r\n";
static const char *s_error_404 = "HTTP/1.1 404 Failed\r\n";
static const char *s_content_len_0 = "Content-Length: 0\r\n";
static const char *s_http_port = "8000";
#define MAX_BACKENDS 100
static struct http_backend s_http_backends[MAX_BACKENDS];
static int s_num_http_backends = 0;
static int s_sig_num = 0;
#ifdef NS_ENABLE_SSL
const char *s_ssl_cert = NULL;
#endif
static void ev_handler(struct ns_connection *nc, int ev, void *ev_data);

static void signal_handler(int sig_num) {
  signal(sig_num, signal_handler);
  s_sig_num = sig_num;
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

static void choose_backend(struct ns_connection *nc) {
  struct http_message hm;
  struct iobuf *io = &nc->recv_iobuf;
  int req_len = ns_parse_http(io->buf, io->len, &hm);

  if (req_len < 0 || (req_len == 0 && io->len >= NS_MAX_HTTP_REQUEST_SIZE)) {
    /* Invalid, or too large request */
    nc->flags |= NSF_CLOSE_IMMEDIATELY;
  } else if (req_len == 0) {
    /* Do nothing, request is not yet fully buffered */
  } else {
    /*
     * Got HTTP request, look which backend to use. Round-robin over the
     * backends with the same uri_prefix and vhost.
     */
    int i, chosen = -1;
    struct ns_str vhost = *ns_get_http_header(&hm, "host");
    const char *vhost_end = vhost.p;
    while(vhost_end < vhost.p + vhost.len &&
          *vhost_end != ':') {
      vhost_end++;
    }
    vhost.len = vhost_end - vhost.p;

    for (i = 0; i < s_num_http_backends; i++) {
      if (has_prefix(&hm.uri, s_http_backends[i].uri_prefix) &&
          matches_vhost(&vhost, s_http_backends[i].vhost) &&
          (chosen == -1 || s_http_backends[i].usage_counter <
           s_http_backends[chosen].usage_counter)) {
        chosen = i;
      }
    }

    if (chosen == -1) {
      /* No backend with given uri_prefix found, bail out */
      ns_printf(nc, "%s%s\r\n", s_error_404, s_content_len_0);
    } else if (s_http_backends[chosen].redirect != 0) {
      ns_printf(nc, "HTTP/1.1 302 Found\r\nLocation: %s\r\n\r\n",
                s_http_backends[chosen].host_port);
      nc->flags |= NSF_SEND_AND_CLOSE;
    } else if ((nc->proto_data = ns_connect(nc->mgr,
               s_http_backends[chosen].host_port, ev_handler)) == NULL) {
      /* Connection to backend failed */
      ns_printf(nc, "%s%s\r\n", s_error_500, s_content_len_0);
    } else {
      /*
       * Forward request to the backend. Note that we can insert extra headers
       * to pass information to the backend.
       * Store backend index as user_data for the backend connection.
       */
      ((struct ns_connection *) nc->proto_data)->proto_data = nc;
      ((struct ns_connection *) nc->proto_data)->user_data =
        (void *) (long) chosen;
      s_http_backends[chosen].usage_counter++;
      if (s_http_backends[chosen].uri_prefix_replacement != NULL) {
        const char *headers = NULL;
        size_t trim_len;
        /* Mark client connection so we can rewrite future requests. */
        nc->user_data = (void *) (long) MAX_BACKENDS;
        /*
         * Figure out how many characters to remove. URI length was checked by
         * has_prefix() during backend selection.
         */
        trim_len = strlen(s_http_backends[chosen].uri_prefix);
        /* Write rewritten request line. */
        ns_printf(nc->proto_data, "%.*s %s%.*s",
            (int) hm.method.len, hm.method.p,
            s_http_backends[chosen].uri_prefix_replacement,
            (int) (hm.uri.len - trim_len), hm.uri.p + trim_len);
        if (hm.query_string.len > 0) {
          ns_printf(nc->proto_data, "?%.*s", (int) hm.query_string.len,
                    hm.query_string.p);
        }
        ns_printf(nc->proto_data, " %.*s\r\n", (int) hm.proto.len, hm.proto.p);
        /*
         * Forward the rest of the headers as is. This code assumes that fields
         * of hm point to the io iobuf.
         */
        headers = hm.proto.p + hm.proto.len;
        while (headers < io->buf + io->len &&
               (*headers == '\r' || *headers == '\n')) {
          headers++;
        }
        ns_send(nc->proto_data, headers, io->len - (headers - io->buf));
      } else {
        /* Forward request as is. */
        ns_send(nc->proto_data, io->buf, io->len);
      }
      iobuf_remove(io, io->len);
    }
  }
}

static void rewrite_request(struct ns_connection *nc, struct http_backend *be) {
  struct http_message hm;
  struct iobuf *io = &nc->recv_iobuf;
  int req_len = ns_parse_http(io->buf, io->len, &hm);

  if (req_len < 0 || (req_len == 0 && io->len >= NS_MAX_HTTP_REQUEST_SIZE)) {
    /* Invalid, or too large request */
    nc->flags |= NSF_CLOSE_IMMEDIATELY;
  } else if (req_len == 0) {
    /* Do nothing, request is not yet fully buffered */
  } else {
    /*
     * Got HTTP request, we already have a connection to the backend, so
     * just forward the request.
     */
    be->usage_counter++;
    if (be->uri_prefix_replacement != NULL) {
      const char *headers = NULL;
      size_t trim_len;
      /*
       * Figure out how many characters to remove. URI length was checked by
       * has_prefix() during backend selection.
       */
      trim_len = strlen(be->uri_prefix);
      /* Write rewritten request line. */
      ns_printf(nc->proto_data, "%.*s %s%.*s",
          (int) hm.method.len, hm.method.p,
          be->uri_prefix_replacement,
          (int) (hm.uri.len - trim_len), hm.uri.p + trim_len);
      if (hm.query_string.len > 0) {
        ns_printf(nc->proto_data, "?%.*s", (int) hm.query_string.len,
                  hm.query_string.p);
      }
      ns_printf(nc->proto_data, " %.*s\r\n", (int) hm.proto.len, hm.proto.p);
      /*
       * Forward the rest of the headers as is. This code assumes that fields
       * of hm point to the io iobuf.
       */
      headers = hm.proto.p + hm.proto.len;
      while (headers < io->buf + io->len &&
             (*headers == '\r' || *headers == '\n')) {
        headers++;
      }
      ns_send(nc->proto_data, headers, io->len - (headers - io->buf));
    } else {
      /* Forward request as is. */
      ns_send(nc->proto_data, io->buf, io->len);
    }
    iobuf_remove(io, io->len);
  }
}

static void ev_handler(struct ns_connection *nc, int ev, void *ev_data) {
  struct iobuf *io = &nc->recv_iobuf;
  struct ns_connection *peer = (struct ns_connection *) nc->proto_data;

  switch (ev) {
    case NS_CONNECT:
      if (* (int *) ev_data != 0) {
        /* TODO(lsm): mark backend as defunct, try it later on */
        fprintf(stderr, "connect(%s) failed\n",
                s_http_backends[(int) nc->user_data].host_port);
        ns_printf(nc->proto_data, "%s%s\r\n", s_error_500, s_content_len_0);
      }
      break;
    case NS_RECV:
      /*
       * For incoming client connection, nc->proto_data points to the respective
       * backend connection. For backend connection, nc->proto_data points
       * to the respective incoming client connection.
       */
      if (peer == NULL) {
        choose_backend(nc);
      } else {
        /* Check for special marker on connection that need URI rewrite. */
        if ((int) nc->user_data == MAX_BACKENDS) {
          rewrite_request(nc, &s_http_backends[(int) peer->user_data]);
        } else {
          /* Forward data to peer */
          ns_send(peer, io->buf, io->len);
          iobuf_remove(io, io->len);
        }
      }
      break;
    case NS_CLOSE:
      /* We're closing, detach our peer */
      if (peer != NULL) {
        peer->proto_data = NULL;
        peer->flags |= NSF_SEND_AND_CLOSE;
      }
      break;
  }
}

int main(int argc, char *argv[]) {
  struct ns_mgr mgr;
  struct ns_connection *nc;
  int i;
  int redirect = 0;
  const char *vhost = NULL;

  ns_mgr_init(&mgr, NULL);

  /* Parse command line arguments */
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-D") == 0) {
      mgr.hexdump_file = argv[i + 1];
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
      struct http_backend *backend = &s_http_backends[s_num_http_backends];
      char *r = NULL;
      s_num_http_backends++;
      backend->vhost = vhost;
      backend->uri_prefix = argv[i + 1];
      backend->host_port = argv[i + 2];
      backend->redirect = redirect;
      if ((r = strchr(backend->uri_prefix, '=')) != NULL) {
        *r = '\0';
        backend->uri_prefix_replacement = r+1;
      }
      printf("Adding a new backend for %s%s : %s "
             "[redirect=%d,prefix_replacement=%s]\n",
             backend->vhost == NULL ? "" : backend->vhost, backend->uri_prefix,
             backend->host_port, backend->redirect,
             backend->uri_prefix_replacement == NULL ?
               backend->uri_prefix :
               backend->uri_prefix_replacement);
      vhost = NULL;
      redirect = 0;
      i += 2;
#ifdef NS_ENABLE_SSL
    } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
      s_ssl_cert = argv[++i];
#endif
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

  if (s_num_http_backends == 0) {
    fprintf(stderr, "Usage: %s [-D debug_dump_file] [-p http_port] "
#if NS_ENABLE_SSL
            "[-s ssl_cert] "
#endif
            "<[-r] [-v vhost] -b uri_prefix[=replacement] host_port> ... \n", argv[0]);
    exit(EXIT_FAILURE);
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
