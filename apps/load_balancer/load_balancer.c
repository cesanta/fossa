/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#include "../../fossa.h"

struct http_backend {
  const char *uri_prefix;   /* URI prefix, e.g. "/api/v1/", "/static/" */
  const char *host_port;    /* Backend address */
  int usage_counter;        /* Number of times this backend was chosen */
};

static const char *s_error_500 = "HTTP/1.1 500 Failed\r\n";
static const char *s_error_404 = "HTTP/1.1 404 Failed\r\n";
static const char *s_content_len_0 = "Content-Length: 0\r\n";
static const char *s_http_port = "8000";
static struct http_backend s_http_backends[100];
static int s_num_http_backends = 0;
static int s_sig_num = 0;
static void ev_handler(struct ns_connection *nc, int ev, void *ev_data);

static void signal_handler(int sig_num) {
  signal(sig_num, signal_handler);
  s_sig_num = sig_num;
}

static int has_prefix(const struct ns_str *uri, const char *prefix) {
  size_t prefix_len = strlen(prefix);
  return uri->len >= prefix_len && memcmp(uri->p, prefix, prefix_len) == 0;
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
     * backends with the same uri_prefix.
     */
    int i, chosen = -1;
    for (i = 0; i < s_num_http_backends; i++) {
      if (has_prefix(&hm.uri, s_http_backends[i].uri_prefix) &&
          (chosen == -1 || s_http_backends[i].usage_counter <
           s_http_backends[chosen].usage_counter)) {
        chosen = i;
      }
    }

    if (chosen == -1) {
      /* No backend with given uri_prefix found, bail out */
      ns_printf(nc, "%s%s\r\n", s_error_404, s_content_len_0);
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
      ns_send(nc->proto_data, io->buf, io->len);
      iobuf_remove(io, io->len);
    }
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
        /* Forward data to peer */
        ns_send(peer, io->buf, io->len);
        iobuf_remove(io, io->len);
      }
      break;
    case NS_CLOSE:
      /* We're closing, detach our peer */
      if (peer != NULL) {
        peer->proto_data = NULL;
        peer->flags |= NSF_FINISHED_SENDING_DATA;
      }
      break;
  }
}

int main(int argc, char *argv[]) {
  struct ns_mgr mgr;
  int i;

  ns_mgr_init(&mgr, NULL);

  /* Parse command line arguments */
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-D") == 0) {
      mgr.hexdump_file = argv[i + 1];
      i++;
    } else if (strcmp(argv[i], "-p") == 0) {
      s_http_port = argv[i + 1];
      i++;
    } else if (strcmp(argv[i], "-b") == 0 && i + 2 < argc) {
      s_http_backends[s_num_http_backends].uri_prefix = argv[i + 1];
      s_http_backends[s_num_http_backends].host_port = argv[i + 2];
      s_num_http_backends++;
      i += 2;
    }
  }

  /* Open listening socket */
  if (ns_bind(&mgr, s_http_port, ev_handler) == NULL) {
    fprintf(stderr, "ns_bind(%s) failed\n", s_http_port);
    exit(EXIT_FAILURE);
  }

  if (s_num_http_backends == 0) {
    fprintf(stderr, "Usage: %s [-D] [-p http_port] "
            "<-b uri_prefix host_port> ...\n", argv[0]);
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
