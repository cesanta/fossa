#include "net_skeleton.h"

static int s_received_signal = 0;

struct nc_config {
  const char *listening_port;
  const char *ssl_certificate;
  const char *ca_ssl_certificate;
  const char *hexdump_file;
  const char *target_host;
  const char *target_port;
  const char *target_uses_ssl;
};

static void signal_handler(int sig_num) {
  signal(sig_num, signal_handler);
  s_received_signal = sig_num;
}

static void elog(int do_exit, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
  if (do_exit) exit(EXIT_FAILURE);
}

static void show_usage_and_exit(const char *prog_name) {
  elog(0, "%s", "Copyright (c) 2014 CESANTA SOFTWARE");
  elog(0, "%s", "Usage:");
  elog(0, "%s [-d] [-s cert] [-l listening_port]", prog_name);
  elog(1, "%s [-d] [-S] [-s cert] <host> <port>", prog_name);
}

static void on_stdin_read(struct ns_connection *nc, enum ns_event ev, void *p) {
  int ch = * (int *) p;

  (void) ev;

  if (ch < 0) {
    // EOF is received from stdin. Schedule the connection to close
    nc->flags |= NSF_FINISHED_SENDING_DATA;
    if (nc->send_iobuf.len <= 0) {
      nc->flags |= NSF_CLOSE_IMMEDIATELY;
    }
  } else {
    // A character is received from stdin. Send it to the connection.
    unsigned char c = (unsigned char) ch;
    ns_send(nc, &c, 1);
  }
}

static void *stdio_thread_func(void *param) {
  struct ns_server *server = (struct ns_server *) param;
  int ch;

  // Read stdin until EOF character by character, sending them to the server
  while ((ch = getchar()) != EOF) {
    ns_server_wakeup_ex(server, on_stdin_read, &ch, sizeof(ch));
  }
  s_received_signal = 1;

  return NULL;
}

static void ev_handler(struct ns_connection *nc, enum ns_event ev, void *p) {
  (void) p;

  switch (ev) {
    case NS_ACCEPT:
    case NS_CONNECT:
      ns_start_thread(stdio_thread_func, nc->server);
      break;

    case NS_CLOSE:
      s_received_signal = 1;
      break;

    case NS_RECV:
      fwrite(nc->recv_iobuf.buf, 1, nc->recv_iobuf.len, stdout);
      iobuf_remove(&nc->recv_iobuf, nc->recv_iobuf.len);
      break;

    default:
      break;
  }
}

static void start_netcat(struct nc_config *cfg) {
  struct ns_server server;
  char resolved_target_ip[60] = "";

  ns_server_init(&server, cfg, ev_handler);

  if (cfg->listening_port != NULL &&
      ns_bind(&server, cfg->listening_port) < 0) {
    elog(1, "ns_bind(%s) failed", cfg->listening_port);
  } else if (cfg->target_host != NULL &&
             ns_resolve(cfg->target_host, resolved_target_ip,
                        sizeof(resolved_target_ip)) <= 0) {
    elog(1, "resolve(%s) failed", cfg->target_host);
  } else if (cfg->ssl_certificate != NULL && cfg->listening_port != NULL &&
             ns_set_ssl_cert(&server, cfg->ssl_certificate) != 0) {
    elog(1, "ns_set_ssl_cert(%s) failed", cfg->ssl_certificate);
  } else if (cfg->ca_ssl_certificate != NULL &&
             ns_set_ssl_ca_cert(&server, cfg->ca_ssl_certificate) != 0) {
    elog(1, "ns_set_ssl_ca_cert(%s) failed", cfg->ca_ssl_certificate);
  }

  if (resolved_target_ip[0] != '\0') {
    if (ns_connect2(&server, resolved_target_ip, atoi(cfg->target_port),
                    cfg->target_uses_ssl != NULL, cfg->ssl_certificate,
                    cfg->ca_ssl_certificate,  NULL) == NULL) {
      elog(1, "ns_connect2(%s:%s) error (ssl: %s)", cfg->target_host,
           cfg->target_port, cfg->target_uses_ssl ? "yes" : "no");
    }
  }

  server.hexdump_file = cfg->hexdump_file;

  while (s_received_signal == 0) {
    ns_server_poll(&server, 1000);
  }
  ns_server_free(&server);
}

int main(int argc, char *argv[]) {
  struct nc_config nc_config;
  int i;

  memset(&nc_config, 0, sizeof(nc_config));

  // Parse command line options
  for (i = 1; i < argc && argv[i][0] == '-'; i++) {
    if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
      nc_config.listening_port = argv[++i];
    } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
      nc_config.ssl_certificate = argv[++i];
    } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
      nc_config.ca_ssl_certificate = argv[++i];
    } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
      nc_config.hexdump_file = argv[++i];
    } else if (strcmp(argv[i], "-S") == 0) {
      nc_config.target_uses_ssl = "yes";
    } else {
      show_usage_and_exit(argv[0]);
    }
  }

  if (i < argc && i + 2 == argc) {
    nc_config.target_host = argv[i];
    nc_config.target_port = argv[i + 1];
  }

  if ((nc_config.target_host == NULL && nc_config.listening_port == NULL) ||
      (nc_config.target_host != NULL && nc_config.listening_port != NULL)) {
    show_usage_and_exit(argv[0]);
  }

  signal(SIGTERM, signal_handler);
  signal(SIGINT, signal_handler);

  start_netcat(&nc_config);

  return EXIT_SUCCESS;
}
