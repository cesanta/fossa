// Copyright (c) 2014 Cesanta Software Limited
// All rights reserved
//
// This file implements "netcat" utility with SSL and traffic hexdump.

#include "net_skeleton.h"

static int s_received_signal = 0;

static void signal_handler(int sig_num) {
  signal(sig_num, signal_handler);
  s_received_signal = sig_num;
}

static void show_usage_and_exit(const char *prog_name) {
  fprintf(stderr, "%s\n", "Copyright (c) 2014 CESANTA SOFTWARE");
  fprintf(stderr, "%s\n", "Usage:");
  fprintf(stderr, "  %s\n [-d debug_file] [-l] [tcp|ssl]://[ip:]port[:cert][:ca_cert]",
          prog_name);
  fprintf(stderr, "%s\n", "Examples:");
  fprintf(stderr, "  %s\n -d hexdump.txt ssl://google.com:443", prog_name);
  fprintf(stderr, "  %s\n -l ssl://443:ssl_cert.pem", prog_name);
  fprintf(stderr, "  %s\n -l tcp://8080", prog_name);
  exit(EXIT_FAILURE);
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

int main(int argc, char *argv[]) {
  struct ns_server server;
  int i, is_listening = 0;
  const char *address = NULL;

  ns_server_init(&server, NULL, ev_handler);

  // Parse command line options
  for (i = 1; i < argc && argv[i][0] == '-'; i++) {
    if (strcmp(argv[i], "-l") == 0) {
      is_listening = 1;
    } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
      server.hexdump_file = argv[++i];
    } else {
      show_usage_and_exit(argv[0]);
    }
  }

  if (i + 1 == argc) {
    address = argv[i];
  } else {
    show_usage_and_exit(argv[0]);
  }

  signal(SIGTERM, signal_handler);
  signal(SIGINT, signal_handler);
  signal(SIGPIPE, SIG_IGN);

  if (is_listening) {
    if (ns_bind(&server, address) == NULL) {
      fprintf(stderr, "ns_bind(%s) failed\n", address);
      exit(EXIT_FAILURE);
    }
  } else if (ns_connect(&server, address, NULL) == NULL) {
    fprintf(stderr, "ns_connect(%s) failed\n", address);
    exit(EXIT_FAILURE);
  }

  while (s_received_signal == 0) {
    ns_server_poll(&server, 1000);
  }
  ns_server_free(&server);

  return EXIT_SUCCESS;
}
