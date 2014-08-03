#include "net_skeleton.h"

static int s_received_signal = 0;

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
  elog(0, "%s [-c cert] [-l listening_port] ", prog_name);
  elog(1, "%s [-c cert] [host] [port]", prog_name);
}

int main(int argc, char *argv[]) {
  const char *cert = NULL, *host = NULL, *port = "2014";
  const char *listen_port = NULL, *hexdump = NULL;
  int i;

  // Parse command line options
  for (i = 1; i < argc && argv[i][0] == '-'; i++) {
    if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
      listen_port = argv[++i];
    } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
      cert = argv[++i];
    } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
      hexdump = argv[i];
    } else {
      show_usage_and_exit(argv[0]);
    }
  }

  if (i < argc && i + 2 == argc) {
    host = argv[i];
    port = argv[i + 1];
  } else {
    show_usage_and_exit(argv[0]);
  }

  signal(SIGTERM, signal_handler);
  signal(SIGINT, signal_handler);

  return EXIT_SUCCESS;
}
