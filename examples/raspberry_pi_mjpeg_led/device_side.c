// Copyright (c) 2014 Cesanta Software Limited
// All rights reserved
//
// This program polls given file, and if it is modified, it sends it
// over the websocket connection to the specified server.

#include <unistd.h>
#include "net_skeleton.h"

static int s_received_signal = 0;
static int s_connected = 0;
static int s_poll_interval_ms = 100;
static int s_still_period = 1000;
static int s_vertical_flip = 0;
static int s_width = 320*2;
static int s_height = 180*2;
static int s_jpegoptim_level = 60;
static const char *s_mjpg_file = "/var/run/shm/cam.jpg";
static const char *s_mjpg_opti_file = "/var/run/shm/cam-opti.jpg";
static int s_led_state = 0;

static void signal_handler(int sig_num) {
  signal(sig_num, signal_handler);
  s_received_signal = sig_num;
}

static void set_gpio(int pin, int v) {
  char gpio_file[200];
  snprintf(gpio_file, sizeof(gpio_file), "/sys/class/gpio/gpio%d/value", pin);

  FILE *fp;
  if ((fp = fopen(gpio_file, "w")) == NULL) {
    printf("Failed to open gpio file %s: %s\n", gpio_file, strerror(errno));
    return;
  }
  fprintf(fp, "%d", v);
  fclose(fp);
}

static void set_led(int v) {
  printf("Setting led to %d\n", v);
  set_gpio(22, v);
  set_gpio(23, v);
  set_gpio(24, v);

  s_led_state = v;
}

static const char* optimize_jpeg(const char *file_path) {
  FILE *fp;
  char cmd[200], line[500];
  snprintf(cmd, sizeof(cmd), "mv %s %s; jpegoptim -m%d --strip-all %s", file_path, s_mjpg_opti_file, s_jpegoptim_level, s_mjpg_opti_file);

  if ((fp = popen(cmd, "r")) == NULL) {
    perror("cannot optimize jpeg");
    return file_path;
  }

  while (fgets(line, sizeof(line), fp) != NULL) {
    //printf("==> %s", line);
  }
  fclose(fp);

  return s_mjpg_opti_file;
}

static void send_mjpg_frame(struct ns_connection *nc, const char *file_path) {
  static int skipped_frames = 0;
  struct stat st;
  FILE *fp;

  // Check file modification time.
  // Send if there is not too much data enqueued.
  // /* If changed, send file content to the websocket */
  if (stat(file_path, &st) == 0
      /* && st.st_mtime != (time_t) nc->user_data */) {

    printf("send buffer length: %lu\n", (unsigned long)(nc->send_iobuf.len));
    if (nc->send_iobuf.len > 256) {
      skipped_frames++;
      // Store new modification time
      nc->user_data = (void *) st.st_mtime;
      return;
    }

    const char *optimized_file = optimize_jpeg(file_path);
    printf("Opening %s\n", optimized_file);

    if ((fp = fopen(optimized_file, "rb")) == NULL) {
      perror("cannot open optimized jpeg");
      return;
    }
    stat(optimized_file, &st);

    // Timestamp
    uint32_t time_stamp = htonl(st.st_mtime);

    // Read new mjpg frame into a buffer
    char buf[st.st_size];
    fread(buf, 1, sizeof(buf), fp);  // TODO (lsm): check error
    fclose(fp);

    // Send timestamp as header and then the image as payload.
    struct ns_str buffers[] = {
      {(const char*)&time_stamp, sizeof(time_stamp)},
      {buf, sizeof(buf)}
    };

    // Send those buffers to a websocket connection
    ns_send_websocket_framev(nc, WEBSOCKET_OP_BINARY, buffers, 2);
    printf("Sent mjpg frame, %lu bytes after skippping %d frames\n", (unsigned long) sizeof(buf), skipped_frames);
    skipped_frames = 0;
    // Store new modification time
    nc->user_data = (void *) st.st_mtime;
  }
}

static void perform_control_command(const char* data, size_t len) {
  struct json_token toks[200], *onoff;
  int n = parse_json(data, len, toks, sizeof(toks));
  if (n < 0) {
    printf("invalid json\n");
    return;
  }

  onoff = find_json_token(toks, "onoff");
  if (onoff == NULL) {
    printf("invalid json\n");
    return;
  }

  set_led(strncmp("[\"on\"]", onoff->ptr, onoff->len) == 0);
}

static void ev_handler(struct ns_connection *nc, int ev, void *ev_data) {
  struct websocket_message *wm = (struct websocket_message *) ev_data;

  switch (ev) {
    case NS_CONNECT:
      printf("Reconnect: %s\n", * (int *) ev_data == 0 ? "ok" : "failed");
      if (* (int *) ev_data == 0) {
        int sndbuf_size = 512;
        if(setsockopt(nc->sock, SOL_SOCKET, SO_SNDBUF, (void *) &sndbuf_size, sizeof(int)) == -1) {
          perror("failed to tune TCP send buffer size\n");
        }

        ns_send_websocket_handshake(nc, "/stream", NULL);
      }
      break;
    case NS_CLOSE:
      printf("Connection %p closed\n", nc);
      s_connected = 0;
      break;
    case NS_POLL:
      send_mjpg_frame(nc, s_mjpg_file);
      break;
    case NS_WEBSOCKET_FRAME:
      printf("GOT CONTROL COMMAND: [%.*s]\n", (int) wm->size, wm->data);
      perform_control_command((const char*)wm->data, wm->size);
      break;
  }
}

// This thread regenerates s_mjpg_file every s_poll_interval_ms milliseconds.
// It is Raspberry PI specific, change this function on other systems.
static void *generate_mjpg_data_thread_func(void *param) {
  FILE *fp;
  char cmd[200], line[500];

  (void) param;
  snprintf(cmd, sizeof(cmd), "raspistill -w %d -h %d -n -q 100 -tl %d "
           "-t 999999999 -v %s -o %s 2>&1", s_width, s_height, s_still_period,
           s_vertical_flip ? "-vf" : "", s_mjpg_file);

  for (;;) {
    if ((fp = popen(cmd, "r")) != NULL) {
      while (fgets(line, sizeof(line), fp) != NULL) {
        //printf("==> %s", line);
      }
      fclose(fp);
    }
    sleep(1);
  }

  return NULL;
}

void usage(char *argv[]) {
  fprintf(stderr, "Usage: %s [-t still_period_ms] [-v] <server_address>\n", argv[0]);
  exit(EXIT_FAILURE);
}

void parse_flags(int argc, char *argv[]) {
  int opt;
  while((opt = getopt(argc, argv, "vt:w:h:")) != -1) {
    switch(opt) {
    case 'v':
      s_vertical_flip = 1;
      break;
    case 't':
      s_still_period = atoi(optarg);
      if (s_still_period == 0) {
        printf("Invalid still interval '%s'\n", optarg);
        exit(EXIT_FAILURE);
      }
      break;
    case 'w':
      s_width = atoi(optarg);
      if (s_width == 0) {
        printf("Invalid width '%s'\n", optarg);
        exit(EXIT_FAILURE);
      }
      break;
    case 'h':
      s_height = atoi(optarg);
      if (s_height == 0) {
        printf("Invalid height '%s'\n", optarg);
        exit(EXIT_FAILURE);
      }
      break;
    case '?':
      printf("Unknown flag -%c\n", optopt);
        exit(EXIT_FAILURE);

      break;
    }
  }
}

int main(int argc, char *argv[]) {
  parse_flags(argc, argv);

  char *addr = argv[optind];

  struct ns_mgr mgr;
  time_t last_reconnect_time = 0, now = 0;

  if (argc < optind + 1) {
    usage(argv);
  }

  signal(SIGTERM, signal_handler);
  signal(SIGINT, signal_handler);
  signal(SIGPIPE, SIG_IGN);

  // Start separate thread that generates MJPG data
  ns_start_thread(generate_mjpg_data_thread_func, NULL);

  printf("Streaming [%s] to [%s]\n", s_mjpg_file, addr);

  ns_mgr_init(&mgr, NULL);

  char *error_string = NULL;
  static struct ns_connect_opts connect_opts;
  connect_opts.error_string = &error_string;

  while (s_received_signal == 0) {
    now = ns_mgr_poll(&mgr, s_poll_interval_ms);
    if (s_connected == 0 && now - last_reconnect_time > 0) {
      // Reconnect if disconnected
      printf("Reconnecting to %s...\n", addr);
      struct ns_connection *nc = ns_connect_opt(&mgr, addr, ev_handler, connect_opts);

      last_reconnect_time = now;  // Rate-limit reconnections to 1 per second
      if (nc) {
        ns_set_protocol_http_websocket(nc);
        s_connected = 1;
      } else {
        printf("connection error, retring: %s\n", error_string ? error_string : "");
      }
    }
  }
  ns_mgr_free(&mgr);

  printf("Quitting on signal %d\n", s_received_signal);

  return EXIT_SUCCESS;
}
