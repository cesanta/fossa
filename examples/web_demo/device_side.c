// Copyright (c) 2014 Cesanta Software Limited
// All rights reserved
//
// This program polls given file, and if it is modified, it sends it
// over the websocket connection to the specified server.

#include "net_skeleton.h"

static int s_received_signal = 0;
static int s_connected = 0;
static int s_poll_interval_ms = 100;
static int s_width = 400;
static int s_height = 200;
static const char *s_mjpg_file = "/var/run/shm/cam.jpg";

static void signal_handler(int sig_num) {
  signal(sig_num, signal_handler);
  s_received_signal = sig_num;
}

static void send_mjpg_frame(struct ns_connection *nc, const char *file_path) {
  struct stat st;
  FILE *fp;

  // Check file modification time.
  // If changed, send file content to the websocket
  if (stat(file_path, &st) == 0 &&
      st.st_mtime != (time_t) nc->user_data &&
      (fp = fopen(file_path, "rb")) != NULL) {

    // Read new mjpg frame into a buffer
    char buf[st.st_size];
    fread(buf, 1, sizeof(buf), fp);  // TODO (lsm): check error
    fclose(fp);

    // Send that buffer to a websocket connection
    ns_send_websocket_frame(nc, WEBSOCKET_OP_BINARY, buf, sizeof(buf));
    printf("Sent mjpg frame, %lu bytes\n", (unsigned long) sizeof(buf));

    // Store new modification time
    nc->user_data = (void *) st.st_mtime;
  }
}

static void ev_handler(struct ns_connection *nc, int ev, void *ev_data) {
  struct websocket_message *wm = (struct websocket_message *) ev_data;

  switch (ev) {
    case NS_CONNECT:
      printf("Reconnect: %s\n", * (int *) ev_data == 0 ? "ok" : "failed");
      if (* (int *) ev_data == 0) {
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
      break;
  }
}

// This thread regenerates s_mjpg_file every s_poll_interval_ms milliseconds.
// It is Raspberry PI specific, change this function on other systems.
static void *generate_mjpg_data_thread_func(void *param) {
  FILE *fp;
  char cmd[200], line[500];

  (void) param;
  snprintf(cmd, sizeof(cmd), "raspistill -w %d -h %d -n -q 80 -tl 1 "
           "-t 999999999 -v -o %s 2>&1", s_width, s_height, s_mjpg_file);

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

int main(int argc, char *argv[]) {
  struct ns_mgr mgr;
  time_t last_reconnect_time = 0, now = 0;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s <server_address>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  signal(SIGTERM, signal_handler);
  signal(SIGINT, signal_handler);
  signal(SIGPIPE, SIG_IGN);

  // Start separate thread that generates MJPG data
  ns_start_thread(generate_mjpg_data_thread_func, NULL);

  printf("Streaming [%s] to [%s]\n", s_mjpg_file, argv[1]);

  ns_mgr_init(&mgr, NULL);

  while (s_received_signal == 0) {
    now = ns_mgr_poll(&mgr, s_poll_interval_ms);
    if (s_connected == 0 && now - last_reconnect_time > 0) {
      // Reconnect if disconnected
      printf("Reconnecting to %s...\n", argv[1]);
      struct ns_connection *nc = ns_connect(&mgr, argv[1], ev_handler);
      if (nc) {
        ns_set_protocol_http_websocket(nc);
      } else {
        printf("connection error, retring\n");
      }
      last_reconnect_time = now;  // Rate-limit reconnections to 1 per second
      s_connected = 1;
    }
  }
  ns_mgr_free(&mgr);

  printf("Quitting on signal %d\n", s_received_signal);

  return EXIT_SUCCESS;
}
