/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */
 
#include <Ethernet.h>
#include <SPI.h>
#include "fossa.h"

/* 
 * Build and run instructions:
 * 1. Add (Sketch->Add files...) the following files to sketch:
 *    - /fossa/fossa.h
 *    - /fossa/fossa.c
 *    - /fossa/platforms/arduino_ethernet_W5100/avrsupport.h
 *    - /fossa/platforms/arduino_ethernet_W5100/avrsupport.cpp
 * 2. Make board_ip variable suitable for your network
 * 3. Compile & flash sketch
 * 4. Run curl http://<board_ip/blink
 *    LED attached to PIN 13 will blink and board free memory size and uptime will responsed
 */
 
uint8_t board_mac[] = {
  0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED
};

uint8_t board_ip[] = {192, 168, 10, 177};

static const char *s_http_port = "60000";

static void rfs_ev_handler(struct ns_connection *nc, int ev, void *ev_data) {
  struct http_message *hm = (struct http_message *) ev_data;
  char buf[100];
  int clen;

  switch (ev) {
    case NS_HTTP_REQUEST:      
      if (ns_vcmp(&hm->uri, "/blink") == 0) {
        blink(1, 500);
      }

      clen = snprintf(buf, sizeof(buf),
                      "Free memory size: %d Uptime: %d",
                      (int)get_freememsize(), (int)time(NULL));

      ns_printf_http_chunk(nc, "HTTP/1.1 200 OK\r\n"
                               "Content-Length: %d\r\n"
                               "Transfer-Encoding: chunked\r\n\r\n"
                               "%s",
                               clen, buf);

      ns_send_http_chunk(nc, "", 0);
      break;
    case NS_SEND:
      nc->flags |= NSF_CLOSE_IMMEDIATELY;
      break;
      
    default:
      break;
  }
}

struct ns_connection *nc;
struct ns_mgr mgr;

void setup() {
  avr_netinit(board_mac, board_ip);

  ns_mgr_init(&mgr, NULL);
  nc = ns_bind(&mgr, s_http_port, rfs_ev_handler);
  ns_set_protocol_http_websocket(nc);
}

void loop() {
  ns_mgr_poll(&mgr, 1000);
}
