
/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 * 
 * Build and run instructions:
 * To run with Arduino Ethernet (W5100) shield:
 * -----------------------------------------------------------
 *  1. Add (Sketch->Add file...) the following files to sketch:
 *     - /fossa/fossa.h
 *     - /fossa/fossa.c
 *     - /fossa/platforms/arduino_ethernet_W5100/avrsupport.h
 *     - /fossa/platforms/arduino_ethernet_W5100/avrsupport.cpp
 *  2. Buils and run in console /Users/alex/Projects/fossa/examples/restful_server example
 *  3. Make board_ip and board_mac variables suitable for your network and board
 *  4. Change IP address in s_target_address variable to IP address of host running restful_server
 *  5. Compile & flash sketch
 *  6. restful_server server will start to show current uptime and free memory size (with 1 second interval) 
 */
 
#include <Ethernet.h>
#include <SPI.h>
#include "fossa.h"

static uint8_t board_mac[] = {
  0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED
};

// CHANGE THESE VARIABLES
static uint8_t board_ip[] = {192, 168, 10, 177};
static const char *s_target_address = "192.168.10.3:8000";

static const char *s_request = "/printcontent";

static int get_data_to_send(char* buf, int buf_size) {
  // Adding data to send
  // It could be any sensor data, now just put uptime & free memory size here
  return snprintf(buf, buf_size, "Uptime: %lus Free memory: %db",
                  millis()/1000, get_freememsize());
}
static void rfc_ev_handler(struct ns_connection *nc, int ev, void *ev_data) {
  int connect_status;

  switch (ev) {
    case NS_CONNECT:
      connect_status = * (int *) ev_data;

      if (connect_status == 0) {
        char buf[100];
        int len = get_data_to_send(buf, sizeof(buf));
        ns_printf(nc, "POST %s HTTP/1.0\r\nHost: %s\r\nContent-Lenght: %d"
                  "\r\n\r\n%s", s_request, s_target_address, len, buf);
        nc->flags |= NSF_SEND_AND_CLOSE;
      } else {
        nc->flags |= NSF_CLOSE_IMMEDIATELY;
      }
      break;
    default:
      break;
  }
}

static struct ns_mgr mgr;
static struct ns_connection *nc;

void setup()
{
  avr_netinit(board_mac, board_ip);

  ns_mgr_init(&mgr, NULL);
}

void loop() {
  nc = ns_connect(&mgr, s_target_address, rfc_ev_handler);
  if (nc != NULL) {
    ns_set_protocol_http_websocket(nc);
  }

  ns_mgr_poll(&mgr, 1000);  
  delay(1000);
}

