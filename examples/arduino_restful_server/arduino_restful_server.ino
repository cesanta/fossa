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
 *  2. Make board_ip variable suitable for your network
 *  3. Uncomment line #include <Ethernet.h>
 *  4. Compile & flash sketch
 *  5. Run curl http://<board_ip/blink
 *     LED attached to PIN 13 will blink and board free memory size and uptime will responsed
 *
 * To run with Adafruit WiFi (CC3000) shield:
 * -----------------------------------------------------------
 *  1. Add (Sketch->Add files...) the following files to sketch:
 *     - /fossa/fossa.h
 *     - /fossa/fossa.c
 *     - /fossa/platforms/arduino_ethernet_W5100/avrsupport.h
 *     - /fossa/platforms/arduino_ethernet_W5100/avrsupport.cpp
 *  2. Import Adafruit CC3000 library for fossa (select Sketch->Import Library...->Add library... and point 
 *     /fossa/platforms/arduino_wifi_CC3000/adafruit_CC3000_lib_fossa folder
 *  3. Make the following variables suitable for your network
 *     - board_ip
 *     - subnet_mask
 *     - gateway
 *     - dns 
 *     - wlan_ssid
 *     - wlan_pwd
 *     - wlan_security
 *  5. Uncomment line #include <Adafruit_CC3000.h>
 *  4. Compile & flash sketch
 *  5. Run curl http://<board_ip/blink
 *     LED attached to PIN 13 will blink and board free memory size and uptime will responsed
 *
 */

//#include <Ethernet.h>
//#include <Adafruit_CC3000.h>
#include <SPI.h>
#include "fossa.h"

static uint8_t board_mac[] = {
  0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED
};

static uint8_t board_ip[] = {192, 168, 10, 8};

#ifdef WIFI_CC3000
static uint8_t subnet_mask[] = {255, 255, 255, 0};
static uint8_t gateway[] = {192, 168, 10, 254};
static uint8_t dns_ip[] = {192, 168, 10, 254};

static const char *wlan_ssid = "mynetwork";     
static const char *wlan_pwd = "mypassword";
static int wlan_security = WLAN_SEC_WPA2;
#endif

static const char *s_http_port = "60000";

static uint32_t IP2U32(uint8_t* iparr) {
  return ((uint32_t)iparr[0] << 24) | ((uint32_t)iparr[1] << 16) | (iparr[2] << 8) | (iparr[3]);
}

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

static struct ns_connection *nc;
static struct ns_mgr mgr;

void setup() {
  Serial.begin(9600);
  Serial.println("Initialization...");
#if defined(ETHERNET_W5100)
  avr_netinit(board_mac, board_ip);
#elif defined(WIFI_CC3000)
  if (avr_netinit(wlan_ssid, wlan_pwd, wlan_security, IP2U32(board_ip), 
              IP2U32(subnet_mask), IP2U32(gateway), IP2U32(dns_ip)) != 0) {
    Serial.println("Initialization error, check network settings");
    return;
  };
#endif

  ns_mgr_init(&mgr, NULL);
  nc = ns_bind(&mgr, s_http_port, rfs_ev_handler);
  ns_set_protocol_http_websocket(nc);
  Serial.println("Initialization done");
}

void loop() {
  ns_mgr_poll(&mgr, 1000);
}
