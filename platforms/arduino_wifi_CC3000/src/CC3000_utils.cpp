/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <Adafruit_CC3000.h>
#include <utility/socket.h>

#define ADAFRUIT_CC3000_IRQ 3
#define ADAFRUIT_CC3000_VBAT 5
#define ADAFRUIT_CC3000_CS 10
#define DHCP_TIMEOUT 30

static unsigned long aucDHCP = 14400;
static unsigned long aucARP = 3600;
static unsigned long aucKeepalive = 30;
static unsigned long aucInactivity = 0;

Adafruit_CC3000 cc3000(ADAFRUIT_CC3000_CS, ADAFRUIT_CC3000_IRQ,
                       ADAFRUIT_CC3000_VBAT, SPI_CLOCK_DIVIDER);

int check_dhcp() {
  time_t finish_time = millis() + DHCP_TIMEOUT * 1000;
  while (!cc3000.checkDHCP() && millis() < finish_time) {
    delay(100);
    yield();
  }

  return cc3000.checkDHCP();
}

int avr_netinit(const char* wlan_ssid, const char* wlan_pwd, int wlan_security,
                uint32_t ip, uint32_t subnet_mask, uint32_t gateway,
                uint32_t dns) {
  init_sockets_buffer();

  if (!cc3000.begin()) {
    return -1;
  }

  if (!cc3000.connectToAP(wlan_ssid, wlan_pwd, wlan_security)) {
    return -1;
  }

  if (!check_dhcp()) {
    return -1;
  }

  uint32_t current_ip = 0, current_subnet_mask = 0, current_gw = 0,
           currend_dhcp = 0, current_dns = 0;

  if (!cc3000.getIPAddress(&current_ip, &current_subnet_mask, &current_gw,
                           &currend_dhcp, &current_dns)) {
    return -1;
  }

  if (current_ip != ip || current_subnet_mask != subnet_mask ||
      current_gw != gateway || current_dns != dns) {
    if (!cc3000.setStaticIPAddress(ip, subnet_mask, gateway, dns)) {
      return -1;
    }

    /* Waiting while new address is really assigned */
    if (!check_dhcp()) {
      return -1;
    }
  }

  if (netapp_timeout_values(&aucDHCP, &aucARP, &aucKeepalive, &aucInactivity) !=
      0) {
    return -1;
  }

  return 0;
}
