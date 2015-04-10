/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */
#ifndef CC3000UTILS_HEADER_INCLUDED
#define CC3000UTILS_HEADER_INCLUDED

#define WIFI_CC3000

#ifdef __cplusplus
extern "C" {
#endif

int avr_netinit(const char* wlan_ssid, const char* wlan_pwd, int wlan_security,
                uint32_t ip, uint32_t subnet_mask, uint32_t gateway,
                uint32_t dns);

#include <utility/socket.h>
#include <utility/wlan.h>

#define close(x) closesocket(x)

#ifdef __cplusplus
}
#endif

#endif
