/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 *
 * This program listens on 5683 for CoAP messages, 
 * sends ACK is nessesary and dump everything received.
 * It is possible to use ../coap_client to send message.
 */

#include "fossa.h"

static char* s_default_address = "udp://:5683";
static int s_sig_received = 0;

static void signal_handler(int sig_num) {
  signal(sig_num, signal_handler); 
  s_sig_received = sig_num;
}

static void coap_handler(struct ns_connection *nc, int ev, void *p) {
  switch (ev) {
    case NS_COAP_CON: {
      uint32_t res;
      struct ns_coap_message *cm = (struct ns_coap_message *)p;
      printf("CON with msg_id = %d received\n", cm->msg_id);
      res = ns_coap_send_ack(nc, cm->msg_id);
      if (res == 0) {
        printf("Successfully sent ACK for message with msg_id = %d\n",
               cm->msg_id);
      } else {
        printf("Error: %d\n", res);
      }
      break;
    }
    case NS_COAP_NOC:
    case NS_COAP_ACK:
    case NS_COAP_RST:  {
      struct ns_coap_message *cm = (struct ns_coap_message *)p;
      printf("ACK/RST/NOC with msg_id = %d received\n",
             cm->msg_id);
      break;
    }
  }
}

int main() {
  struct ns_mgr mgr;
  struct ns_connection *nc;

  signal(SIGTERM, signal_handler);
  signal(SIGINT, signal_handler);

  ns_mgr_init(&mgr, 0);

  nc = ns_bind(&mgr, s_default_address, coap_handler);
  if (nc == NULL) {
    printf("Unable to start listener at %s\n", s_default_address);
    return -1;
  }

  printf("Listening for CoAP messages at %s\n", s_default_address); 

  ns_set_protocol_coap(nc);

  while (!s_sig_received) {
    ns_mgr_poll(&mgr, 1);
  }

  printf("Exiting on signal %d\n", s_sig_received);

  ns_mgr_free(&mgr);
}
