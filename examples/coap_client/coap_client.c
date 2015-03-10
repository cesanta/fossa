/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 *
 * This program sends CoAP CON-message to server (coap.me by default) 
 * and waits for answer.
 */

#include "fossa.h"

static int s_time_to_exit = 0;
static char* s_default_address = "udp://coap.me:5683";

static void coap_handler(struct ns_connection *nc, int ev, void *p) {
  switch (ev) {
    case NS_CONNECT: {
      struct ns_coap_message cm;
      uint32_t res;

      memset(&cm, 0, sizeof(cm));
      cm.msg_id = 1;
      cm.msg_type = NS_COAP_MSG_CON;
      printf("Sending CON...\n");
      res = ns_coap_send_message(nc, &cm);
      if (res == 0) {
        printf("Sent CON with msg_id = %d\n", cm.msg_id);
      } else {
        printf("Error: %d\n", res);
        s_time_to_exit = 1;
      }
      break;
    }
    case NS_COAP_ACK:
    case NS_COAP_RST:  {
      struct ns_coap_message *cm = (struct ns_coap_message *)p;
      printf("ACK/RST for message with msg_id = %d received\n",
             cm->msg_id);
      s_time_to_exit = 1;
      break;
    }
  }
}

int main(int argc, char* argv[]) {
  struct ns_mgr mgr;
  struct ns_connection *nc;
  char *address = s_default_address;

  if (argc > 1) {
    address = argv[1];
  }

  printf("Using %s as CoAP server\n", address); 

  ns_mgr_init(&mgr, 0);

  nc = ns_connect(&mgr, address, coap_handler);
  if (nc == NULL) {
    printf("Unable to connect to %s\n", address);
    return -1;
  }

  ns_set_protocol_coap(nc);

  while (!s_time_to_exit) {
    ns_mgr_poll(&mgr, 1);
  }

  ns_mgr_free(&mgr);
}
