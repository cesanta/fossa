/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

/*
 * Try it out with:
 * $ dig -t A www.google.com -4 @localhost -p 5533
 */

#include "../../fossa.h"

#include <stdio.h>

static int s_exit_flag = 0;

static void ev_handler(struct ns_connection *nc, int ev, void *ev_data) {
  struct ns_dns_message msg;
  struct ns_dns_resource_record *rr;
  struct iobuf *io = &nc->send_iobuf;;
  in_addr_t addr = * (in_addr_t *) nc->user_data;
  char name[512];
  int i;

  (void) ev_data;

  switch (ev) {
    case NS_RECV:
      if (ns_parse_dns(nc->recv_iobuf.buf, nc->recv_iobuf.len, &msg) == -1) {
        fprintf(stderr, "cannot parse DNS request\n");

        /* reply + recursion allowed + format error */
        msg.flags |= 0x8081;
        ns_dns_insert_header(io, 0, &msg);
        ns_send(nc, io->buf, io->len);
        iobuf_remove(io, io->len);
        break;
      }

      /* reply + recursion allowed */
      msg.flags |= 0x8080;

      ns_dns_copy_body(io, &msg);

      msg.num_answers = 0;
      for (i = 0; i < msg.num_questions; i++) {
        if (msg.questions[0].rtype != NS_DNS_A_RECORD) {
          continue;
        }

        rr = &msg.answers[msg.num_answers];
        *rr = msg.questions[i];
        rr->ttl = 3600;
        rr->kind = NS_DNS_ANSWER;

        ns_dns_uncompress_name(&msg, &msg.questions[0].name, name,
                               sizeof(name));
        if (ns_dns_encode_record(io, rr, name, strlen(name), &addr, 4) == -1) {
          continue;
        }
        msg.num_answers++;
      }

      /*
       * We don't set the error flag even if there were no answers
       * maching the NS_DNS_A_RECORD query type.
       * This indicates that we have (syntetic) answers for NS_DNS_A_RECORD.
       * See http://goo.gl/QWvufr for a distinction between NXDOMAIN and NODATA.
       */

      /* prepends header now that we know the number of answers */
      ns_dns_insert_header(io, 0, &msg);

      ns_send(nc, io->buf, io->len);
      iobuf_remove(io, io->len);
      break;
  }
}

int main(int argc, char *argv[]) {
  struct ns_mgr mgr;
  struct ns_connection *nc;
  in_addr_t addr = inet_addr("127.0.0.1");
  char *bind_addr = ":5533";
  char url[256];
  int i;

  ns_mgr_init(&mgr, NULL);

  /* Parse command line arguments */
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-D") == 0) {
      mgr.hexdump_file = argv[++i];
    } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
      bind_addr = argv[++i];
    } else {
      addr = inet_addr(argv[i]);
    }
  }

  snprintf(url, sizeof(url), "udp://%s", bind_addr);
  fprintf(stderr, "Listening to '%s'\n", url);
  if ((nc = ns_bind(&mgr, url, ev_handler)) == NULL) {
    fprintf(stderr, "cannot bind to socket\n");
    exit(1);
  }
  nc->user_data = &addr;

  while (s_exit_flag == 0) {
    ns_mgr_poll(&mgr, 1000);
  }
  ns_mgr_free(&mgr);

  return 0;
}
