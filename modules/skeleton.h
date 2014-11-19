/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 * This software is dual-licensed: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. For the terms of this
 * license, see <http://www.gnu.org/licenses/>.
 *
 * You are free to use this software under the terms of the GNU General
 * Public License, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * Alternatively, you can license this software under a commercial
 * license, as set out in <http://cesanta.com/>.
 */

#ifndef NS_SKELETON_HEADER_INCLUDED
#define NS_SKELETON_HEADER_INCLUDED

#ifdef NS_ENABLE_SSL
#ifdef __APPLE__
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
#include <openssl/ssl.h>
#else
typedef void *SSL;
typedef void *SSL_CTX;
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

union socket_address {
  struct sockaddr sa;
  struct sockaddr_in sin;
#ifdef NS_ENABLE_IPV6
  struct sockaddr_in6 sin6;
#else
  struct sockaddr sin6;
#endif
};

/* Describes chunk of memory */
struct ns_str {
  const char *p;  /* Memory chunk pointer */
  size_t len;     /* Memory chunk length */
};

#define NS_STR(str_literal) { str_literal, sizeof(str_literal) - 1 }

/* Callback function (event handler) prototype, must be defined by user. */
/* Net skeleton will call event handler, passing events defined above. */
struct ns_connection;
typedef void (*ns_event_handler_t)(struct ns_connection *, int ev, void *);

/* Events. Meaning of event parameter (evp) is given in the comment. */
#define NS_POLL    0  /*
                       * Sent to each connection on each call
                       * to ns_mgr_poll()
                       */
#define NS_ACCEPT  1  /*
                       * New connection accept()-ed.
                       * union socket_address *addr
                       */
#define NS_CONNECT 2  /* connect() succeeded or failed. int *success_status */
#define NS_RECV    3  /* Data has benn received. int *num_bytes */
#define NS_SEND    4  /* Data has been written to a socket. int *num_bytes */
#define NS_CLOSE   5  /* Connection is closed. NULL */

/*
 * Fossa event manager.
 */
struct ns_mgr {
  struct ns_connection *active_connections;
  const char *hexdump_file;         /* Debug hexdump file path */
  sock_t ctl[2];                    /* Socketpair for mg_wakeup() */
  void *user_data;                  /* User data */
};

/*
 * Fossa connection.
 */
struct ns_connection {
  struct ns_connection *next, *prev;  /* ns_mgr::active_connections linkage */
  struct ns_connection *listener;     /* Set only for accept()-ed connections */
  struct ns_mgr *mgr;

  sock_t sock;                /* Socket */
  union socket_address sa;    /* Peer address */
  struct iobuf recv_iobuf;    /* Received data */
  struct iobuf send_iobuf;    /* Data scheduled for sending */
  SSL *ssl;
  SSL_CTX *ssl_ctx;
  time_t last_io_time;        /* Timestamp of the last socket IO */
  ns_event_handler_t proto_handler;   /* Protocol-specific event handler */
  void *proto_data;                   /* Protocol-specific data */
  ns_event_handler_t handler; /* Event handler function */
  void *user_data;            /* User-specific data */

  unsigned long flags;
#define NSF_FINISHED_SENDING_DATA   (1 << 0)
#define NSF_BUFFER_BUT_DONT_SEND    (1 << 1)
#define NSF_SSL_HANDSHAKE_DONE      (1 << 2)
#define NSF_CONNECTING              (1 << 3)
#define NSF_CLOSE_IMMEDIATELY       (1 << 4)
#define NSF_WANT_READ               (1 << 5)
#define NSF_WANT_WRITE              (1 << 6)  /* NOTE(lsm): proto-specific */
#define NSF_LISTENING               (1 << 7)  /* NOTE(lsm): proto-specific */
#define NSF_UDP                     (1 << 8)
#define NSF_IS_WEBSOCKET            (1 << 9)  /* NOTE(lsm): proto-specific */
#define NSF_WEBSOCKET_NO_DEFRAG     (1 << 10) /* NOTE(lsm): proto-specific */

#define NSF_USER_1                  (1 << 20)
#define NSF_USER_2                  (1 << 21)
#define NSF_USER_3                  (1 << 22)
#define NSF_USER_4                  (1 << 23)
#define NSF_USER_5                  (1 << 24)
#define NSF_USER_6                  (1 << 25)
};

void ns_mgr_init(struct ns_mgr *, void *user_data);
void ns_mgr_free(struct ns_mgr *);
time_t ns_mgr_poll(struct ns_mgr *, int milli);
void ns_broadcast(struct ns_mgr *, ns_event_handler_t, void *, size_t);

struct ns_connection *ns_next(struct ns_mgr *, struct ns_connection *);

#define NS_COMMON_CONNECTION_OPTIONS \
  void *user_data;                   \
  unsigned int flags;                \
  char **error_string                \

#define NS_COPY_COMMON_CONNECTION_OPTIONS(dst, src) \
  *((struct ns_connection_common_opts*)(dst)) =     \
    *((struct ns_connection_common_opts*)(src));

struct ns_connection_common_opts {
  NS_COMMON_CONNECTION_OPTIONS;
};

struct ns_add_sock_opts {
  NS_COMMON_CONNECTION_OPTIONS;
};
struct ns_connection *ns_add_sock(struct ns_mgr *, sock_t, ns_event_handler_t);
struct ns_connection *ns_add_sock_opt(struct ns_mgr *, sock_t,
                                      ns_event_handler_t,
                                      struct ns_add_sock_opts);

struct ns_bind_opts {
  NS_COMMON_CONNECTION_OPTIONS;
};
struct ns_connection *ns_bind(struct ns_mgr *, const char *,
                              ns_event_handler_t);
struct ns_connection *ns_bind_opt(struct ns_mgr *, const char *,
                                  ns_event_handler_t, struct ns_bind_opts);

struct ns_connect_opts {
  NS_COMMON_CONNECTION_OPTIONS;
};
struct ns_connection *ns_connect(struct ns_mgr *, const char *,
                                 ns_event_handler_t);
struct ns_connection *ns_connect_opt(struct ns_mgr *, const char *,
                                     ns_event_handler_t,
                                     struct ns_connect_opts);
const char *ns_set_ssl(struct ns_connection *nc, const char *, const char *);

int ns_send(struct ns_connection *, const void *buf, int len);
int ns_printf(struct ns_connection *, const char *fmt, ...);
int ns_vprintf(struct ns_connection *, const char *fmt, va_list ap);

/* Utility functions */
void *ns_start_thread(void *(*f)(void *), void *p);
int ns_socketpair(sock_t[2]);
int ns_socketpair2(sock_t[2], int sock_type);  /* SOCK_STREAM or SOCK_DGRAM */
void ns_set_close_on_exec(sock_t);
void ns_sock_to_str(sock_t sock, char *buf, size_t len, int flags);
int ns_hexdump(const void *buf, int len, char *dst, int dst_len);
void ns_hexdump_connection(struct ns_connection *nc, const char *path,
                           int num_bytes, int ev);
int ns_avprintf(char **buf, size_t size, const char *fmt, va_list ap);
int ns_resolve(const char *domain_name, char *ip_addr_buf, size_t buf_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* NS_SKELETON_HEADER_INCLUDED */
