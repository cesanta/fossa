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
 * license, as set out in <https://www.cesanta.com/license>.
 */

/*
 * === Core: TCP/UDP/SSL
 *
 * NOTE: Fossa manager is single threaded. It does not protect
 * its data structures by mutexes, therefore all functions that are dealing
 * with particular event manager should be called from the same thread,
 * with exception of `mg_broadcast()` function. It is fine to have different
 * event managers handled by different threads.
 */

#ifndef NS_NET_HEADER_INCLUDED
#define NS_NET_HEADER_INCLUDED

#include "common.h"
#include "../../common/mbuf.h"

#ifdef NS_ENABLE_SSL
#ifdef __APPLE__
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
#include <openssl/ssl.h>
#else
typedef void *SSL;
typedef void *SSL_CTX;
#endif

#ifdef NS_USE_READ_WRITE
#define NS_RECV_FUNC(s, b, l, f) read(s, b, l)
#define NS_SEND_FUNC(s, b, l, f) write(s, b, l)
#else
#define NS_RECV_FUNC(s, b, l, f) recv(s, b, l, f)
#define NS_SEND_FUNC(s, b, l, f) send(s, b, l, f)
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
  const char *p; /* Memory chunk pointer */
  size_t len;    /* Memory chunk length */
};

#define NS_STR(str_literal) \
  { str_literal, sizeof(str_literal) - 1 }

/*
 * Callback function (event handler) prototype, must be defined by user.
 * Fossa calls event handler, passing events defined below.
 */
struct ns_connection;
typedef void (*ns_event_handler_t)(struct ns_connection *, int ev, void *);

/* Events. Meaning of event parameter (evp) is given in the comment. */
#define NS_POLL 0    /* Sent to each connection on each ns_mgr_poll() call */
#define NS_ACCEPT 1  /* New connection accepted. union socket_address *addr */
#define NS_CONNECT 2 /* connect() succeeded or failed. int *success_status */
#define NS_RECV 3    /* Data has benn received. int *num_bytes */
#define NS_SEND 4    /* Data has been written to a socket. int *num_bytes */
#define NS_CLOSE 5   /* Connection is closed. NULL */

/*
 * Fossa event manager.
 */
struct ns_mgr {
  struct ns_connection *active_connections;
  const char *hexdump_file; /* Debug hexdump file path */
  sock_t ctl[2];            /* Socketpair for mg_wakeup() */
  void *user_data;          /* User data */
  void *mgr_data;           /* Implementation-specific event manager's data. */
};

/*
 * Fossa connection.
 */
struct ns_connection {
  struct ns_connection *next, *prev; /* ns_mgr::active_connections linkage */
  struct ns_connection *listener;    /* Set only for accept()-ed connections */
  struct ns_mgr *mgr;                /* Pointer to containing manager */

  sock_t sock;             /* Socket to the remote peer */
  union socket_address sa; /* Remote peer address */
  size_t recv_mbuf_limit;  /* Max size of recv buffer */
  struct mbuf recv_mbuf;   /* Received data */
  struct mbuf send_mbuf;   /* Data scheduled for sending */
  SSL *ssl;
  SSL_CTX *ssl_ctx;
  time_t last_io_time;              /* Timestamp of the last socket IO */
  ns_event_handler_t proto_handler; /* Protocol-specific event handler */
  void *proto_data;                 /* Protocol-specific data */
  ns_event_handler_t handler;       /* Event handler function */
  void *user_data;                  /* User-specific data */
  void *priv_1;                     /* Used by ns_enable_multithreading() */
  void *priv_2;                     /* Used by ns_enable_multithreading() */
  void *mgr_data; /* Implementation-specific event manager's data. */

  unsigned long flags;
/* Flags set by Fossa */
#define NSF_LISTENING (1 << 0)          /* This connection is listening */
#define NSF_UDP (1 << 1)                /* This connection is UDP */
#define NSF_RESOLVING (1 << 2)          /* Waiting for async resolver */
#define NSF_CONNECTING (1 << 3)         /* connect() call in progress */
#define NSF_SSL_HANDSHAKE_DONE (1 << 4) /* SSL specific */
#define NSF_WANT_READ (1 << 5)          /* SSL specific */
#define NSF_WANT_WRITE (1 << 6)         /* SSL specific */
#define NSF_IS_WEBSOCKET (1 << 7)       /* Websocket specific */

/* Flags that are settable by user */
#define NSF_SEND_AND_CLOSE (1 << 10)      /* Push remaining data and close  */
#define NSF_DONT_SEND (1 << 11)           /* Do not send data to peer */
#define NSF_CLOSE_IMMEDIATELY (1 << 12)   /* Disconnect */
#define NSF_WEBSOCKET_NO_DEFRAG (1 << 13) /* Websocket specific */
#define NSF_DELETE_CHUNK (1 << 14)        /* HTTP specific */

#define NSF_USER_1 (1 << 20) /* Flags left for application */
#define NSF_USER_2 (1 << 21)
#define NSF_USER_3 (1 << 22)
#define NSF_USER_4 (1 << 23)
#define NSF_USER_5 (1 << 24)
#define NSF_USER_6 (1 << 25)
};

/*
 * Initialize Fossa manager. Side effect: ignores SIGPIPE signal.
 * `mgr->user_data` field will be initialized with `user_data` parameter.
 * That is an arbitrary pointer, where user code can associate some data
 * with the particular Fossa manager. For example, a C++ wrapper class
 * could be written, in which case `user_data` can hold a pointer to the
 * class instance.
 */
void ns_mgr_init(struct ns_mgr *mgr, void *user_data);

/*
 * De-initializes Fossa manager.
 *
 * Close and deallocate all active connections.
 */
void ns_mgr_free(struct ns_mgr *);

/*
 * This function performs the actual IO, and must be called in a loop
 * (an event loop). Returns the current timestamp.
 * `milli` is the maximum number of milliseconds to sleep.
 * `ns_mgr_poll()` checks all connection for IO readiness. If at least one
 * of the connections is IO-ready, `ns_mgr_poll()` triggers respective
 * event handlers and returns.
 */
time_t ns_mgr_poll(struct ns_mgr *, int milli);

/*
 * Pass a message of a given length to all connections.
 *
 * Must be called from a thread that does NOT call `ns_mgr_poll()`.
 * Note that `ns_broadcast()` is the only function
 * that can be, and must be, called from a different (non-IO) thread.
 *
 * `func` callback function will be called by the IO thread for each
 * connection. When called, event would be `NS_POLL`, and message will
 * be passed as `ev_data` pointer. Maximum message size is capped
 * by `NS_CTL_MSG_MESSAGE_SIZE` which is set to 8192 bytes.
 */
void ns_broadcast(struct ns_mgr *, ns_event_handler_t func, void *, size_t);

/*
 * Iterate over all active connections.
 *
 * Returns next connection from the list
 * of active connections, or `NULL` if there is no more connections. Below
 * is the iteration idiom:
 *
 * [source,c]
 * ----
 * for (c = ns_next(srv, NULL); c != NULL; c = ns_next(srv, c)) {
 *   // Do something with connection `c`
 * }
 * ----
 */
struct ns_connection *ns_next(struct ns_mgr *, struct ns_connection *);

/*
 * Optional parameters to ns_add_sock_opt()
 * `flags` is an initial `struct ns_connection::flags` bitmask to set,
 * see `NSF_*` flags definitions.
 */
struct ns_add_sock_opts {
  void *user_data;           /* Initial value for connection's user_data */
  unsigned int flags;        /* Initial connection flags */
  const char **error_string; /* Placeholder for the error string */
};

/*
 * Create a connection, associate it with the given socket and event handler,
 * and add it to the manager.
 *
 * For more options see the `ns_add_sock_opt` variant.
 */
struct ns_connection *ns_add_sock(struct ns_mgr *, sock_t, ns_event_handler_t);

/*
 * Create a connection, associate it with the given socket and event handler,
 * and add to the manager.
 *
 * See the `ns_add_sock_opts` structure for a description of the options.
 */
struct ns_connection *ns_add_sock_opt(struct ns_mgr *, sock_t,
                                      ns_event_handler_t,
                                      struct ns_add_sock_opts);

/*
 * Optional parameters to ns_bind_opt()
 * `flags` is an initial `struct ns_connection::flags` bitmask to set,
 * see `NSF_*` flags definitions.
 */
struct ns_bind_opts {
  void *user_data;           /* Initial value for connection's user_data */
  unsigned int flags;        /* Extra connection flags */
  const char **error_string; /* Placeholder for the error string */
};

/*
 * Create listening connection.
 *
 * See `ns_bind_opt` for full documentation.
 */
struct ns_connection *ns_bind(struct ns_mgr *, const char *,
                              ns_event_handler_t);
/*
 * Create listening connection.
 *
 * `address` parameter tells which address to bind to. It's format is the same
 * as for the `ns_connect()` call, where `HOST` part is optional. `address`
 * can be just a port number, e.g. `:8000`. To bind to a specific interface,
 * an IP address can be specified, e.g. `1.2.3.4:8000`. By default, a TCP
 * connection is created. To create UDP connection, prepend `udp://` prefix,
 * e.g. `udp://:8000`. To summarize, `address` paramer has following format:
 * `[PROTO://][IP_ADDRESS]:PORT`, where `PROTO` could be `tcp` or `udp`.
 *
 * See the `ns_bind_opts` structure for a description of the optional
 * parameters.
 *
 * Return a new listening connection, or `NULL` on error.
 * NOTE: Connection remains owned by the manager, do not free().
 */
struct ns_connection *ns_bind_opt(struct ns_mgr *, const char *,
                                  ns_event_handler_t, struct ns_bind_opts);

/* Optional parameters to ns_connect_opt() */
struct ns_connect_opts {
  void *user_data;           /* Initial value for connection's user_data */
  unsigned int flags;        /* Extra connection flags */
  const char **error_string; /* Placeholder for the error string */
};

/*
 * Connect to a remote host.
 *
 * See `ns_connect_opt()` for full documentation.
 */
struct ns_connection *ns_connect(struct ns_mgr *, const char *,
                                 ns_event_handler_t);

/*
 * Connect to a remote host.
 *
 * `address` format is `[PROTO://]HOST:PORT`. `PROTO` could be `tcp` or `udp`.
 * `HOST` could be an IP address,
 * IPv6 address (if Fossa is compiled with `-DNS_ENABLE_IPV6`), or a host name.
 * If `HOST` is a name, Fossa will resolve it asynchronously. Examples of
 * valid addresses: `google.com:80`, `udp://1.2.3.4:53`, `10.0.0.1:443`,
 * `[::1]:80`
 *
 * See the `ns_connect_opts` structure for a description of the optional
 * parameters.
 *
 * Returns a new outbound connection, or `NULL` on error.
 *
 * NOTE: Connection remains owned by the manager, do not free().
 *
 * NOTE: To enable IPv6 addresses, `-DNS_ENABLE_IPV6` should be specified
 * in the compilation flags.
 *
 * NOTE: New connection will receive `NS_CONNECT` as it's first event
 * which will report connect success status.
 * If asynchronous resolution fail, or `connect()` syscall fail for whatever
 * reason (e.g. with `ECONNREFUSED` or `ENETUNREACH`), then `NS_CONNECT`
 * event report failure. Code example below:
 *
 * [source,c]
 * ----
 * static void ev_handler(struct ns_connection *nc, int ev, void *ev_data) {
 *   int connect_status;
 *
 *   switch (ev) {
 *     case NS_CONNECT:
 *       connect_status = * (int *) ev_data;
 *       if (connect_status == 0) {
 *         // Success
 *       } else  {
 *         // Error
 *         printf("connect() error: %s\n", strerror(connect_status));
 *       }
 *       break;
 *     ...
 *   }
 * }
 *
 *   ...
 *   ns_connect(mgr, "my_site.com:80", ev_handler);
 * ----
 */
struct ns_connection *ns_connect_opt(struct ns_mgr *, const char *,
                                     ns_event_handler_t,
                                     struct ns_connect_opts);

/*
 * Enable SSL for a given connection.
 * `cert` is a server certificate file name for a listening connection,
 * or a client certificate file name for an outgoing connection.
 * Certificate files must be in PEM format. Server certificate file
 * must contain a certificate, concatenated with a private key, optionally
 * concatenated with parameters.
 * `ca_cert` is a CA certificate, or NULL if peer verification is not
 * required.
 * Return: NULL on success, or error message on error.
 */
const char *ns_set_ssl(struct ns_connection *nc, const char *cert,
                       const char *ca_cert);

/*
 * Send data to the connection.
 *
 * Return number of written bytes. Note that sending
 * functions do not actually push data to the socket. They just append data
 * to the output buffer. The exception is UDP connections. For UDP, data is
 * sent immediately, and returned value indicates an actual number of bytes
 * sent to the socket.
 */
int ns_send(struct ns_connection *, const void *buf, int len);

/*
 * Send `printf`-style formatted data to the connection.
 *
 * See `ns_send` for more details on send semantics.
 */
int ns_printf(struct ns_connection *, const char *fmt, ...);

/* Same as `ns_printf()`, but takes `va_list ap` as an argument. */
int ns_vprintf(struct ns_connection *, const char *fmt, va_list ap);

/*
 * Create a socket pair.
 * `sock_type` can be either `SOCK_STREAM` or `SOCK_DGRAM`.
 * Return 0 on failure, 1 on success.
 */
int ns_socketpair(sock_t[2], int sock_type);

/*
 * Convert domain name into IP address.
 *
 * This is a utility function. If compilation flags have
 * `-DNS_ENABLE_GETADDRINFO`, then `getaddrinfo()` call is used for name
 * resolution. Otherwise, `gethostbyname()` is used.
 *
 * CAUTION: this function can block.
 * Return 1 on success, 0 on failure.
 */
int ns_resolve(const char *domain_name, char *ip_addr_buf, size_t buf_len);

/*
 * Verify given IP address against the ACL.
 *
 * `remote_ip` - an IPv4 address to check, in host byte order
 * `acl` - a comma separated list of IP subnets: `x.x.x.x/x` or `x.x.x.x`.
 * Each subnet is
 * prepended by either a - or a + sign. A plus sign means allow, where a
 * minus sign means deny. If a subnet mask is omitted, such as `-1.2.3.4`,
 * this means to deny only that single IP address.
 * Subnet masks may vary from 0 to 32, inclusive. The default setting
 * is to allow all accesses. On each request the full list is traversed,
 * and the last match wins. Example:
 *
 * `-0.0.0.0/0,+192.168/16` - deny all acccesses, only allow 192.168/16 subnet
 *
 * To learn more about subnet masks, see the
 * link:https://en.wikipedia.org/wiki/Subnetwork[Wikipedia page on Subnetwork]
 *
 * Return -1 if ACL is malformed, 0 if address is disallowed, 1 if allowed.
 */
int ns_check_ip_acl(const char *acl, uint32_t remote_ip);

/*
 * Enable multi-threaded handling for the given listening connection `nc`.
 * For each accepted connection, Mongoose will create a separate thread
 * and run event handler in that thread. Thus, if an event hanler is doing
 * a blocking call or some long computation, that will not slow down
 * other connections.
 */
void ns_enable_multithreading(struct ns_connection *nc);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* NS_NET_HEADER_INCLUDED */
