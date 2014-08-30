TCP client/server library for C/C++
===================================

Net Skeleton is a networking library written in C.
It provides easy to use event-driven interface that allows to implement
network protocols or scalable network applications  with little effort.
Net Skeleton releives developers from the burden of network programming
complexity and let them concentrate on the logic, saving time and money.

# Features

- Cross-platform: works on Windows, Linux/UNIX, QNX, eCos, Android, iPhone, etc
- Single-threaded, asynchronous, non-blocking core with simple event-bases API
- Has both client and server functionality
- SSL/TLS support, client-side SSL auth (two-way SSL)
- Tiny static and run-time footprint
- Mature and tested, it is a networking engine of
  [Mongoose Embedded Web Server](https://github.com/cesanta/mongoose),
  trusted by many blue chip companies in production environment

# Concept

Net Skeleton is a non-blocking, asyncronous event manager described by
`struct ns_server` structure. That structure holds active connections
and a pointer to the event handler function. Connections could be either
client or server. Client connections are created by means of
`ns_connect2()` call. Server connections are created by making a listening
socket with `ns_bind()` call, which will accept incoming connections. A
connection is described by `struct ns_connection` structure.

`ns_server_poll()` should be called in an infinite event loop.
`ns_server_poll()` iterates over all sockets, accepts new connections,
sends and receives data, closes connections, and calls an event handler
function for each of those events.

Each connection has send and receive buffer, `struct ns_connection::send_iobuf`
and `struct ns_connection::recv_iobuf` respectively. When data is received
for the connection, Net Skeleton appends received data to the `recv_iobuf` and
triggers `NS_RECV` event. Net Skeleton will append data indefinitely, until
RAM is exhausted, so to prevent out-of-memory situation, event handler must
discard data from `recv_iobuf` when it is not needed anymore by calling
`iobuf_remove()`.

Event handler may send data back (`ns_send()` or
`ns_printf()`), which appends data to the `send_iobuf`. When Net Skeleton
successfully writes data to the socket, it discards it from `send_iobuf` and
sends `NS_SEND` event. When connection is closed, `NS_CLOSE` event is sent.

![Diagram](http://cesanta.com/images/net_skeleton/iobuf.png)

# Using Net Skeleton

- Define an event handler function
- Initialize server by calling `ns_server_init()`
- Create a listening socket with `ns_bind()` or client connection with
  `ns_connect2()`
- Call `ns_server_poll()` in a loop

Net Skeleton accepts incoming connections, reads and writes data, and
calls specified event handler for each connection when appropriate. An
event handler should examine received data, set connection flags if needed,
and send data back to the client by `ns_send()` or `ns_printf()`. Here is a
typical event flow for the accepted connection:
`NS_ACCEPT` -> `NS_RECV` -> .... -> `NS_CLOSE`

An event handler can set `struct ns_connection::flags` attribute to control
the behavior of the connection.  Below is a list of connection flags:

   * `NSF_FINISHED_SENDING_DATA` tells Net Skeleton that all data has been
      appended to the `send_iobuf`. As soon as Net Skeleton sends it to the
      socket, the connection will be closed.
   * `NSF_BUFFER_BUT_DONT_SEND` tells Net Skeleton to append data to the
      `send_iobuf` but hold on sending it, because the data will be modified
      later and then will be sent by clearing `NSF_BUFFER_BUT_DONT_SEND` flag.
   * `NSF_SSL_HANDSHAKE_DONE` SSL only, set when SSL handshake is done
   * `NSF_CONNECTING` set when connection is in connecting state after
      `ns_connect()` call
   * `NSF_CLOSE_IMMEDIATELY` tells Net Skeleton to close the connection
      immediately, usually after some error
   * `NSF_ACCEPTED` set for all accepted connection
   * `NSF_USER_1`, `NSF_USER_2`, `NSF_USER_3`, `NSF_USER_4` could be
      used by a developer to store application-specific state

# Examples

- echo_server: a simple TCP echo server. It accepts incoming connections
  and echoes back any data that it receives
- publish_subscribe: implements pubsub pattern for TCP communication
- netcat: an implementation of Netcat utility with traffic hexdump and
  SSL support


# API documentation

Net skeleton server instance is single threaded. All functions should be
called from the same thread, with exception of `mg_wakeup_server_ex()`.

    void ns_server_init(struct ns_server *, void *server_data, ns_callback_t);
    void ns_server_free(struct ns_server *);

Initializes and de-initializes the server.

    int ns_bind(struct ns_server *, const char *addr);

Start listening on the given port. `addr` could be a port number,
e.g. `"3128"`, or IP address with a port number, e.g. `"127.0.0.1:3128"`.
In latter case, Net Skeleton binds to a specific interface only. Also,
a value of `"0"` can be used, in which case a random non-occupied port number
will be chosen. This function returns a positive port number on success, or
negative value on error.

    int ns_set_ssl_cert(struct ns_server *, const char *ssl_cert);

Set SSL certificate to use. Return 0 on success, and negative number on error.
On success, listening port will expect SSL-encrypted traffic.

    int ns_server_poll(struct ns_server *, int milli);

This function performs the actual IO, and must be called in a loop.
Return number of active connections.

    void ns_server_wakeup(struct ns_server *);

Interrupt `ns_server_poll()` that currently runs in another thread and is
blocked on `select()` system call. This is the only function can can be
used from a different thread. It is used to force Net Skeleton to
interrupt `select()` and perform the next IO cycle. A common use case is
a thread that decides that new data is available for IO.

    void ns_next(struct ns_server *, struct ns_connection *);

Iterates over all active connections:
`for (c = ns_next(srv, NULL); c != NULL; c = ns_next(srv, c)) { ... }` .

    struct ns_connection *ns_add_sock(struct ns_server *, sock_t sock, void *p);

Add a socket to the server.

    struct ns_connection *ns_connect2(struct ns_server *server, const char *host,
                                      int port, int use_ssl, const char *ssl_cert,
                                      const char *ca_cert, void *param);


Connect to a remote host. If successful, `NS_CONNECT` event will be delivered
to the new connection.

    int ns_send(struct ns_connection *, const void *buf, int len);
    int ns_printf(struct ns_connection *, const char *fmt, ...);
    int ns_vprintf(struct ns_connection *, const char *fmt, va_list ap);

These functions are for sending un-formatted and formatted data to the
connection. Number of written bytes is returned.

    // Utility functions
    void *ns_start_thread(void *(*f)(void *), void *p);
    int ns_socketpair(sock_t [2]);
    void ns_set_close_on_exec(sock_t);
    void ns_sock_to_str(sock_t sock, char *buf, size_t len, int add_port);
    int ns_hexdump(const void *buf, int len, char *dst, int dst_len);


# License

Net Skeleton is released under
[GNU GPL v.2](http://www.gnu.org/licenses/old-licenses/gpl-2.0.html).
Businesses have an option to get non-restrictive, royalty-free commercial
license and professional support from
[Cesanta Software](http://cesanta.com).
