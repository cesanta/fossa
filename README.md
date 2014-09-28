Networking client/server library for C/C++
===================================

Net Skeleton is a networking library written in C.
It provides easy to use event-driven interface that allows to implement
network protocols or scalable network applications  with little effort.
Net Skeleton releives developers from the burden of network programming
complexity and let them concentrate on the logic, saving time and money.

# Features

- Cross-platform: works on Linux/UNIX, QNX, eCos, Windows, Android, iPhone, etc
- Single-threaded, asynchronous, non-blocking core with simple event-bases API
- Has both client and server functionality
- TCP and UDP support
- SSL/TLS support, one-way and two-way SSL
- Tiny static and run-time footprint
- Mature and tested, it is a networking engine of
  [Mongoose Embedded Web Server](https://github.com/cesanta/mongoose),
  trusted by many blue chip companies in production environment

# Concept

Net Skeleton is a non-blocking, asyncronous event manager described by
`struct ns_mgr` structure. That structure holds active connections.
Connections could be either listening, client or accepted connections.
Client connections are created by means of
`ns_connect()` call. Listening connections are created by `ns_bind()` call.
Accepted connections are those that incoming on a listening connection.
A connection is described by `struct ns_connection` structure, which has
a number of fields like socket, event handler function, send/receive buffer,
flags, et cetera.

`ns_mgr_poll()` should be called in an infinite event loop.
`ns_mgr_poll()` iterates over all sockets, accepts new connections,
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
- Initialize mgr by calling `ns_mgr_init()`
- Create a listening socket with `ns_bind()` or client connection with
  `ns_connect2()`
- Call `ns_mgr_poll()` in a loop

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
      `ns_connect()` call but connect did not finish yet
   * `NSF_CLOSE_IMMEDIATELY` tells Net Skeleton to close the connection
      immediately, usually after some error
   * `NSF_LISTENING` set for all listening connections
   * `NSF_UDP` set if connection is UDP
   * `NSF_USER_1`, `NSF_USER_2`, `NSF_USER_3`, `NSF_USER_4` could be
      used by a developer to store application-specific state

# Examples

- echo_server: a simple TCP echo server. It accepts incoming connections
  and echoes back any data that it receives
- publish_subscribe: implements pubsub pattern for TCP communication
- netcat: an implementation of Netcat utility with traffic hexdump and
  SSL support


# API documentation

Net skeleton manager instance is single threaded. All functions should be
called from the same thread, with exception of `mg_broadcast()`.

    void ns_mgr_init(struct ns_mgr *, void *user_data);
    void ns_mgr_free(struct ns_mgr *);

Initializes and de-initializes skeleton manager.

    struct ns_connection *ns_bind(struct ns_mgr *, const char *addr,
                                  ns_callback_t ev_handler, void *user_data);

Start listening on the given port. `addr` could be a port number,
e.g. `"3128"`, or IP address with a port number, e.g. `"127.0.0.1:3128"`.
Also, a protocol prefix could be specified, valid prefixes are `tcp://`,
`udp://` and `ssl://`. For SSL, server certficate must be specified:
`ssl://[IP:]PORT:SERVER_CERT.PEM`. Two enable client certificate authentication
(two-way SSL), a CA certificate should be specified:
`ssl://[IP:]PORT:SERVER_CERT.PEM:CA_CERT.PEM`. Server certificate must be
in PEM format. PEM file should contain both certificate and the private key
concatenated together.

Note that for UDP listening connections, only `NS_RECV` and `NS_CLOSE`
are triggered.

If IP address is specified, Net Skeleton binds to a specific interface only.
Also, port could be `"0"`, in which case a random non-occupied port number
will be chosen. Return value: a listening connection on success, or
`NULL` on error.

    time_t ns_mgr_poll(struct ns_mgr *, int milliseconds);

This function performs the actual IO, and must be called in a loop
(an event loop). Returns number current timestamp.

    void ns_broadcast(struct ns_mgr *, ns_callback_t cb, void *msg, size_t len);

Must be called from a different thread. Passes a message of a given length to
all connections. Skeleton manager has a socketpair, `struct ns_mgr::ctl`,
where `ns_broadcast()` pushes the message.
`ns_mgr_poll()` wakes up, reads a message from the socket pair, and calls
specified callback for each connection. Thus the callback function executes
in event manager thread. Note that `ns_broadcast()` is the only function
that can be, and must be, called from a different thread.

    void ns_next(struct ns_mgr *, struct ns_connection *);

Iterates over all active connections, that is the iteration idiom:
`for (c = ns_next(srv, NULL); c != NULL; c = ns_next(srv, c)) { ... }` .

    struct ns_connection *ns_add_sock(struct ns_mgr *, sock_t sock,
                                      ns_callback_t ev_handler, void *user_data);

Add a socket to the server. `user_data` will become
`struct ns_connection::user_data` pointer for the created connection.

    struct ns_connection *ns_connect(struct ns_mgr *server, const char *addr,
                                     ns_callback_t ev_handler, void *user_data);


Connect to a remote host. If successful, `NS_CONNECT` event will be delivered
to the new connection. `addr` format is the same as for the `ns_bind()` call,
just an IP address becomes mandatory: `[PROTO://]HOST:PORT[:CERT][:CA_CERT]`.
`PROTO` could be `tcp://`, `udp://` or `ssl://`. If `HOST` is not an IP
address, Net Skeleton will resolve it - beware that standard blocking resolver
will be used. It is a good practice to pre-resolve hosts beforehands and
use only IP addresses to avoid blockin an IO thread.
`user_data` will become `struct ns_connection::user_data`.
For SSL connections, specify `CERT` if server is requiring client auth.
Specify `CA_CERT` to authenticate server certificate. All certificates
must be in PEM format.
Returns: new client connection, or `NULL` on error.

    int ns_send(struct ns_connection *, const void *buf, int len);
    int ns_printf(struct ns_connection *, const char *fmt, ...);
    int ns_vprintf(struct ns_connection *, const char *fmt, va_list ap);

These functions are for sending un-formatted and formatted data to the
connection. Number of written bytes is returned. Note that these sending
functions do not actually push data to the sockets, they just append data
to the output buffer. The exception is UDP connections. For UDP, data is
sent immediately, and returned value indicates an actual number of bytes
sent to the socket.

    // Utility functions
    void *ns_start_thread(void *(*f)(void *), void *p);
    int ns_socketpair2(sock_t [2], int proto);  // SOCK_STREAM or SOCK_DGRAM
    void ns_set_close_on_exec(sock_t);
    void ns_sock_to_str(sock_t sock, char *buf, size_t len, int add_port);
    int ns_hexdump(const void *buf, int len, char *dst, int dst_len);
    int ns_resolve(const char *domain_name, char *ip_addr_buf, size_t buf_len);

# License

Net Skeleton is released under
[GNU GPL v.2](http://www.gnu.org/licenses/old-licenses/gpl-2.0.html).
Businesses have an option to get non-restrictive, royalty-free commercial
license and professional support from
[Cesanta Software](http://cesanta.com).
