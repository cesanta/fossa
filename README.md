TCP client/server library for C/C++
===================================

Net Skeleton is a networking library written in C.
It provides easy to use event-driven interface that allows to implement
network protocols or scalable network applications  with little effort.
Net Skeleton releives developers from the burden of network programming
complexity and let them concentrate on the logic.
Net Skeleton saves time and money.

# Features

   * Includes both client and server functionality
   * Cross-platform: works on Windows, Linux/UNIX, QNX, Android, iPhone, etc
   * Single-threaded, asynchronous, non-blocking core
   * SSL/TLS support
   * Tiny static and run-time footprint

# Concept

Net Skeleton has three core structures:

   * `struct iobuf` - holds sent or received data
   * `struct ns_connection` - describes client or server connection
   * `struct ns_server` - holds listening socket (if any) and list of
      connections

To use Net Skeleton, a developer should:

   * Define an event handler function
   * Initialize the server by calling `ns_server_init()`
   * Optionally, create a listening socket by `ns_bind()`
   * Call `ns_server_poll()` in a loop infinitely

Net Skeleton accepts incoming connections, reads and writes data, and
calls specified event handler for each connection when appropriate. An
event handler should examine received data, set connection flags if needed,
and send data back to the client by `ns_send()` or `ns_printf()`. Here is a
typical event flow for the accepted connection:
`NS_ACCEPT` -> `NS_RECV` -> .... -> `NS_CLOSE`

Each connection has send and receive buffer, `struct ns_connection::send_iobuf`
and `struct ns_connection::recv_iobuf` respectively. When data is received
for the connection, Net Skeleton appends received data to the `recv_iobuf` and
sends `NS_RECV` event. Net Skeleton will append data indefinitely, until
RAM is exhausted, so to prevent out-of-memory situation, event handler must
discard data from `recv_iobuf` when it is not needed anymore by calling
`iobuf_remove()`.

Event handler may send data back (`ns_send()` or
`ns_printf()`), which appends data to the `send_iobuf`. When Net Skeleton
successfully writes data to the socket, it discards it from `send_iobuf` and
sends `NS_SEND` event. When connection is closed, `NS_CLOSE` event is sent.

![Diagram](http://cesanta.com/images/net_skeleton/iobuf.png)

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
      
# Example

Below is a minimalistic example that implements TCP echo server. To compile
and run on UNIX system, start terminal, copy `echo.c`, `tcp_skeleton.c` and
`tcp_skeleton.h` to some directory and execute
`cc echo.c tcp_skeleton.c -o echo && ./echo` command. That will start the
server. To connect to it, start another terminal, type
`telnet 127.0.0.1 1234` , press enter, then type any message and press enter.

    // TCP echo server
    #include "net_skeleton.h"

    static void event_handler(struct ns_connection *conn, enum ns_event ev, void *p) {
      struct iobuf *io = &conn->recv_iobuf; // IO buffer that holds received message

      switch (ev) {
        case NS_RECV:
          ns_send(conn, io->buf, io->len);  // Echo received message back
          iobuf_remove(io, io->len);        // Discard message from recv buffer
        default:
          break;    // We ignore all other events
      }
    }

    int main(void) {
      struct ns_server server;
      const char *port = "1234";

      // Initialize server and open listening port
      ns_server_init(&server, NULL, event_handler);
      ns_bind(&server, port);

      printf("Starting echo server on port %s\n", port);
      for (;;) {
        ns_server_poll(&server, 1000);
      }
      ns_server_free(&server);

      return 0;
    }

For more examples, please take a look at
[tcp_skeleton/examples](https://github.com/cesanta/tcp_skeleton/tree/master/examples).

# API

Net skeleton server instance is single threaded. All functions should be
called from the same thread, with exception of `mg_wakeup_server()`.

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

    void ns_iterate(struct ns_server *, ns_callback_t cb, void *param);

Call specified function for all active connections.

    struct ns_connection *ns_add_sock(struct ns_server *, sock_t sock, void *p);

Add a socket to the server.

    struct ns_connection *ns_connect(struct ns_server *, const char *host,
                                     int port, int ssl, void *connection_param);

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

Tcp_skeleton is released under
[GNU GPL v.2](http://www.gnu.org/licenses/old-licenses/gpl-2.0.html).
Businesses have an option to get non-restrictive, royalty-free commercial
license and professional support from
[Cesanta Software](http://cesanta.com).
