TCP client/server library for C/C++
===================================

Net Skeleton is a networking library written in C.
It provides easy to use event-driven interface that allows to implement
network protocols or scalable network applications  with little effort.
Net Skeleton releives developers from the burden of network programming
complexity and let them concentrate on the logic, saving time and money.

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

Net Skeleton application is done as follows:

   * Define an event handler function
   * Initialize the server by calling `ns_server_init()`
   * Optionally, create a listening socket by `ns_bind()`
   * Call `ns_server_poll()` in a loop infinitely

Net Skeleton will accept incoming connections, read and write data, and
call specified event handler for each connection when appropriate. An
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
        case ns_RECV:
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

    void ns_server_init(struct ns_server *, void *server_data, ns_callback_t);
    void ns_server_free(struct ns_server *);
    int ns_server_poll(struct ns_server *, int milli);
    void ns_server_wakeup(struct ns_server *, void *conn_param);

    int ns_bind_to(struct ns_server *, const char *port, const char *ssl_cert);
    int ns_connect(struct ns_server *, const char *host, int port, int ssl, void *);

    int ns_send(struct ns_connection *, const void *buf, int len);
    int ns_printf(struct ns_connection *, const char *fmt, ...);

    // Utility functions
    void *ns_start_thread(void *(*f)(void *), void *p);
    int ns_socketpair(int [2]);

# License

Tcp_skeleton is released under
[GNU GPL v.2](http://www.gnu.org/licenses/old-licenses/gpl-2.0.html).
Businesses have an option to get non-restrictive, royalty-free commercial
license and professional support from
[Cesanta Software](http://cesanta.com).
