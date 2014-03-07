TCP client/server library for C/C++
===================================

Tcp_skeleton is a TCP communication library written in C.
It provides easy to use event-driven interface that allows to
implement any TCP-based protocol with little effort.

# Features

   * Includes both client and server functionality
   * Cross-platform: works on Windows, Linux/UNIX, QNX, Android, iPhone, etc
   * Single-threaded, asynchronous, non-blocking core
   * SSL/TLS support
   * Tiny compiled and run-time footprint

# Usage

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
