// Copyright (c) 2014 Cesanta Software Limited
// All rights reserved

#ifndef NS_HTTP_HEADER_DEFINED
#define NS_HTTP_HEADER_DEFINED

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define NS_MAX_HTTP_HEADERS 40
#define NS_MAX_HTTP_REQUEST_SIZE 8192
#define NS_MAX_PATH 1024

struct http_message {
  struct ns_str message;    // Whole message: request line + headers + body

  // HTTP Request line (or HTTP response line)
  struct ns_str method;     // "GET"
  struct ns_str uri;        // "/my_file.html"
  struct ns_str proto;      // "HTTP/1.1"

  // Headers
  struct ns_str header_names[NS_MAX_HTTP_HEADERS];
  struct ns_str header_values[NS_MAX_HTTP_HEADERS];

  // Message body
  struct ns_str body;            // Zero-length for requests with no body
};

struct websocket_message {
  unsigned char *data;
  size_t size;
  unsigned flags;
};

// HTTP and websocket events. void *ev_data is described in a comment.
#define NS_HTTP_REQUEST                 100   // struct http_message *
#define NS_HTTP_REPLY                   101   // struct http_message *

#define NS_WEBSOCKET_HANDSHAKE_REQUEST  111   // NULL
#define NS_WEBSOCKET_HANDSHAKE_DONE     112   // NULL
#define NS_WEBSOCKET_FRAME              113   // struct websocket_message *
#define NS_WEBSOCKET_NOT_SUPPORTED      114   // NULL

struct ns_connection *ns_bind_http(struct ns_mgr *mgr, const char *addr,
                                   ns_event_handler_t cb, void *user_data);

struct ns_connection *ns_connect_http(struct ns_mgr *mgr, const char *addr,
                                      ns_event_handler_t cb, void *user_data);

struct ns_connection *ns_connect_websocket(struct ns_mgr *mgr, const char *addr,
                                           ns_event_handler_t cb, void *user_data,
                                           const char *uri, const char *hdrs);

void ns_send_websocket(struct ns_connection *, int op, const void *, size_t);
void ns_printf_websocket(struct ns_connection *, int op, const char *, ...);

// Websocket opcodes, from http://tools.ietf.org/html/rfc6455
#define WEBSOCKET_OP_CONTINUE  0
#define WEBSOCKET_OP_TEXT      1
#define WEBSOCKET_OP_BINARY    2
#define WEBSOCKET_OP_CLOSE     8
#define WEBSOCKET_OP_PING      9
#define WEBSOCKET_OP_PONG      10

// Utility functions
struct ns_str *get_http_header(struct http_message *, const char *);
void ns_serve_uri_from_fs(struct ns_connection *, struct ns_str *uri,
                          const char *web_root);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif  // NS_HTTP_HEADER_DEFINED
