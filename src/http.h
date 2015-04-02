/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#ifndef NS_HTTP_HEADER_DEFINED
#define NS_HTTP_HEADER_DEFINED

#include "net.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef NS_MAX_HTTP_HEADERS
#define NS_MAX_HTTP_HEADERS 40
#endif

#ifndef NS_MAX_HTTP_REQUEST_SIZE
#define NS_MAX_HTTP_REQUEST_SIZE 8192
#endif

#ifndef NS_MAX_PATH
#define NS_MAX_PATH 1024
#endif

#ifndef NS_MAX_HTTP_SEND_IOBUF
#define NS_MAX_HTTP_SEND_IOBUF 4096
#endif

#ifndef NS_WEBSOCKET_PING_INTERVAL_SECONDS
#define NS_WEBSOCKET_PING_INTERVAL_SECONDS 5
#endif

#ifndef NS_CGI_ENVIRONMENT_SIZE
#define NS_CGI_ENVIRONMENT_SIZE 8192
#endif

#ifndef NS_MAX_CGI_ENVIR_VARS
#define NS_MAX_CGI_ENVIR_VARS 64
#endif

#ifndef NS_ENV_EXPORT_TO_CGI
#define NS_ENV_EXPORT_TO_CGI "FOSSA_CGI"
#endif

/* HTTP message */
struct http_message {
  struct ns_str message; /* Whole message: request line + headers + body */

  /* HTTP Request line (or HTTP response line) */
  struct ns_str method; /* "GET" */
  struct ns_str uri;    /* "/my_file.html" */
  struct ns_str proto;  /* "HTTP/1.1" */

  /*
   * Query-string part of the URI. For example, for HTTP request
   *    GET /foo/bar?param1=val1&param2=val2
   *    |    uri    |     query_string     |
   *
   * Note that question mark character doesn't belong neither to the uri,
   * nor to the query_string
   */
  struct ns_str query_string;

  /* Headers */
  struct ns_str header_names[NS_MAX_HTTP_HEADERS];
  struct ns_str header_values[NS_MAX_HTTP_HEADERS];

  /* Message body */
  struct ns_str body; /* Zero-length for requests with no body */
};

struct websocket_message {
  unsigned char *data;
  size_t size;
  unsigned char flags;
};

/* HTTP and websocket events. void *ev_data is described in a comment. */
#define NS_HTTP_REQUEST 100 /* struct http_message * */
#define NS_HTTP_REPLY 101   /* struct http_message * */

#define NS_WEBSOCKET_HANDSHAKE_REQUEST 111 /* NULL */
#define NS_WEBSOCKET_HANDSHAKE_DONE 112    /* NULL */
#define NS_WEBSOCKET_FRAME 113             /* struct websocket_message * */
#define NS_WEBSOCKET_CONTROL_FRAME 114     /* struct websocket_message * */

void ns_set_protocol_http_websocket(struct ns_connection *);
void ns_send_websocket_handshake(struct ns_connection *, const char *,
                                 const char *);
void ns_send_websocket_frame(struct ns_connection *, int, const void *, size_t);
void ns_send_websocket_framev(struct ns_connection *, int,
                              const struct ns_str *, int);
void ns_printf_websocket_frame(struct ns_connection *, int, const char *, ...);
void ns_send_http_chunk(struct ns_connection *, const char *, size_t);
void ns_printf_http_chunk(struct ns_connection *, const char *, ...);

/* Websocket opcodes, from http://tools.ietf.org/html/rfc6455 */
#define WEBSOCKET_OP_CONTINUE 0
#define WEBSOCKET_OP_TEXT 1
#define WEBSOCKET_OP_BINARY 2
#define WEBSOCKET_OP_CLOSE 8
#define WEBSOCKET_OP_PING 9
#define WEBSOCKET_OP_PONG 10

/* Utility functions */
struct ns_str *ns_get_http_header(struct http_message *, const char *);
int ns_http_parse_header(struct ns_str *, const char *, char *, size_t);
int ns_parse_http(const char *s, int n, struct http_message *req);
int ns_get_http_var(const struct ns_str *, const char *, char *dst, size_t);
int ns_http_create_digest_auth_header(char *buf, size_t buf_len,
                                      const char *method, const char *uri,
                                      const char *auth_domain, const char *user,
                                      const char *passwd);
struct ns_connection *ns_connect_http(struct ns_mgr *, ns_event_handler_t,
                                      const char *, const char *, const char *);

/*
 * This structure defines how `ns_serve_http()` works.
 * Best practice is to set only required settings, and leave the rest as NULL.
 */
struct ns_serve_http_opts {
  /* Path to web root directory */
  const char *document_root;

  /* List of index files. Default is "" */
  const char *index_files;

  /*
   * Leave as NULL to disable authentication.
   * To enable directory protection with authentication, set this to ".htpasswd"
   * Then, creating ".htpasswd" file in any directory automatically protects
   * it with digest authentication.
   * Use `mongoose` web server binary, or `htdigest` Apache utility to
   * create/manipulate passwords file.
   * Make sure `auth_domain` is set to a valid domain name.
   */
  const char *per_directory_auth_file;

  /* Authorization domain (domain name of this web server) */
  const char *auth_domain;

  /*
   * Leave as NULL to disable authentication.
   * Normally, only selected directories in the document root are protected.
   * If absolutely every access to the web server needs to be authenticated,
   * regardless of the URI, set this option to the path to the passwords file.
   * Format of that file is the same as ".htpasswd" file. Make sure that file
   * is located outside document root to prevent people fetching it.
   */
  const char *global_auth_file;

  /* Set to "no" to disable directory listing. Enabled by default. */
  const char *enable_directory_listing;

  /* SSI files suffix. By default is NULL, SSI is disabled */
  const char *ssi_suffix;

  /* IP ACL. By default, NULL, meaning all IPs are allowed to connect */
  const char *ip_acl;

  /* URL rewrites.
   *
   * Comma-separated list of `uri_pattern=file_or_directory_path` rewrites.
   * When HTTP request is received, Fossa constructs a file name from the
   * requested URI by combining `document_root` and the URI. However, if the
   * rewrite option is used and `uri_pattern` matches requested URI, then
   * `document_root` is ignored. Instead, `file_or_directory_path` is used,
   * which should be a full path name or a path relative to the web server's
   * current working directory. Note that `uri_pattern`, as all Fossa patterns,
   * is a prefix pattern.
   *
   * If uri_pattern starts with `@` symbol, then Fossa compares it with the
   * HOST header of the request. If they are equal, Fossa sets document root
   * to `file_or_directory_path`, implementing virtual hosts support.
   */
  const char *url_rewrites;

  /* DAV document root. If NULL, DAV requests are going to fail. */
  const char *dav_document_root;

  /* Glob pattern for the files to hide. */
  const char *hidden_file_pattern;

  /* Set to non-NULL to enable CGI, e.g. **.cgi$|**.php$" */
  const char *cgi_file_pattern;

  /* If not NULL, ignore CGI script hashbang and use this interpreter */
  const char *cgi_interpreter;

  /*
   * Comma-separated list of Content-Type overrides for path suffixes, e.g.
   * ".txt=text/plain; charset=utf-8,.c=text/plain"
   */
  const char *custom_mime_types;
};
void ns_serve_http(struct ns_connection *, struct http_message *,
                   struct ns_serve_http_opts);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* NS_HTTP_HEADER_DEFINED */
