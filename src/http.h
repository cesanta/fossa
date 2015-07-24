/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

/*
 * === HTTP + Websocket
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

  struct ns_str proto; /* "HTTP/1.1" -- for both request and response */
  /* HTTP Request line (or HTTP response line) */
  struct ns_str method; /* "GET" */
  struct ns_str uri;    /* "/my_file.html" */
  /* For responses, code and response status message are set */
  int resp_code;
  struct ns_str resp_status_msg;

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
#define NS_HTTP_CHUNK 102   /* struct http_message * */
#define NS_SSI_CALL 105     /* char * */

#define NS_WEBSOCKET_HANDSHAKE_REQUEST 111 /* NULL */
#define NS_WEBSOCKET_HANDSHAKE_DONE 112    /* NULL */
#define NS_WEBSOCKET_FRAME 113             /* struct websocket_message * */
#define NS_WEBSOCKET_CONTROL_FRAME 114     /* struct websocket_message * */

/*
 * Attach built-in HTTP event handler to the given connection.
 * User-defined event handler will receive following extra events:
 *
 * - NS_HTTP_REQUEST: HTTP request has arrived. Parsed HTTP request is passed as
 *   `struct http_message` through the handler's `void *ev_data` pointer.
 * - NS_HTTP_REPLY: HTTP reply has arrived. Parsed HTTP reply is passed as
 *   `struct http_message` through the handler's `void *ev_data` pointer.
 * - NS_HTTP_CHUNK: HTTP chunked-encoding chunk has arrived.
 *   Parsed HTTP reply is passed as `struct http_message` through the
 *   handler's `void *ev_data` pointer. `http_message::body` would contain
 *   incomplete, reassembled HTTP body.
 *   It will grow with every new chunk arrived, and
 *   potentially can consume a lot of memory. An event handler may process
 *   the body as chunks are coming, and signal Fossa to delete processed
 *   body by setting `NSF_DELETE_CHUNK` in `ns_connection::flags`. When
 *   the last zero chunk is received, Fossa sends `NS_HTTP_REPLY` event will
 *   full reassembled body (if handler did not signal to delete chunks) or
 *   with empty body (if handler did signal to delete chunks).
 * - NS_WEBSOCKET_HANDSHAKE_REQUEST: server has received websocket handshake
 *   request. `ev_data` contains parsed HTTP request.
 * - NS_WEBSOCKET_HANDSHAKE_DONE: server has completed Websocket handshake.
 *   `ev_data` is `NULL`.
 * - NS_WEBSOCKET_FRAME: new websocket frame has arrived. `ev_data` is
 *   `struct websocket_message *`
 */
void ns_set_protocol_http_websocket(struct ns_connection *nc);

/*
 * Send websocket handshake to the server.
 *
 * `nc` must be a valid connection, connected to a server. `uri` is an URI
 * to fetch, extra_headers` is extra HTTP headers to send or `NULL`.
 *
 * This function is intended to be used by websocket client.
 */
void ns_send_websocket_handshake(struct ns_connection *nc, const char *uri,
                                 const char *extra_headers);

/*
 * Send websocket frame to the remote end.
 *
 * `op` specifies frame's type , one of:
 *
 * - WEBSOCKET_OP_CONTINUE
 * - WEBSOCKET_OP_TEXT
 * - WEBSOCKET_OP_BINARY
 * - WEBSOCKET_OP_CLOSE
 * - WEBSOCKET_OP_PING
 * - WEBSOCKET_OP_PONG
 * `data` and `data_len` contain frame data.
 */
void ns_send_websocket_frame(struct ns_connection *nc, int op, const void *data,
                             size_t data_len);

/*
 * Send multiple websocket frames.
 *
 * Like `ns_send_websocket_frame()`, but composes a frame from multiple buffers.
 */
void ns_send_websocket_framev(struct ns_connection *nc, int op,
                              const struct ns_str *strings, int num_strings);

/*
 * Send websocket frame to the remote end.
 *
 * Like `ns_send_websocket_frame()`, but allows to create formatted message
 * with `printf()`-like semantics.
 */
void ns_printf_websocket_frame(struct ns_connection *nc, int op,
                               const char *fmt, ...);

/*
 * Send buffer `buf` of size `len` to the client using chunked HTTP encoding.
 * This function first sends buffer size as hex number + newline, then
 * buffer itself, then newline. For example,
 *   `ns_send_http_chunk(nc, "foo", 3)` whill append `3\r\nfoo\r\n` string to
 * the `nc->send_mbuf` output IO buffer.
 *
 * NOTE: HTTP header "Transfer-Encoding: chunked" should be sent prior to
 * using this function.
 *
 * NOTE: do not forget to send empty chunk at the end of the response,
 * to tell the client that everything was sent. Example:
 *
 * ```
 *   ns_printf_http_chunk(nc, "%s", "my response!");
 *   ns_send_http_chunk(nc, "", 0); // Tell the client we're finished
 * ```
 */
void ns_send_http_chunk(struct ns_connection *nc, const char *buf, size_t len);

/*
 * Send printf-formatted HTTP chunk.
 * Functionality is similar to `ns_send_http_chunk()`.
 */
void ns_printf_http_chunk(struct ns_connection *, const char *, ...);

/*
 * Send printf-formatted HTTP chunk, escaping HTML tags.
 */
void ns_printf_html_escape(struct ns_connection *, const char *, ...);

/* Websocket opcodes, from http://tools.ietf.org/html/rfc6455 */
#define WEBSOCKET_OP_CONTINUE 0
#define WEBSOCKET_OP_TEXT 1
#define WEBSOCKET_OP_BINARY 2
#define WEBSOCKET_OP_CLOSE 8
#define WEBSOCKET_OP_PING 9
#define WEBSOCKET_OP_PONG 10

/*
 * Parse a HTTP message.
 *
 * `is_req` should be set to 1 if parsing request, 0 if reply.
 *
 * Return number of bytes parsed. If HTTP message is
 * incomplete, `0` is returned. On parse error, negative number is returned.
 */
int ns_parse_http(const char *s, int n, struct http_message *hm, int is_req);

/*
 * Search and return header `name` in parsed HTTP message `hm`.
 * If header is not found, NULL is returned. Example:
 *
 *     struct ns_str *host_hdr = ns_get_http_header(hm, "Host");
 */
struct ns_str *ns_get_http_header(struct http_message *hm, const char *name);

/*
 * Parse HTTP header `hdr`. Find variable `var_name` and store it's value
 * in the buffer `buf`, `buf_size`. Return 0 if variable not found, non-zero
 * otherwise.
 *
 * This function is supposed to parse
 * cookies, authentication headers, etcetera. Example (error handling omitted):
 *
 *     char user[20];
 *     struct ns_str *hdr = ns_get_http_header(hm, "Authorization");
 *     ns_http_parse_header(hdr, "username", user, sizeof(user));
 *
 * Return length of the variable's value. If buffer is not large enough,
 * or variable not found, 0 is returned.
 */
int ns_http_parse_header(struct ns_str *hdr, const char *var_name, char *buf,
                         size_t buf_size);

/*
 * Parse buffer `buf`, `buf_len` that contains multipart form data chunks.
 * Store chunk name in a `var_name`, `var_name_len` buffer.
 * If a chunk is an uploaded file, then `file_name`, `file_name_len` is
 * filled with an uploaded file name. `chunk`, `chunk_len`
 * points to the chunk data.
 *
 * Return: number of bytes to skip to the next chunk, or 0 if there are
 *         no more chunks.
 *
 * Usage example:
 *
 *    static void ev_handler(struct ns_connection *nc, int ev, void *ev_data) {
 *      switch(ev) {
 *        case NS_HTTP_REQUEST: {
 *          struct http_message *hm = (struct http_message *) ev_data;
 *          char var_name[100], file_name[100];
 *          const char *chunk;
 *          size_t chunk_len, n1, n2;
 *
 *          n1 = n2 = 0;
 *          while ((n2 = ns_parse_multipart(hm->body.p + n1,
 *                                          hm->body.len - n1,
 *                                          var_name, sizeof(var_name),
 *                                          file_name, sizeof(file_name),
 *                                          &chunk, &chunk_len)) > 0) {
 *            printf("var: %s, file_name: %s, size: %d, chunk: [%.*s]\n",
 *                   var_name, file_name, (int) chunk_len,
 *                   (int) chunk_len, chunk);
 *            n1 += n2;
 *          }
 *        }
 *        break;
 *
 */
size_t ns_parse_multipart(const char *buf, size_t buf_len, char *var_name,
                          size_t var_name_len, char *file_name,
                          size_t file_name_len, const char **chunk,
                          size_t *chunk_len);

/*
 * Fetch an HTTP form variable.
 *
 * Fetch a variable `name` from a `buf` into a buffer specified by
 * `dst`, `dst_len`. Destination is always zero-terminated. Return length
 * of a fetched variable. If not found, 0 is returned. `buf` must be
 * valid url-encoded buffer. If destination is too small, `-1` is returned.
 */
int ns_get_http_var(const struct ns_str *, const char *, char *dst, size_t);

/* Create Digest authentication header for client request. */
int ns_http_create_digest_auth_header(char *buf, size_t buf_len,
                                      const char *method, const char *uri,
                                      const char *auth_domain, const char *user,
                                      const char *passwd);
/*
 * Helper function that creates outbound HTTP connection.
 *
 * `url` is a URL to fetch. It must be properly URL-encoded, e.g. have
 * no spaces, etc. By default, `ns_connect_http()` sends Connection and
 * Host headers. `extra_headers` is an extra HTTP headers to send, e.g.
 * `"User-Agent: my-app\r\n"`.
 * If `post_data` is NULL, then GET request is created. Otherwise, POST request
 * is created with the specified POST data. Examples:
 *
 * [source,c]
 * ----
 *   nc1 = ns_connect_http(mgr, ev_handler_1, "http://www.google.com", NULL,
 *                         NULL);
 *   nc2 = ns_connect_http(mgr, ev_handler_1, "https://github.com", NULL, NULL);
 *   nc3 = ns_connect_http(mgr, ev_handler_1, "my_server:8000/form_submit/",
 *                         NULL, "var_1=value_1&var_2=value_2");
 * ----
 */
struct ns_connection *ns_connect_http(struct ns_mgr *,
                                      ns_event_handler_t event_handler,
                                      const char *url,
                                      const char *extra_headers,
                                      const char *post_data);

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

  /* SSI files pattern. If not set, "**.shtml$|**.shtm$" is used. */
  const char *ssi_pattern;

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

/*
 * Serve given HTTP request according to the `options`.
 *
 * Example code snippet:
 *
 * [source,c]
 * .web_server.c
 * ----
 * static void ev_handler(struct ns_connection *nc, int ev, void *ev_data) {
 *   struct http_message *hm = (struct http_message *) ev_data;
 *   struct ns_serve_http_opts opts = { .document_root = "/var/www" };  // C99
 *
 *   switch (ev) {
 *     case NS_HTTP_REQUEST:
 *       ns_serve_http(nc, hm, opts);
 *       break;
 *     default:
 *       break;
 *   }
 * }
 * ----
 */
void ns_serve_http(struct ns_connection *, struct http_message *,
                   struct ns_serve_http_opts);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* NS_HTTP_HEADER_DEFINED */
