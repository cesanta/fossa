/* Copyright (c) 2014 Cesanta Software Limited
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

#define NS_SKELETON_VERSION "2.2.0"

#undef UNICODE                  /* Use ANSI WinAPI functions */
#undef _UNICODE                 /* Use multibyte encoding on Windows */
#define _MBCS                   /* Use multibyte encoding on Windows */
#define _INTEGRAL_MAX_BITS 64   /* Enable _stati64() on Windows */
#define _CRT_SECURE_NO_WARNINGS /* Disable deprecation warning in VS2005+ */
#undef WIN32_LEAN_AND_MEAN      /* Let windows.h always include winsock2.h */
#define _XOPEN_SOURCE 600       /* For flockfile() on Linux */
#define __STDC_FORMAT_MACROS    /* <inttypes.h> wants this for C++ */
#define __STDC_LIMIT_MACROS     /* C++ wants that for INT64_MAX */
#ifndef _LARGEFILE_SOURCE
#define _LARGEFILE_SOURCE       /* Enable fseeko() and ftello() functions */
#endif
#define _FILE_OFFSET_BITS 64    /* Enable 64-bit file offsets */

#ifdef _MSC_VER
#pragma warning (disable : 4127)  /* FD_SET() emits warning, disable it */
#pragma warning (disable : 4204)  /* missing c99 support */
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>

#ifdef _WIN32
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")    /* Linking with winsock library */
#endif
#include <windows.h>
#include <process.h>
#ifndef EINPROGRESS
#define EINPROGRESS WSAEINPROGRESS
#endif
#ifndef EWOULDBLOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif
#ifndef __func__
#define STRX(x) #x
#define STR(x) STRX(x)
#define __func__ __FILE__ ":" STR(__LINE__)
#endif
#ifndef __va_copy
#define __va_copy(x,y) (x) = (y)
#endif /* MINGW #defines va_copy */
#define snprintf _snprintf
#define vsnprintf _vsnprintf
#define sleep(x) Sleep((x) * 1000)
int64_t strtoll(const char * str, char ** endptr, int base);
#define to64(x) _atoi64(x)
typedef int socklen_t;
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned __int64 uint64_t;
typedef __int64   int64_t;
typedef SOCKET sock_t;
typedef struct _stati64 ns_stat_t;
#ifndef S_ISDIR
#define S_ISDIR(x) ((x) & _S_IFDIR)
#endif
#else
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdarg.h>
#include <unistd.h>
#include <arpa/inet.h>  /* For inet_pton() when NS_ENABLE_IPV6 is defined */
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#define closesocket(x) close(x)
#define __cdecl
#define INVALID_SOCKET (-1)
int64_t strtoll(const char * str, char ** endptr, int base);
#define to64(x) strtoll(x, NULL, 10)
typedef int sock_t;
typedef struct stat ns_stat_t;
#endif

#ifdef NS_ENABLE_DEBUG
#define DBG(x) do { printf("%-20s ", __func__); printf x; putchar('\n'); \
  fflush(stdout); } while(0)
#else
#define DBG(x)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))
#endif

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
  const char *p;
  size_t len;
};

/* IO buffers interface */
struct iobuf {
  char *buf;
  size_t len;
  size_t size;
};

void iobuf_init(struct iobuf *, size_t initial_size);
void iobuf_free(struct iobuf *);
size_t iobuf_append(struct iobuf *, const void *data, size_t data_size);
void iobuf_remove(struct iobuf *, size_t data_size);
void iobuf_resize(struct iobuf *, size_t new_size);

/* Callback function (event handler) prototype, must be defined by user. */
/* Net skeleton will call event handler, passing events defined above. */
struct ns_connection;
typedef void (*ns_event_handler_t)(struct ns_connection *, int ev, void *);

/* Events. Meaning of event parameter (evp) is given in the comment. */
#define NS_POLL    0  /* Sent to each connection on each call to ns_mgr_poll() */
#define NS_ACCEPT  1  /* New connection accept()-ed. union socket_address *addr */
#define NS_CONNECT 2  /* connect() succeeded or failed. int *success_status */
#define NS_RECV    3  /* Data has benn received. int *num_bytes */
#define NS_SEND    4  /* Data has been written to a socket. int *num_bytes */
#define NS_CLOSE   5  /* Connection is closed. NULL */


struct ns_mgr {
  struct ns_connection *active_connections;
  const char *hexdump_file;         /* Debug hexdump file path */
  sock_t ctl[2];                    /* Socketpair for mg_wakeup() */
  void *user_data;                  /* User data */
};

/* List of event handlers */
struct ns_cb_list {
  struct ns_cb_list *next;
  ns_event_handler_t cb;
};

#define NS_ADD_CB(nc, cb) do { \
  static struct ns_cb_chain __tmp = { (nc)->cblist, cb }; \
  (nc)->cblist = &__tmp; \
} while (0)

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
  void *user_data;            /* User-specific data */
  void *proto_data;           /* Application protocol-specific data */
  time_t last_io_time;        /* Timestamp of the last socket IO */
  ns_event_handler_t callback;     /* Event handler function */
  struct ns_cb_list *cblist;  /* List of event handlers */

  unsigned int flags;
#define NSF_FINISHED_SENDING_DATA   (1 << 0)
#define NSF_BUFFER_BUT_DONT_SEND    (1 << 1)
#define NSF_SSL_HANDSHAKE_DONE      (1 << 2)
#define NSF_CONNECTING              (1 << 3)
#define NSF_CLOSE_IMMEDIATELY       (1 << 4)
#define NSF_WANT_READ               (1 << 5)
#define NSF_WANT_WRITE              (1 << 6)
#define NSF_LISTENING               (1 << 7)
#define NSF_UDP                     (1 << 8)

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
struct ns_connection *ns_add_sock(struct ns_mgr *, sock_t, ns_event_handler_t);
struct ns_connection *ns_bind(struct ns_mgr *, const char *, ns_event_handler_t);
struct ns_connection *ns_connect(struct ns_mgr *, const char *, ns_event_handler_t);

int ns_send(struct ns_connection *, const void *buf, int len);
int ns_printf(struct ns_connection *, const char *fmt, ...);
int ns_vprintf(struct ns_connection *, const char *fmt, va_list ap);

/* Utility functions */
void *ns_start_thread(void *(*f)(void *), void *p);
int ns_socketpair(sock_t [2]);
int ns_socketpair2(sock_t [2], int sock_type);  /* SOCK_STREAM or SOCK_DGRAM */
void ns_set_close_on_exec(sock_t);
void ns_sock_to_str(sock_t sock, char *buf, size_t len, int flags);
int ns_hexdump(const void *buf, int len, char *dst, int dst_len);
int ns_avprintf(char **buf, size_t size, const char *fmt, va_list ap);
int ns_resolve(const char *domain_name, char *ip_addr_buf, size_t buf_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* NS_SKELETON_HEADER_INCLUDED */
/* Copyright (c) 2004-2013 Sergey Lyubka <valenok@gmail.com>
 * Copyright (c) 2013 Cesanta Software Limited
 * All rights reserved
 *
 * This library is dual-licensed: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. For the terms of this
 * license, see <http://www.gnu.org/licenses/>.
 *
 * You are free to use this library under the terms of the GNU General
 * Public License, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * Alternatively, you can license this library under a commercial
 * license, as set out in <http://cesanta.com/products.html>.
 */

#ifndef FROZEN_HEADER_INCLUDED
#define FROZEN_HEADER_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stdarg.h>

enum json_type {
  JSON_TYPE_EOF     = 0,      /* End of parsed tokens marker */
  JSON_TYPE_STRING  = 1,
  JSON_TYPE_NUMBER  = 2,
  JSON_TYPE_OBJECT  = 3,
  JSON_TYPE_TRUE    = 4,
  JSON_TYPE_FALSE   = 5,
  JSON_TYPE_NULL    = 6,
  JSON_TYPE_ARRAY   = 7
};

struct json_token {
  const char *ptr;      /* Points to the beginning of the token */
  int len;              /* Token length */
  int num_desc;         /* For arrays and object, total number of descendants */
  enum json_type type;  /* Type of the token, possible values above */
};

/* Error codes */
#define JSON_STRING_INVALID           -1
#define JSON_STRING_INCOMPLETE        -2
#define JSON_TOKEN_ARRAY_TOO_SMALL    -3

int parse_json(const char *json_string, int json_string_length,
               struct json_token *tokens_array, int size_of_tokens_array);
struct json_token *parse_json2(const char *json_string, int string_length);
struct json_token *find_json_token(struct json_token *toks, const char *path);

int json_emit_long(char *buf, int buf_len, long value);
int json_emit_double(char *buf, int buf_len, double value);
int json_emit_quoted_str(char *buf, int buf_len, const char *str, int len);
int json_emit_unquoted_str(char *buf, int buf_len, const char *str, int len);
int json_emit(char *buf, int buf_len, const char *fmt, ...);
int json_emit_va(char *buf, int buf_len, const char *fmt, va_list);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* FROZEN_HEADER_INCLUDED */
/* Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#ifndef NS_SHA1_HEADER_INCLUDED
#define NS_SHA1_HEADER_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} SHA1_CTX;

void SHA1Init(SHA1_CTX *);
void SHA1Update(SHA1_CTX *, const unsigned char *data, uint32_t len);
void SHA1Final(unsigned char digest[20], SHA1_CTX *);

#ifdef __cplusplus
}
#endif  /* __cplusplus */
#endif  /* NS_SHA1_HEADER_INCLUDED */
/* Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#ifndef NS_UTIL_HEADER_DEFINED
#define NS_UTIL_HEADER_DEFINED

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

const char *ns_skip(const char *, const char *, const char *, struct ns_str *);
int ns_ncasecmp(const char *s1, const char *s2, size_t len);
int ns_vcmp(const struct ns_str *str2, const char *str1);
int ns_vcasecmp(const struct ns_str *str2, const char *str1);
void ns_base64_decode(const unsigned char *s, int len, char *dst);
void ns_base64_encode(const unsigned char *src, int src_len, char *dst);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif  /* NS_UTIL_HEADER_DEFINED */
/* Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#ifndef NS_HTTP_HEADER_DEFINED
#define NS_HTTP_HEADER_DEFINED

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define NS_MAX_HTTP_HEADERS 40
#define NS_MAX_HTTP_REQUEST_SIZE 8192
#define NS_MAX_PATH 1024

struct http_message {
  struct ns_str message;    /* Whole message: request line + headers + body */

  /* HTTP Request line (or HTTP response line) */
  struct ns_str method;     /* "GET" */
  struct ns_str uri;        /* "/my_file.html" */
  struct ns_str proto;      /* "HTTP/1.1" */

  /* Headers */
  struct ns_str header_names[NS_MAX_HTTP_HEADERS];
  struct ns_str header_values[NS_MAX_HTTP_HEADERS];

  /* Message body */
  struct ns_str body;            /* Zero-length for requests with no body */
};

struct websocket_message {
  unsigned char *data;
  size_t size;
  unsigned flags;
};

/* HTTP and websocket events. void *ev_data is described in a comment. */
#define NS_HTTP_REQUEST                 100   /* struct http_message * */
#define NS_HTTP_REPLY                   101   /* struct http_message * */

#define NS_WEBSOCKET_HANDSHAKE_REQUEST  111   /* NULL */
#define NS_WEBSOCKET_HANDSHAKE_DONE     112   /* NULL */
#define NS_WEBSOCKET_FRAME              113   /* struct websocket_message * */
#define NS_WEBSOCKET_NOT_SUPPORTED      114   /* NULL */

void ns_set_protocol_http_websocket(struct ns_connection *);
void ns_send_websocket_handshake(struct ns_connection *, const char *,
                                 const char *);
void ns_send_websocket_frame(struct ns_connection *, int, const void *, size_t);
void ns_printf_websocket_frame(struct ns_connection *, int, const char *, ...);

/* Websocket opcodes, from http://tools.ietf.org/html/rfc6455 */
#define WEBSOCKET_OP_CONTINUE  0
#define WEBSOCKET_OP_TEXT      1
#define WEBSOCKET_OP_BINARY    2
#define WEBSOCKET_OP_CLOSE     8
#define WEBSOCKET_OP_PING      9
#define WEBSOCKET_OP_PONG      10

/* Utility functions */
struct ns_str *ns_get_http_header(struct http_message *, const char *);

struct http_server_opts {
  const char *document_root;
  const char *index_files;
};
void ns_serve_http(struct ns_connection *, struct http_message *,
                   struct http_server_opts);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif  /* NS_HTTP_HEADER_DEFINED */
/* Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#ifndef NS_JSON_RPC_HEADER_DEFINED
#define NS_JSON_RPC_HEADER_DEFINED

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct ns_rpc_request {
  struct json_token *message;   /* Whole RPC message */
  struct json_token *id;        /* Message ID */
  struct json_token *method;    /* Method name */
  struct json_token *params;    /* Method params */
};
typedef void (*ns_rpc_request_handler_t)(struct ns_connection *,
                                         struct ns_rpc_request *);

struct ns_rpc_reply {
  struct json_token *message;   /* Whole RPC message */
  struct json_token *id;        /* Message ID */
  struct json_token *result;    /* Remote call result */
};

struct ns_rpc_error {
  struct json_token *message;   /* Whole RPC message */
  struct json_token *id;        /* Message ID */
  struct json_token *error_code;      /* error.code */
  struct json_token *error_message;   /* error.message */
  struct json_token *error_data;      /* error.data, can be NULL */
};
typedef void (*ns_rpc_reply_handler_t)(struct ns_connection *,
                                       struct ns_rpc_reply *,
                                       struct ns_rpc_error *);

int ns_printf_rpc_request(struct ns_connection *, const char *method,
                          const char *params_fmt, ...);
int ns_printf_rpc_result(struct ns_connection *, struct json_token *id,
                         const char *result_fmt, ...);
int ns_printf_rpc_error(struct ns_connection *, int code,
                        struct json_token *id, const char *msg_fmt, ...);

int ns_handle_rpc_request(struct ns_connection *, const void *buf, int len,
                          ns_rpc_request_handler_t);
int ns_handle_rpc_reply(struct ns_connection *, const void *buf, int len,
                        ns_rpc_reply_handler_t);


int ns_printf_standard_rpc_error(struct ns_connection *, int code,
                                 struct json_token *id);

/* JSON-RPC standard error codes */
#define JSON_RPC_PARSE_ERROR              (-32700)
#define JSON_RPC_INVALID_REQUEST_ERROR    (-32600)
#define JSON_RPC_METHOD_NOT_FOUND_ERROR   (-32601)
#define JSON_RPC_INVALID_PARAMS_ERROR     (-32602)
#define JSON_RPC_INTERNAL_ERROR           (-32603)
#define JSON_RPC_SERVER_ERROR             (-32000)

int ns_rpc_reply(struct ns_connection *, const char *fmt, ...);
/*int nc_rpc_dispatch(struct ns_connection *, struct ns_rpc_method *); */

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif  /* NS_JSON_RPC_HEADER_DEFINED */
