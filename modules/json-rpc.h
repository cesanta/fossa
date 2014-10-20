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
