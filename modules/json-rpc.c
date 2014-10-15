// Copyright (c) 2014 Cesanta Software Limited
// All rights reserved

#ifndef NS_DISABLE_JSON_RPC

#include "net_skeleton.h"
#include "json-rpc.h"

int ns_rpc_reply(struct ns_connection *nc, const char *fmt, ...) {
  struct iobuf *io = &nc->send_iobuf;
  va_list ap, ap_copy;
  int len, n = 0;

  // Find out how long the message is, without actually making a message
  va_start(ap, fmt);
  va_copy(ap_copy, ap);
  len = json_emit_va(NULL, 0, fmt, ap);
  va_end(ap);

  if (len > 0) {
    if (io->size < io->len + len) {
      iobuf_resize(io, io->len + len);
    }
    if (io->size <= io->len + len) {
      // Output buffer is large enough to hold RPC message, create a message
      n = json_emit_va(io->buf + io->len, len, fmt, ap_copy);
      io->len += n;
    }
  }
  va_end(ap_copy);

  return n;
}

#if 0
static struct ns_rpc_method *find_method(struct ns_rpc_method *tbl,
                                         const char *name, int name_len) {
  while (tbl->name != NULL) {
    if (strncmp(tbl->name, name, name_len) == 0) return tbl;
    tbl++;
  }
  return NULL;
}

int nc_rpc_dispatch(struct ns_connection *nc, struct ns_rpc_method *tbl) {
  struct iobuf *io = &nc->recv_iobuf;
  struct json_token toks[200], *method, *params, *id;
  struct ns_rpc_method *m;

  int n = parse_json(io->buf, io->len, toks, sizeof(toks));
  if (n == JSON_STRING_INCOMPLETE) {
    // Do nothing, we haven't received everything yet
  } else if (n > 0) {
    method = find_json_token(toks, "method");
    params = find_json_token(toks, "params");
    id = find_json_token(toks, "id");
    if (method != NULL && params != NULL &&
        (m = find_method(tbl, method->ptr, method->len)) != NULL) {
      m->handler(nc, id, params);
    }
    iobuf_remove(io, n);
  } else {
    iobuf_remove(io, io->len);
  }

  return n;
}
#endif

#endif  // NS_DISABLE_JSON_RPC