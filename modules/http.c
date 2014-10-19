// Copyright (c) 2014 Cesanta Software Limited
// All rights reserved

#ifndef NS_DISABLE_HTTP_WEBSOCKET

#include "net_skeleton.h"
#include "sha1.h"
#include "util.h"
#include "http.h"

// Check whether full request is buffered. Return:
//   -1  if request is malformed
//    0  if request is not yet fully buffered
//   >0  actual request length, including last \r\n\r\n
static int get_request_len(const char *s, int buf_len) {
  const unsigned char *buf = (unsigned char *) s;
  int i;

  for (i = 0; i < buf_len; i++) {
    if (!isprint(buf[i]) && buf[i] != '\r' && buf[i] != '\n' && buf[i] < 128) {
      return -1;
    } else if (buf[i] == '\n' && i + 1 < buf_len && buf[i + 1] == '\n') {
      return i + 2;
    } else if (buf[i] == '\n' && i + 2 < buf_len && buf[i + 1] == '\r' &&
               buf[i + 2] == '\n') {
      return i + 3;
    }
  }

  return 0;
}

static int parse_http(const char *s, int n, struct http_message *req) {
  const char *end;
  int len, i;

  if ((len = get_request_len(s, n)) <= 0) return len;

  memset(req, 0, sizeof(*req));
  req->message.p = s;
  req->body.p = s + len;
  req->message.len = req->body.len = (size_t) ~0;
  end = s + len;

  // Request is fully buffered. Skip leading whitespaces.
  while (s < end && isspace(* (unsigned char *) s)) s++;

  // Parse request line: method, URI, proto
  s = ns_skip(s, end, " ", &req->method);
  s = ns_skip(s, end, " ", &req->uri);
  s = ns_skip(s, end, "\r\n", &req->proto);
  if (req->uri.p <= req->method.p || req->proto.p <= req->uri.p) return -1;

  for (i = 0; i < (int) ARRAY_SIZE(req->header_names); i++) {
    struct ns_str *k = &req->header_names[i], *v = &req->header_values[i];

    s = ns_skip(s, end, ": ", k);
    s = ns_skip(s, end, "\r\n", v);

    while (v->len > 0 && v->p[v->len - 1] == ' ') {
      v->len--;  // Trim trailing spaces in header value
    }

    if (k->len == 0 || v->len == 0) {
      k->p = v->p = NULL;
      break;
    }

    if (!ns_ncasecmp(k->p, "Content-Length", 14)) {
      req->body.len = to64(v->p);
      req->message.len = len + req->body.len;
    }
  }

  if (req->body.len == (size_t) ~0 && ns_vcasecmp(&req->method, "GET") == 0) {
    req->body.len = 0;
    req->message.len = len;
  }

  return len;
}

struct ns_str *get_http_header(struct http_message *hm, const char *name) {
  size_t i, len = strlen(name);

  for (i = 0; i < ARRAY_SIZE(hm->header_names); i++) {
    struct ns_str *h = &hm->header_names[i], *v = &hm->header_values[i];
    if (h->p != NULL && h->len == len && !ns_ncasecmp(h->p, name, len)) return v;
  }

  return NULL;
}

static int deliver_websocket_data(struct ns_connection *nc) {
  // Having buf unsigned char * is important, as it is used below in arithmetic
  unsigned char *buf = (unsigned char *) nc->recv_iobuf.buf;
  uint64_t i, data_len = 0, frame_len = 0, buf_len = nc->recv_iobuf.len,
  len, mask_len = 0, header_len = 0, ok;

  if (buf_len >= 2) {
    len = buf[1] & 127;
    mask_len = buf[1] & 128 ? 4 : 0;
    if (len < 126 && buf_len >= mask_len) {
      data_len = len;
      header_len = 2 + mask_len;
    } else if (len == 126 && buf_len >= 4 + mask_len) {
      header_len = 4 + mask_len;
      data_len = ntohs(* (uint16_t *) &buf[2]);
    } else if (buf_len >= 10 + mask_len) {
      header_len = 10 + mask_len;
      data_len = (((uint64_t) ntohl(* (uint32_t *) &buf[2])) << 32) +
        ntohl(* (uint32_t *) &buf[6]);
    }
  }

  frame_len = header_len + data_len;
  ok = frame_len > 0 && frame_len <= buf_len;

  if (ok) {
    struct websocket_message wsm;

    wsm.size = (size_t) data_len;
    wsm.data = buf + header_len;
    wsm.flags = buf[0];

    // Apply mask if necessary
    if (mask_len > 0) {
      for (i = 0; i < data_len; i++) {
        buf[i + header_len] ^= (buf + header_len - mask_len)[i % 4];
      }
    }

    // Call event handler
    ((ns_event_handler_t) nc->proto_data)(nc, NS_WEBSOCKET_FRAME, &wsm);

    // Remove frame from the iobuf
    iobuf_remove(&nc->recv_iobuf, frame_len);
  }

  return ok;
}

static void ns_send_ws_header(struct ns_connection *nc, int op, size_t len) {
  int header_len;
  unsigned char header[10];

  header[0] = 0x80 + (op & 0x0f);
  if (len < 126) {
    header[1] = len;
    header_len = 2;
  } else if (len < 65535) {
    header[1] = 126;
    * (uint16_t *) &header[2] = htons((uint16_t) len);
    header_len = 4;
  } else {
    header[1] = 127;
    * (uint32_t *) &header[2] = htonl((uint32_t) ((uint64_t) len >> 32));
    * (uint32_t *) &header[6] = htonl((uint32_t) (len & 0xffffffff));
    header_len = 10;
  }
  ns_send(nc, header, header_len);
}

void ns_send_websocket_frame(struct ns_connection *nc, int op,
                             const void *data, size_t len) {
  ns_send_ws_header(nc, op, len);
  ns_send(nc, data, len);

  if (op == WEBSOCKET_OP_CLOSE) {
    nc->flags |= NSF_FINISHED_SENDING_DATA;
  }
}

void ns_printf_websocket(struct ns_connection *nc, int op,
                         const char *fmt, ...) {
  char mem[4192], *buf = mem;
  va_list ap;
  int len;

  va_start(ap, fmt);
  if ((len = ns_avprintf(&buf, sizeof(mem), fmt, ap)) > 0) {
    ns_send_websocket_frame(nc, op, buf, len);
  }
  va_end(ap);

  if (buf != mem && buf != NULL) {
    free(buf);
  }
}

static void websocket_handler(struct ns_connection *nc, int ev, void *ev_data) {
  ns_event_handler_t cb = (ns_event_handler_t) nc->proto_data;

  cb(nc, ev, ev_data);

  switch (ev) {
    case NS_RECV:
      do { } while (deliver_websocket_data(nc));
      break;
    default:
      break;
  }
}

static void send_websocket_handshake(struct ns_connection *nc,
                                     const struct ns_str *key) {
  static const char *magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  char buf[500], sha[20], b64_sha[sizeof(sha) * 2];
  SHA1_CTX sha_ctx;

  snprintf(buf, sizeof(buf), "%.*s%s", (int) key->len, key->p, magic);

  SHA1Init(&sha_ctx);
  SHA1Update(&sha_ctx, (unsigned char *) buf, strlen(buf));
  SHA1Final((unsigned char *) sha, &sha_ctx);

  ns_base64_encode((unsigned char *) sha, sizeof(sha), b64_sha);
  ns_printf(nc, "%s%s%s",
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: ", b64_sha, "\r\n\r\n");
}

static void http_handler(struct ns_connection *nc, int ev, void *ev_data) {
  struct iobuf *io = &nc->recv_iobuf;
  ns_event_handler_t cb = (ns_event_handler_t) nc->proto_data;
  struct http_message hm;
  struct ns_str *vec;
  int req_len;

  cb(nc, ev, ev_data);

  switch (ev) {

    case NS_RECV:
      req_len = parse_http(io->buf, io->len, &hm);
      if (req_len < 0 || io->len >= NS_MAX_HTTP_REQUEST_SIZE) {
        nc->flags |= NSF_CLOSE_IMMEDIATELY;
      } else if (req_len == 0) {
        // Do nothing, request is not yet fully buffered
      } else if (nc->listener == NULL &&
                 get_http_header(&hm, "Sec-WebSocket-Accept")) {
        // We're websocket client, got handshake response from server.
        // TODO(lsm): check the validity of accept Sec-WebSocket-Accept
        iobuf_remove(io, req_len);
        nc->callback = websocket_handler;
        nc->flags |= NSF_USER_1;
        cb(nc, NS_WEBSOCKET_HANDSHAKE_DONE, NULL);
        websocket_handler(nc, NS_RECV, ev_data);
      } else if (nc->listener != NULL &&
                 (vec = get_http_header(&hm, "Sec-WebSocket-Key")) != NULL) {
        // This is a websocket request. Switch protocol handlers.
        iobuf_remove(io, req_len);
        nc->callback = websocket_handler;
        nc->flags |= NSF_USER_1;

        // Send handshake
        cb(nc, NS_WEBSOCKET_HANDSHAKE_REQUEST, NULL);
        if (!(nc->flags & NSF_CLOSE_IMMEDIATELY)) {
          if (nc->send_iobuf.len == 0) {
            send_websocket_handshake(nc, vec);
          }
          cb(nc, NS_WEBSOCKET_HANDSHAKE_DONE, NULL);
          websocket_handler(nc, NS_RECV, ev_data);
        }
      } else if (hm.message.len <= io->len) {
        // Whole HTTP message is fully buffered, call event handler
        if (cb) cb(nc, nc->listener ? NS_HTTP_REQUEST : NS_HTTP_REPLY, &hm);
        iobuf_remove(io, hm.message.len);
      }
      break;

    case NS_CLOSE:
      if (io->len > 0 && parse_http(io->buf, io->len, &hm) > 0 && cb) {
        hm.body.len = io->buf + io->len - hm.body.p;
        cb(nc, nc->listener ? NS_HTTP_REQUEST : NS_HTTP_REPLY, &hm);
      }
      break;

    default:
      break;
  }
}

void ns_set_protocol_http_websocket(struct ns_connection *nc) {
  nc->proto_data = (void *) nc->callback;
  nc->callback = http_handler;
}

void ns_send_websocket_handshake(struct ns_connection *nc, const char *uri,
                                 const char *extra_headers) {
  unsigned long random = (unsigned long) uri;
  char key[sizeof(random) * 2];

  ns_base64_encode((unsigned char *) &random, sizeof(random), key);
  ns_printf(nc, "GET %s HTTP/1.1\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "Sec-WebSocket-Key: %s\r\n"
            "%s\r\n",
            uri, key, extra_headers == NULL ? "" : extra_headers);
}


void ns_send_http_file(struct ns_connection *nc, const char *path,
                       ns_stat_t *st) {
  char buf[BUFSIZ];
  size_t n;
  FILE *fp;

  if ((fp = fopen(path, "rb")) != NULL) {
    ns_printf(nc, "HTTP/1.1 200 OK\r\n"
              "Content-Length: %lu\r\n\r\n", (unsigned long) st->st_size);
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
      ns_send(nc, buf, n);
    }
    fclose(fp);
  } else {
    ns_printf(nc, "%s", "HTTP/1.1 500 Server Error\r\n"
              "Content-Length: 0\r\n\r\n");
  }
}

static void remove_double_dots(char *s) {
  char *p = s;

  while (*s != '\0') {
    *p++ = *s++;
    if (s[-1] == '/' || s[-1] == '\\') {
      while (s[0] != '\0') {
        if (s[0] == '/' || s[0] == '\\') {
          s++;
        } else if (s[0] == '.' && s[1] == '.') {
          s += 2;
        } else {
          break;
        }
      }
    }
  }
  *p = '\0';
}

void ns_serve_http(struct ns_connection *nc, struct http_message *hm,
                   struct http_server_opts opts) {
  char path[NS_MAX_PATH];
  ns_stat_t st;

  snprintf(path, sizeof(path), "%s/%.*s", opts.document_root, (int) hm->uri.len, hm->uri.p);
  remove_double_dots(path);

  if (stat(path, &st) != 0) {
    ns_printf(nc, "%s", "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
  } else if (S_ISDIR(st.st_mode)) {
    strncat(path, "/index.html", sizeof(path) - (strlen(path) + 1));
    if (stat(path, &st) == 0) {
      ns_send_http_file(nc, path, &st);
    } else {
      ns_printf(nc, "%s", "HTTP/1.1 403 Access Denied\r\n"
                "Content-Length: 0\r\n\r\n");
    }
  } else {
    ns_send_http_file(nc, path, &st);
  }
}
#endif  // NS_DISABLE_HTTP_WEBSOCKET
