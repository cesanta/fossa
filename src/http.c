/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

/*
 * == HTTP/Websocket API
 */

#ifndef NS_DISABLE_HTTP_WEBSOCKET

#include "internal.h"

enum http_proto_data_type { DATA_FILE, DATA_PUT, DATA_CGI };

struct proto_data_http {
  FILE *fp;     /* Opened file. */
  int64_t cl;   /* Content-Length. How many bytes to send. */
  int64_t sent; /* How many bytes have been already sent. */
  struct ns_connection *cgi_nc;
  enum http_proto_data_type type;
};

/*
 * This structure helps to create an environment for the spawned CGI program.
 * Environment is an array of "VARIABLE=VALUE\0" ASCIIZ strings,
 * last element must be NULL.
 * However, on Windows there is a requirement that all these VARIABLE=VALUE\0
 * strings must reside in a contiguous buffer. The end of the buffer is
 * marked by two '\0' characters.
 * We satisfy both worlds: we create an envp array (which is vars), all
 * entries are actually pointers inside buf.
 */
struct cgi_env_block {
  struct ns_connection *nc;
  char buf[NS_CGI_ENVIRONMENT_SIZE];       /* Environment buffer */
  const char *vars[NS_MAX_CGI_ENVIR_VARS]; /* char *envp[] */
  int len;                                 /* Space taken */
  int nvars;                               /* Number of variables in envp[] */
};

#define MIME_ENTRY(_ext, _type) \
  { _ext, sizeof(_ext) - 1, _type }
static const struct {
  const char *extension;
  size_t ext_len;
  const char *mime_type;
} static_builtin_mime_types[] = {
    MIME_ENTRY("html", "text/html"),
    MIME_ENTRY("html", "text/html"),
    MIME_ENTRY("htm", "text/html"),
    MIME_ENTRY("shtm", "text/html"),
    MIME_ENTRY("shtml", "text/html"),
    MIME_ENTRY("css", "text/css"),
    MIME_ENTRY("js", "application/x-javascript"),
    MIME_ENTRY("ico", "image/x-icon"),
    MIME_ENTRY("gif", "image/gif"),
    MIME_ENTRY("jpg", "image/jpeg"),
    MIME_ENTRY("jpeg", "image/jpeg"),
    MIME_ENTRY("png", "image/png"),
    MIME_ENTRY("svg", "image/svg+xml"),
    MIME_ENTRY("txt", "text/plain"),
    MIME_ENTRY("torrent", "application/x-bittorrent"),
    MIME_ENTRY("wav", "audio/x-wav"),
    MIME_ENTRY("mp3", "audio/x-mp3"),
    MIME_ENTRY("mid", "audio/mid"),
    MIME_ENTRY("m3u", "audio/x-mpegurl"),
    MIME_ENTRY("ogg", "application/ogg"),
    MIME_ENTRY("ram", "audio/x-pn-realaudio"),
    MIME_ENTRY("xml", "text/xml"),
    MIME_ENTRY("ttf", "application/x-font-ttf"),
    MIME_ENTRY("json", "application/json"),
    MIME_ENTRY("xslt", "application/xml"),
    MIME_ENTRY("xsl", "application/xml"),
    MIME_ENTRY("ra", "audio/x-pn-realaudio"),
    MIME_ENTRY("doc", "application/msword"),
    MIME_ENTRY("exe", "application/octet-stream"),
    MIME_ENTRY("zip", "application/x-zip-compressed"),
    MIME_ENTRY("xls", "application/excel"),
    MIME_ENTRY("tgz", "application/x-tar-gz"),
    MIME_ENTRY("tar", "application/x-tar"),
    MIME_ENTRY("gz", "application/x-gunzip"),
    MIME_ENTRY("arj", "application/x-arj-compressed"),
    MIME_ENTRY("rar", "application/x-rar-compressed"),
    MIME_ENTRY("rtf", "application/rtf"),
    MIME_ENTRY("pdf", "application/pdf"),
    MIME_ENTRY("swf", "application/x-shockwave-flash"),
    MIME_ENTRY("mpg", "video/mpeg"),
    MIME_ENTRY("webm", "video/webm"),
    MIME_ENTRY("mpeg", "video/mpeg"),
    MIME_ENTRY("mov", "video/quicktime"),
    MIME_ENTRY("mp4", "video/mp4"),
    MIME_ENTRY("m4v", "video/x-m4v"),
    MIME_ENTRY("asf", "video/x-ms-asf"),
    MIME_ENTRY("avi", "video/x-msvideo"),
    MIME_ENTRY("bmp", "image/bmp"),
    {NULL, 0, NULL}};

#ifndef NS_DISABLE_FILESYSTEM
static const char *get_mime_type(const char *path, const char *dflt) {
  const char *ext;
  size_t i, path_len;

  path_len = strlen(path);

  for (i = 0; static_builtin_mime_types[i].extension != NULL; i++) {
    ext = path + (path_len - static_builtin_mime_types[i].ext_len);
    if (path_len > static_builtin_mime_types[i].ext_len && ext[-1] == '.' &&
        ns_casecmp(ext, static_builtin_mime_types[i].extension) == 0) {
      return static_builtin_mime_types[i].mime_type;
    }
  }

  return dflt;
}
#endif

/*
 * Check whether full request is buffered. Return:
 *   -1  if request is malformed
 *    0  if request is not yet fully buffered
 *   >0  actual request length, including last \r\n\r\n
 */
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

static const char *parse_http_headers(const char *s, const char *end, int len,
                                      struct http_message *req) {
  int i;
  for (i = 0; i < (int) ARRAY_SIZE(req->header_names); i++) {
    struct ns_str *k = &req->header_names[i], *v = &req->header_values[i];

    s = ns_skip(s, end, ": ", k);
    s = ns_skip(s, end, "\r\n", v);

    while (v->len > 0 && v->p[v->len - 1] == ' ') {
      v->len--; /* Trim trailing spaces in header value */
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

  return s;
}

/* Parses a HTTP message.
 *
 * Return number of bytes parsed. If HTTP message is
 * incomplete, `0` is returned. On parse error, negative number is returned.
 */
int ns_parse_http(const char *s, int n, struct http_message *req) {
  const char *end, *qs;
  int len = get_request_len(s, n);

  if (len <= 0) return len;

  memset(req, 0, sizeof(*req));
  req->message.p = s;
  req->body.p = s + len;
  req->message.len = req->body.len = (size_t) ~0;
  end = s + len;

  /* Request is fully buffered. Skip leading whitespaces. */
  while (s < end && isspace(*(unsigned char *) s)) s++;

  /* Parse request line: method, URI, proto */
  s = ns_skip(s, end, " ", &req->method);
  s = ns_skip(s, end, " ", &req->uri);
  s = ns_skip(s, end, "\r\n", &req->proto);
  if (req->uri.p <= req->method.p || req->proto.p <= req->uri.p) return -1;

  /* If URI contains '?' character, initialize query_string */
  if ((qs = (char *) memchr(req->uri.p, '?', req->uri.len)) != NULL) {
    req->query_string.p = qs + 1;
    req->query_string.len = &req->uri.p[req->uri.len] - (qs + 1);
    req->uri.len = qs - req->uri.p;
  }

  s = parse_http_headers(s, end, len, req);

  /*
   * ns_parse_http() is used to parse both HTTP requests and HTTP
   * responses. If HTTP response does not have Content-Length set, then
   * body is read until socket is closed, i.e. body.len is infinite (~0).
   *
   * For HTTP requests though, according to
   * http://tools.ietf.org/html/rfc7231#section-8.1.3,
   * only POST and PUT methods have defined body semantics.
   * Therefore, if Content-Length is not specified and methods are
   * not one of PUT or POST, set body length to 0.
   *
   * So,
   * if it is HTTP request, and Content-Length is not set,
   * and method is not (PUT or POST) then reset body length to zero.
   */
  if (req->body.len == (size_t) ~0 &&
      !(req->method.len > 5 && !memcmp(req->method.p, "HTTP/", 5)) &&
      ns_vcasecmp(&req->method, "PUT") != 0 &&
      ns_vcasecmp(&req->method, "POST") != 0) {
    req->body.len = 0;
    req->message.len = len;
  }

  return len;
}

/* Returns HTTP header if it is present in the HTTP message, or `NULL`. */
struct ns_str *ns_get_http_header(struct http_message *hm, const char *name) {
  size_t i, len = strlen(name);

  for (i = 0; i < ARRAY_SIZE(hm->header_names); i++) {
    struct ns_str *h = &hm->header_names[i], *v = &hm->header_values[i];
    if (h->p != NULL && h->len == len && !ns_ncasecmp(h->p, name, len))
      return v;
  }

  return NULL;
}

static int is_ws_fragment(unsigned char flags) {
  return (flags & 0x80) == 0 || (flags & 0x0f) == 0;
}

static int is_ws_first_fragment(unsigned char flags) {
  return (flags & 0x80) == 0 && (flags & 0x0f) != 0;
}

static void handle_incoming_websocket_frame(struct ns_connection *nc,
                                            struct websocket_message *wsm) {
  if (wsm->flags & 0x8) {
    nc->handler(nc, NS_WEBSOCKET_CONTROL_FRAME, wsm);
  } else {
    nc->handler(nc, NS_WEBSOCKET_FRAME, wsm);
  }
}

static int deliver_websocket_data(struct ns_connection *nc) {
  /* Using unsigned char *, cause of integer arithmetic below */
  uint64_t i, data_len = 0, frame_len = 0, buf_len = nc->recv_iobuf.len, len,
              mask_len = 0, header_len = 0;
  unsigned char *p = (unsigned char *) nc->recv_iobuf.buf, *buf = p,
                *e = p + buf_len;
  unsigned *sizep = (unsigned *) &p[1]; /* Size ptr for defragmented frames */
  int ok, reass = buf_len > 0 && is_ws_fragment(p[0]) &&
                  !(nc->flags & NSF_WEBSOCKET_NO_DEFRAG);

  /* If that's a continuation frame that must be reassembled, handle it */
  if (reass && !is_ws_first_fragment(p[0]) && buf_len >= 1 + sizeof(*sizep) &&
      buf_len >= 1 + sizeof(*sizep) + *sizep) {
    buf += 1 + sizeof(*sizep) + *sizep;
    buf_len -= 1 + sizeof(*sizep) + *sizep;
  }

  if (buf_len >= 2) {
    len = buf[1] & 127;
    mask_len = buf[1] & 128 ? 4 : 0;
    if (len < 126 && buf_len >= mask_len) {
      data_len = len;
      header_len = 2 + mask_len;
    } else if (len == 126 && buf_len >= 4 + mask_len) {
      header_len = 4 + mask_len;
      data_len = ntohs(*(uint16_t *) &buf[2]);
    } else if (buf_len >= 10 + mask_len) {
      header_len = 10 + mask_len;
      data_len = (((uint64_t) ntohl(*(uint32_t *) &buf[2])) << 32) +
                 ntohl(*(uint32_t *) &buf[6]);
    }
  }

  frame_len = header_len + data_len;
  ok = frame_len > 0 && frame_len <= buf_len;

  if (ok) {
    struct websocket_message wsm;

    wsm.size = (size_t) data_len;
    wsm.data = buf + header_len;
    wsm.flags = buf[0];

    /* Apply mask if necessary */
    if (mask_len > 0) {
      for (i = 0; i < data_len; i++) {
        buf[i + header_len] ^= (buf + header_len - mask_len)[i % 4];
      }
    }

    if (reass) {
      /* On first fragmented frame, nullify size */
      if (is_ws_first_fragment(wsm.flags)) {
        iobuf_resize(&nc->recv_iobuf, nc->recv_iobuf.size + sizeof(*sizep));
        p[0] &= ~0x0f; /* Next frames will be treated as continuation */
        buf = p + 1 + sizeof(*sizep);
        *sizep = 0; /* TODO(lsm): fix. this can stomp over frame data */
      }

      /* Append this frame to the reassembled buffer */
      memmove(buf, wsm.data, e - wsm.data);
      (*sizep) += wsm.size;
      nc->recv_iobuf.len -= wsm.data - buf;

      /* On last fragmented frame - call user handler and remove data */
      if (wsm.flags & 0x80) {
        wsm.data = p + 1 + sizeof(*sizep);
        wsm.size = *sizep;
        handle_incoming_websocket_frame(nc, &wsm);
        iobuf_remove(&nc->recv_iobuf, 1 + sizeof(*sizep) + *sizep);
      }
    } else {
      /* TODO(lsm): properly handle OOB control frames during defragmentation */
      handle_incoming_websocket_frame(nc, &wsm);
      iobuf_remove(&nc->recv_iobuf, (size_t) frame_len); /* Cleanup frame */
    }
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
    uint16_t tmp = htons((uint16_t) len);
    header[1] = 126;
    memcpy(&header[2], &tmp, sizeof(tmp));
    header_len = 4;
  } else {
    uint32_t tmp;
    header[1] = 127;
    tmp = htonl((uint32_t)((uint64_t) len >> 32));
    memcpy(&header[2], &tmp, sizeof(tmp));
    tmp = htonl((uint32_t)(len & 0xffffffff));
    memcpy(&header[6], &tmp, sizeof(tmp));
    header_len = 10;
  }
  ns_send(nc, header, header_len);
}

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
                             size_t len) {
  ns_send_ws_header(nc, op, len);
  ns_send(nc, data, len);

  if (op == WEBSOCKET_OP_CLOSE) {
    nc->flags |= NSF_SEND_AND_CLOSE;
  }
}

/*
 * Send multiple websocket frames.
 *
 * Like `ns_send_websocket_frame()`, but composes a frame from multiple buffers.
 */
void ns_send_websocket_framev(struct ns_connection *nc, int op,
                              const struct ns_str *strv, int strvcnt) {
  int i;
  int len = 0;
  for (i = 0; i < strvcnt; i++) {
    len += strv[i].len;
  }

  ns_send_ws_header(nc, op, len);

  for (i = 0; i < strvcnt; i++) {
    ns_send(nc, strv[i].p, strv[i].len);
  }

  if (op == WEBSOCKET_OP_CLOSE) {
    nc->flags |= NSF_SEND_AND_CLOSE;
  }
}

/*
 * Send websocket frame to the remote end.
 *
 * Like `ns_send_websocket_frame()`, but allows to create formatted message
 * with `printf()`-like semantics.
 */
void ns_printf_websocket_frame(struct ns_connection *nc, int op,
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
    NS_FREE(buf);
  }
}

static void websocket_handler(struct ns_connection *nc, int ev, void *ev_data) {
  nc->handler(nc, ev, ev_data);

  switch (ev) {
    case NS_RECV:
      do {
      } while (deliver_websocket_data(nc));
      break;
    case NS_POLL:
      /* Ping idle websocket connections */
      {
        time_t now = *(time_t *) ev_data;
        if (nc->flags & NSF_IS_WEBSOCKET &&
            now > nc->last_io_time + NS_WEBSOCKET_PING_INTERVAL_SECONDS) {
          ns_send_websocket_frame(nc, WEBSOCKET_OP_PING, "", 0);
        }
      }
      break;
    default:
      break;
  }
}

static void ws_handshake(struct ns_connection *nc, const struct ns_str *key) {
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
            "Sec-WebSocket-Accept: ",
            b64_sha, "\r\n\r\n");
}

static void free_http_proto_data(struct ns_connection *nc) {
  struct proto_data_http *dp = (struct proto_data_http *) nc->proto_data;
  if (dp != NULL) {
    if (dp->fp != NULL) {
      fclose(dp->fp);
    }
    if (dp->cgi_nc != NULL) {
      dp->cgi_nc->flags |= NSF_CLOSE_IMMEDIATELY;
    }
    NS_FREE(dp);
    nc->proto_data = NULL;
  }
}

static void transfer_file_data(struct ns_connection *nc) {
  struct proto_data_http *dp = (struct proto_data_http *) nc->proto_data;
  char buf[NS_MAX_HTTP_SEND_IOBUF];
  int64_t left = dp->cl - dp->sent;
  size_t n = 0, to_read = 0;

  if (dp->type == DATA_FILE) {
    struct iobuf *io = &nc->send_iobuf;
    if (io->len < sizeof(buf)) {
      to_read = sizeof(buf) - io->len;
    }

    if (left > 0 && to_read > (size_t) left) {
      to_read = left;
    }

    if (to_read == 0) {
      /* Rate limiting. send_iobuf is too full, wait until it's drained. */
    } else if (dp->sent<dp->cl &&(n = fread(buf, 1, to_read, dp->fp))> 0) {
      ns_send(nc, buf, n);
      dp->sent += n;
    } else {
      free_http_proto_data(nc);
    }
  } else if (dp->type == DATA_PUT) {
    struct iobuf *io = &nc->recv_iobuf;
    size_t to_write =
        left <= 0 ? 0 : left < (int64_t) io->len ? (size_t) left : io->len;
    size_t n = fwrite(io->buf, 1, to_write, dp->fp);
    if (n > 0) {
      iobuf_remove(io, n);
      dp->sent += n;
    }
    if (n == 0 || dp->sent >= dp->cl) {
      free_http_proto_data(nc);
    }
  } else if (dp->type == DATA_CGI) {
    printf("%s\n", "CGI!!");
  }
}

static void http_handler(struct ns_connection *nc, int ev, void *ev_data) {
  struct iobuf *io = &nc->recv_iobuf;
  struct http_message hm;
  struct ns_str *vec;
  int req_len;

  /*
   * For HTTP messages without Content-Length, always send HTTP message
   * before NS_CLOSE message.
   */
  if (ev == NS_CLOSE && io->len > 0 &&
      ns_parse_http(io->buf, io->len, &hm) > 0) {
    hm.message.len = io->len;
    hm.body.len = io->buf + io->len - hm.body.p;
    nc->handler(nc, nc->listener ? NS_HTTP_REQUEST : NS_HTTP_REPLY, &hm);
    free_http_proto_data(nc);
  }

  if (nc->proto_data != NULL) {
    transfer_file_data(nc);
  }

  nc->handler(nc, ev, ev_data);

  if (ev == NS_RECV) {
    req_len = ns_parse_http(io->buf, io->len, &hm);
    if (req_len < 0 || (req_len == 0 && io->len >= NS_MAX_HTTP_REQUEST_SIZE)) {
      nc->flags |= NSF_CLOSE_IMMEDIATELY;
    } else if (req_len == 0) {
      /* Do nothing, request is not yet fully buffered */
    } else if (nc->listener == NULL &&
               ns_get_http_header(&hm, "Sec-WebSocket-Accept")) {
      /* We're websocket client, got handshake response from server. */
      /* TODO(lsm): check the validity of accept Sec-WebSocket-Accept */
      iobuf_remove(io, req_len);
      nc->proto_handler = websocket_handler;
      nc->flags |= NSF_IS_WEBSOCKET;
      nc->handler(nc, NS_WEBSOCKET_HANDSHAKE_DONE, NULL);
      websocket_handler(nc, NS_RECV, ev_data);
    } else if (nc->listener != NULL &&
               (vec = ns_get_http_header(&hm, "Sec-WebSocket-Key")) != NULL) {
      /* This is a websocket request. Switch protocol handlers. */
      iobuf_remove(io, req_len);
      nc->proto_handler = websocket_handler;
      nc->flags |= NSF_IS_WEBSOCKET;

      /* Send handshake */
      nc->handler(nc, NS_WEBSOCKET_HANDSHAKE_REQUEST, &hm);
      if (!(nc->flags & NSF_CLOSE_IMMEDIATELY)) {
        if (nc->send_iobuf.len == 0) {
          ws_handshake(nc, vec);
        }
        nc->handler(nc, NS_WEBSOCKET_HANDSHAKE_DONE, NULL);
        websocket_handler(nc, NS_RECV, ev_data);
      }
    } else if (hm.message.len <= io->len) {
      /* Whole HTTP message is fully buffered, call event handler */
      nc->handler(nc, nc->listener ? NS_HTTP_REQUEST : NS_HTTP_REPLY, &hm);
      iobuf_remove(io, hm.message.len);
    }
  }
}

/*
 * Attach built-in HTTP event handler to the given connection.
 * User-defined event handler will receive following extra events:
 *
 * - NS_HTTP_REQUEST: HTTP request has arrived. Parsed HTTP request is passed as
 *   `struct http_message` through the handler's `void *ev_data` pointer.
 * - NS_HTTP_REPLY: HTTP reply has arrived. Parsed HTTP reply is passed as
 *   `struct http_message` through the handler's `void *ev_data` pointer.
 * - NS_WEBSOCKET_HANDSHAKE_REQUEST: server has received websocket handshake
 *   request. `ev_data` contains parsed HTTP request.
 * - NS_WEBSOCKET_HANDSHAKE_DONE: server has completed Websocket handshake.
 *   `ev_data` is `NULL`.
 * - NS_WEBSOCKET_FRAME: new websocket frame has arrived. `ev_data` is
 *   `struct websocket_message *`
 */
void ns_set_protocol_http_websocket(struct ns_connection *nc) {
  nc->proto_handler = http_handler;
}

/*
 * Sends websocket handshake to the server.
 *
 * `nc` must be a valid connection, connected to a server `uri` is an URI
 * to fetch, extra_headers` is extra HTTP headers to send or `NULL`.
 *
 * This function is intended to be used by websocket client.
 */
void ns_send_websocket_handshake(struct ns_connection *nc, const char *uri,
                                 const char *extra_headers) {
  unsigned long random = (unsigned long) uri;
  char key[sizeof(random) * 3];

  ns_base64_encode((unsigned char *) &random, sizeof(random), key);
  ns_printf(nc,
            "GET %s HTTP/1.1\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "Sec-WebSocket-Key: %s\r\n"
            "%s\r\n",
            uri, key, extra_headers == NULL ? "" : extra_headers);
}

#ifndef NS_DISABLE_FILESYSTEM
static void send_http_error(struct ns_connection *nc, int code,
                            const char *reason) {
  if (reason == NULL) {
    reason = "";
  }
  ns_printf(nc, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n", code, reason);
}

/* Suffix must be smaller then string */
static int has_suffix(const char *str, const char *suffix) {
  return str != NULL && suffix != NULL && strlen(suffix) < strlen(str) &&
         strcmp(str + strlen(str) - strlen(suffix), suffix) == 0;
}

#ifndef NS_DISABLE_SSI
static void send_ssi_file(struct ns_connection *, const char *, FILE *, int,
                          const struct ns_serve_http_opts *);

static void send_file_data(struct ns_connection *nc, FILE *fp) {
  char buf[BUFSIZ];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
    ns_send(nc, buf, n);
  }
}

static void do_ssi_include(struct ns_connection *nc, const char *ssi, char *tag,
                           int include_level,
                           const struct ns_serve_http_opts *opts) {
  char file_name[BUFSIZ], path[MAX_PATH_SIZE], *p;
  FILE *fp;

  /*
   * sscanf() is safe here, since send_ssi_file() also uses buffer
   * of size MG_BUF_LEN to get the tag. So strlen(tag) is always < MG_BUF_LEN.
   */
  if (sscanf(tag, " virtual=\"%[^\"]\"", file_name) == 1) {
    /* File name is relative to the webserver root */
    snprintf(path, sizeof(path), "%s/%s", opts->document_root, file_name);
  } else if (sscanf(tag, " abspath=\"%[^\"]\"", file_name) == 1) {
    /*
     * File name is relative to the webserver working directory
     * or it is absolute system path
     */
    snprintf(path, sizeof(path), "%s", file_name);
  } else if (sscanf(tag, " file=\"%[^\"]\"", file_name) == 1 ||
             sscanf(tag, " \"%[^\"]\"", file_name) == 1) {
    /* File name is relative to the currect document */
    snprintf(path, sizeof(path), "%s", ssi);
    if ((p = strrchr(path, '/')) != NULL) {
      p[1] = '\0';
    }
    snprintf(path + strlen(path), sizeof(path) - strlen(path), "%s", file_name);
  } else {
    ns_printf(nc, "Bad SSI #include: [%s]", tag);
    return;
  }

  if ((fp = fopen(path, "rb")) == NULL) {
    ns_printf(nc, "SSI include error: fopen(%s): %s", path, strerror(errno));
  } else {
    ns_set_close_on_exec(fileno(fp));
    if (has_suffix(path, opts->ssi_suffix)) {
      send_ssi_file(nc, path, fp, include_level + 1, opts);
    } else {
      send_file_data(nc, fp);
    }
    fclose(fp);
  }
}

#ifndef NS_DISABLE_POPEN
static void do_ssi_exec(struct ns_connection *nc, char *tag) {
  char cmd[BUFSIZ];
  FILE *fp;

  if (sscanf(tag, " \"%[^\"]\"", cmd) != 1) {
    ns_printf(nc, "Bad SSI #exec: [%s]", tag);
  } else if ((fp = popen(cmd, "r")) == NULL) {
    ns_printf(nc, "Cannot SSI #exec: [%s]: %s", cmd, strerror(errno));
  } else {
    send_file_data(nc, fp);
    pclose(fp);
  }
}
#endif /* !NS_DISABLE_POPEN */

static void send_ssi_file(struct ns_connection *nc, const char *path, FILE *fp,
                          int include_level,
                          const struct ns_serve_http_opts *opts) {
  char buf[BUFSIZ];
  int ch, offset, len, in_ssi_tag;

  if (include_level > 10) {
    ns_printf(nc, "SSI #include level is too deep (%s)", path);
    return;
  }

  in_ssi_tag = len = offset = 0;
  while ((ch = fgetc(fp)) != EOF) {
    if (in_ssi_tag && ch == '>') {
      in_ssi_tag = 0;
      buf[len++] = (char) ch;
      buf[len] = '\0';
      assert(len <= (int) sizeof(buf));
      if (len < 6 || memcmp(buf, "<!--#", 5) != 0) {
        /* Not an SSI tag, pass it */
        (void) ns_send(nc, buf, (size_t) len);
      } else {
        if (!memcmp(buf + 5, "include", 7)) {
          do_ssi_include(nc, path, buf + 12, include_level, opts);
#ifndef NS_DISABLE_POPEN
        } else if (!memcmp(buf + 5, "exec", 4)) {
          do_ssi_exec(nc, buf + 9);
#endif /* !NO_POPEN */
        } else {
          /* Silently ignoring unknown SSI commands. */
        }
      }
      len = 0;
    } else if (in_ssi_tag) {
      if (len == 5 && memcmp(buf, "<!--#", 5) != 0) {
        /* Not an SSI tag */
        in_ssi_tag = 0;
      } else if (len == (int) sizeof(buf) - 2) {
        ns_printf(nc, "%s: SSI tag is too large", path);
        len = 0;
      }
      buf[len++] = ch & 0xff;
    } else if (ch == '<') {
      in_ssi_tag = 1;
      if (len > 0) {
        ns_send(nc, buf, (size_t) len);
      }
      len = 0;
      buf[len++] = ch & 0xff;
    } else {
      buf[len++] = ch & 0xff;
      if (len == (int) sizeof(buf)) {
        ns_send(nc, buf, (size_t) len);
        len = 0;
      }
    }
  }

  /* Send the rest of buffered data */
  if (len > 0) {
    ns_send(nc, buf, (size_t) len);
  }
}

static void handle_ssi_request(struct ns_connection *nc, const char *path,
                               const struct ns_serve_http_opts *opts) {
  FILE *fp;

  if ((fp = fopen(path, "rb")) == NULL) {
    send_http_error(nc, 404, "Not Found");
  } else {
    ns_set_close_on_exec(fileno(fp));
    ns_printf(nc,
              "HTTP/1.1 200 OK\r\n"
              "Content-Type: %s\r\n"
              "Connection: close\r\n\r\n",
              get_mime_type(path, "text/plain"));
    send_ssi_file(nc, path, fp, 0, opts);
    fclose(fp);
    nc->flags |= NSF_SEND_AND_CLOSE;
  }
}
#else
static void handle_ssi_request(struct ns_connection *nc, const char *path,
                               const struct ns_serve_http_opts *opts) {
  (void) path;
  (void) opts;
  send_http_error(nc, 500, "SSI disabled");
}
#endif /* NS_DISABLE_SSI */

static void construct_etag(char *buf, size_t buf_len, const ns_stat_t *st) {
  snprintf(buf, buf_len, "\"%lx.%" INT64_FMT "\"", (unsigned long) st->st_mtime,
           (int64_t) st->st_size);
}
static void gmt_time_string(char *buf, size_t buf_len, time_t *t) {
  strftime(buf, buf_len, "%a, %d %b %Y %H:%M:%S GMT", gmtime(t));
}

static int parse_range_header(const char *header, int64_t *a, int64_t *b) {
  return sscanf(header, "bytes=%" INT64_FMT "-%" INT64_FMT, a, b);
}

static void ns_send_http_file2(struct ns_connection *nc, const char *path,
                               ns_stat_t *st, struct http_message *hm,
                               struct ns_serve_http_opts *opts) {
  struct proto_data_http *dp;

  free_http_proto_data(nc);
  if ((dp = (struct proto_data_http *) NS_CALLOC(1, sizeof(*dp))) == NULL) {
    send_http_error(nc, 500, "Server Error"); /* LCOV_EXCL_LINE */
  } else if ((dp->fp = fopen(path, "rb")) == NULL) {
    NS_FREE(dp);
    nc->proto_data = NULL;
    send_http_error(nc, 500, "Server Error");
  } else if (has_suffix(path, opts->ssi_suffix)) {
    handle_ssi_request(nc, path, opts);
  } else {
    char etag[50], current_time[50], last_modified[50], range[50];
    time_t t = time(NULL);
    int64_t r1 = 0, r2 = 0, cl = st->st_size;
    struct ns_str *range_hdr = ns_get_http_header(hm, "Range");
    int n, status_code = 200;
    const char *status_message = "OK";

    /* Handle Range header */
    range[0] = '\0';
    if (range_hdr != NULL &&
        (n = parse_range_header(range_hdr->p, &r1, &r2)) > 0 && r1 >= 0 &&
        r2 >= 0) {
      /* If range is specified like "400-", set second limit to content len */
      if (n == 1) {
        r2 = cl - 1;
      }
      if (r1 > r2 || r2 >= cl) {
        status_code = 416;
        status_message = "Requested range not satisfiable";
        cl = 0;
        snprintf(range, sizeof(range),
                 "Content-Range: bytes */%" INT64_FMT "\r\n",
                 (int64_t) st->st_size);
      } else {
        status_code = 206;
        status_message = "Partial Content";
        cl = r2 - r1 + 1;
        snprintf(range, sizeof(range), "Content-Range: bytes %" INT64_FMT
                                       "-%" INT64_FMT "/%" INT64_FMT "\r\n",
                 r1, r1 + cl - 1, (int64_t) st->st_size);
        fseeko(dp->fp, r1, SEEK_SET);
      }
    }

    construct_etag(etag, sizeof(etag), st);
    gmt_time_string(current_time, sizeof(current_time), &t);
    gmt_time_string(last_modified, sizeof(last_modified), &st->st_mtime);
    ns_printf(nc,
              "HTTP/1.1 %d %s\r\n"
              "Date: %s\r\n"
              "Last-Modified: %s\r\n"
              "Accept-Ranges: bytes\r\n"
              "Content-Type: %s\r\n"
              "Content-Length: %" INT64_FMT
              "\r\n"
              "%s"
              "Etag: %s\r\n"
              "\r\n",
              status_code, status_message, current_time, last_modified,
              get_mime_type(path, "text/plain"), cl, range, etag);
    nc->proto_data = (void *) dp;
    dp->cl = cl;
    transfer_file_data(nc);
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

#endif

static int ns_url_decode(const char *src, int src_len, char *dst, int dst_len,
                         int is_form_url_encoded) {
  int i, j, a, b;
#define HEXTOI(x) (isdigit(x) ? x - '0' : x - 'W')

  for (i = j = 0; i < src_len && j < dst_len - 1; i++, j++) {
    if (src[i] == '%') {
      if (i < src_len - 2 && isxdigit(*(const unsigned char *) (src + i + 1)) &&
          isxdigit(*(const unsigned char *) (src + i + 2))) {
        a = tolower(*(const unsigned char *) (src + i + 1));
        b = tolower(*(const unsigned char *) (src + i + 2));
        dst[j] = (char) ((HEXTOI(a) << 4) | HEXTOI(b));
        i += 2;
      } else {
        return -1;
      }
    } else if (is_form_url_encoded && src[i] == '+') {
      dst[j] = ' ';
    } else {
      dst[j] = src[i];
    }
  }

  dst[j] = '\0'; /* Null-terminate the destination */

  return i >= src_len ? j : -1;
}

/*
 * Fetch an HTTP form variable.
 *
 * Fetch a variable `name` from a `buf` into a buffer specified by
 * `dst`, `dst_len`. Destination is always zero-terminated. Return length
 * of a fetched variable. If not found, 0 is returned. `buf` must be
 * valid url-encoded buffer. If destination is too small, `-1` is returned.
 */
int ns_get_http_var(const struct ns_str *buf, const char *name, char *dst,
                    size_t dst_len) {
  const char *p, *e, *s;
  size_t name_len;
  int len;

  if (dst == NULL || dst_len == 0) {
    len = -2;
  } else if (buf->p == NULL || name == NULL || buf->len == 0) {
    len = -1;
    dst[0] = '\0';
  } else {
    name_len = strlen(name);
    e = buf->p + buf->len;
    len = -1;
    dst[0] = '\0';

    for (p = buf->p; p + name_len < e; p++) {
      if ((p == buf->p || p[-1] == '&') && p[name_len] == '=' &&
          !ns_ncasecmp(name, p, name_len)) {
        p += name_len + 1;
        s = (const char *) memchr(p, '&', (size_t)(e - p));
        if (s == NULL) {
          s = e;
        }
        len = ns_url_decode(p, (size_t)(s - p), dst, dst_len, 1);
        if (len == -1) {
          len = -2;
        }
        break;
      }
    }
  }

  return len;
}

/*
 * Send buffer `buf` of size `len` to the client using chunked HTTP encoding.
 * This function first sends buffer size as hex number + newline, then
 * buffer itself, then newline. For example,
 *   `ns_send_http_chunk(nc, "foo", 3)` whill append `3\r\nfoo\r\n` string to
 * the `nc->send_iobuf` output IO buffer.
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
void ns_send_http_chunk(struct ns_connection *nc, const char *buf, size_t len) {
  char chunk_size[50];
  int n;

  n = snprintf(chunk_size, sizeof(chunk_size), "%lX\r\n", (unsigned long) len);
  ns_send(nc, chunk_size, n);
  ns_send(nc, buf, len);
  ns_send(nc, "\r\n", 2);
}

/*
 * Send printf-formatted HTTP chunk.
 * Functionality is similar to `ns_send_http_chunk()`.
 */
void ns_printf_http_chunk(struct ns_connection *nc, const char *fmt, ...) {
  char mem[500], *buf = mem;
  int len;
  va_list ap;

  va_start(ap, fmt);
  len = ns_avprintf(&buf, sizeof(mem), fmt, ap);
  va_end(ap);

  if (len >= 0) {
    ns_send_http_chunk(nc, buf, len);
  }

  /* LCOV_EXCL_START */
  if (buf != mem && buf != NULL) {
    NS_FREE(buf);
  }
  /* LCOV_EXCL_STOP */
}

int ns_http_parse_header(struct ns_str *hdr, const char *var_name, char *buf,
                         size_t buf_size) {
  int ch = ' ', ch1 = ',', len = 0, n = strlen(var_name);
  const char *p, *end = hdr->p + hdr->len, *s = NULL;

  if (buf != NULL && buf_size > 0) buf[0] = '\0';

  /* Find where variable starts */
  for (s = hdr->p; s != NULL && s + n < end; s++) {
    if ((s == hdr->p || s[-1] == ch || s[-1] == ch1) && s[n] == '=' &&
        !memcmp(s, var_name, n))
      break;
  }

  if (s != NULL && &s[n + 1] < end) {
    s += n + 1;
    if (*s == '"' || *s == '\'') {
      ch = ch1 = *s++;
    }
    p = s;
    while (p < end && p[0] != ch && p[0] != ch1 && len < (int) buf_size) {
      if (ch != ' ' && p[0] == '\\' && p[1] == ch) p++;
      buf[len++] = *p++;
    }
    if (len >= (int) buf_size || (ch != ' ' && *p != ch)) {
      len = 0;
    } else {
      if (len > 0 && s[len - 1] == ',') len--;
      if (len > 0 && s[len - 1] == ';') len--;
      buf[len] = '\0';
    }
  }

  return len;
}

#ifndef NS_DISABLE_FILESYSTEM
static int is_file_hidden(const char *path,
                          const struct ns_serve_http_opts *opts) {
  const char *p1 = opts->per_directory_auth_file;
  const char *p2 = opts->hidden_file_pattern;
  return !strcmp(path, ".") || !strcmp(path, "..") ||
         (p1 != NULL && !strcmp(path, p1)) ||
         (p2 != NULL && ns_match_prefix(p2, strlen(p2), path) > 0);
}

#ifndef NS_DISABLE_HTTP_DIGEST_AUTH
static FILE *open_auth_file(const char *path, int is_directory,
                            const struct ns_serve_http_opts *opts) {
  char buf[MAX_PATH_SIZE];
  const char *p;
  FILE *fp = NULL;

  if (opts->global_auth_file != NULL) {
    fp = fopen(opts->global_auth_file, "r");
  } else if (is_directory && opts->per_directory_auth_file) {
    snprintf(buf, sizeof(buf), "%s%c%s", path, DIRSEP,
             opts->per_directory_auth_file);
    fp = fopen(buf, "r");
  } else if (opts->per_directory_auth_file) {
    if ((p = strrchr(path, '/')) == NULL && (p = strrchr(path, '\\')) == NULL) {
      p = path;
    }
    snprintf(buf, sizeof(buf), "%.*s/%s", (int) (p - path), path,
             opts->per_directory_auth_file);
    fp = fopen(buf, "r");
  }

  return fp;
}

/*
 * Stringify binary data. Output buffer size must be 2 * size_of_input + 1
 * because each byte of input takes 2 bytes in string representation
 * plus 1 byte for the terminating \0 character.
 */
static void bin2str(char *to, const unsigned char *p, size_t len) {
  static const char *hex = "0123456789abcdef";

  for (; len--; p++) {
    *to++ = hex[p[0] >> 4];
    *to++ = hex[p[0] & 0x0f];
  }
  *to = '\0';
}

static char *ns_md5(char *buf, ...) {
  unsigned char hash[16];
  const unsigned char *p;
  va_list ap;
  MD5_CTX ctx;

  MD5_Init(&ctx);

  va_start(ap, buf);
  while ((p = va_arg(ap, const unsigned char *) ) != NULL) {
    size_t len = va_arg(ap, size_t);
    MD5_Update(&ctx, p, len);
  }
  va_end(ap);

  MD5_Final(hash, &ctx);
  bin2str(buf, hash, sizeof(hash));

  return buf;
}

static void mkmd5resp(const char *method, size_t method_len, const char *uri,
                      size_t uri_len, const char *ha1, size_t ha1_len,
                      const char *nonce, size_t nonce_len, const char *nc,
                      size_t nc_len, const char *cnonce, size_t cnonce_len,
                      const char *qop, size_t qop_len, char *resp) {
  static const char colon[] = ":";
  static const size_t one = 1;
  char ha2[33];

  ns_md5(ha2, method, method_len, colon, one, uri, uri_len, NULL);
  ns_md5(resp, ha1, ha1_len, colon, one, nonce, nonce_len, colon, one, nc,
         nc_len, colon, one, cnonce, cnonce_len, colon, one, qop, qop_len,
         colon, one, ha2, sizeof(ha2) - 1, NULL);
}

/*
 * Create Digest authentication header for client request.
 */
int ns_http_create_digest_auth_header(char *buf, size_t buf_len,
                                      const char *method, const char *uri,
                                      const char *auth_domain, const char *user,
                                      const char *passwd) {
  static const char colon[] = ":", qop[] = "auth";
  static const size_t one = 1;
  char ha1[33], resp[33], cnonce[40];

  snprintf(cnonce, sizeof(cnonce), "%x", (unsigned int) time(NULL));
  ns_md5(ha1, user, (size_t) strlen(user), colon, one, auth_domain,
         (size_t) strlen(auth_domain), colon, one, passwd,
         (size_t) strlen(passwd), NULL);
  mkmd5resp(method, strlen(method), uri, strlen(uri), ha1, sizeof(ha1) - 1,
            cnonce, strlen(cnonce), "1", one, cnonce, strlen(cnonce), qop,
            sizeof(qop) - 1, resp);
  return snprintf(buf, buf_len,
                  "Authorization: Digest username=\"%s\","
                  "realm=\"%s\",uri=\"%s\",qop=%s,nc=1,cnonce=%s,"
                  "nonce=%s,response=%s\r\n",
                  user, auth_domain, uri, qop, cnonce, cnonce, resp);
}

/*
 * Check for authentication timeout.
 * Clients send time stamp encoded in nonce. Make sure it is not too old,
 * to prevent replay attacks.
 * Assumption: nonce is a hexadecimal number of seconds since 1970.
 */
static int check_nonce(const char *nonce) {
  unsigned long now = (unsigned long) time(NULL);
  unsigned long val = (unsigned long) strtoul(nonce, NULL, 16);
  return 1 || now < val || now - val < 3600;
}

/*
 * Authenticate HTTP request against opened passwords file.
 * Returns 1 if authenticated, 0 otherwise.
 */
static int ns_http_check_digest_auth(struct http_message *hm,
                                     const char *auth_domain, FILE *fp) {
  struct ns_str *hdr;
  char buf[128], f_user[sizeof(buf)], f_ha1[sizeof(buf)], f_domain[sizeof(buf)];
  char user[50], cnonce[20], response[40], uri[200], qop[20], nc[20], nonce[30];
  char expected_response[33];

  /* Parse "Authorization:" header, fail fast on parse error */
  if (hm == NULL || fp == NULL ||
      (hdr = ns_get_http_header(hm, "Authorization")) == NULL ||
      ns_http_parse_header(hdr, "username", user, sizeof(user)) == 0 ||
      ns_http_parse_header(hdr, "cnonce", cnonce, sizeof(cnonce)) == 0 ||
      ns_http_parse_header(hdr, "response", response, sizeof(response)) == 0 ||
      ns_http_parse_header(hdr, "uri", uri, sizeof(uri)) == 0 ||
      ns_http_parse_header(hdr, "qop", qop, sizeof(qop)) == 0 ||
      ns_http_parse_header(hdr, "nc", nc, sizeof(nc)) == 0 ||
      ns_http_parse_header(hdr, "nonce", nonce, sizeof(nonce)) == 0 ||
      check_nonce(nonce) == 0) {
    return 0;
  }

  /*
   * Read passwords file line by line. If should have htdigest format,
   * i.e. each line should be a colon-separated sequence:
   * USER_NAME:DOMAIN_NAME:HA1_HASH_OF_USER_DOMAIN_AND_PASSWORD
   */
  while (fgets(buf, sizeof(buf), fp) != NULL) {
    if (sscanf(buf, "%[^:]:%[^:]:%s", f_user, f_domain, f_ha1) == 3 &&
        strcmp(user, f_user) == 0 &&
        /* NOTE(lsm): due to a bug in MSIE, we do not compare URIs */
        strcmp(auth_domain, f_domain) == 0) {
      /* User and domain matched, check the password */
      mkmd5resp(hm->method.p, hm->method.len, hm->uri.p, hm->uri.len, f_ha1,
                strlen(f_ha1), nonce, strlen(nonce), nc, strlen(nc), cnonce,
                strlen(cnonce), qop, strlen(qop), expected_response);
      return ns_casecmp(response, expected_response) == 0;
    }
  }

  /* None of the entries in the passwords file matched - return failure */
  return 0;
}

static int is_authorized(struct http_message *hm, const char *path,
                         int is_directory, struct ns_serve_http_opts *opts) {
  FILE *fp;
  int authorized = 1;

  if (opts->auth_domain != NULL && (opts->per_directory_auth_file != NULL ||
                                    opts->global_auth_file != NULL) &&
      (fp = open_auth_file(path, is_directory, opts)) != NULL) {
    authorized = ns_http_check_digest_auth(hm, opts->auth_domain, fp);
    fclose(fp);
  }

  return authorized;
}
#else
static int is_authorized(struct http_message *hm, const char *path,
                         int is_directory, struct ns_serve_http_opts *opts) {
  (void) hm;
  (void) path;
  (void) is_directory;
  (void) opts;
  return 1;
}
#endif

#ifndef NS_DISABLE_DIRECTORY_LISTING
/* Implementation of POSIX opendir/closedir/readdir for Windows. */
#ifdef _WIN32
struct dirent {
  char d_name[MAX_PATH_SIZE];
};

typedef struct DIR {
  HANDLE handle;
  WIN32_FIND_DATAW info;
  struct dirent result;
} DIR;

static DIR *opendir(const char *name) {
  DIR *dir = NULL;
  wchar_t wpath[MAX_PATH_SIZE];
  DWORD attrs;

  if (name == NULL) {
    SetLastError(ERROR_BAD_ARGUMENTS);
  } else if ((dir = (DIR *) NS_MALLOC(sizeof(*dir))) == NULL) {
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
  } else {
    to_wchar(name, wpath, ARRAY_SIZE(wpath));
    attrs = GetFileAttributesW(wpath);
    if (attrs != 0xFFFFFFFF && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
      (void) wcscat(wpath, L"\\*");
      dir->handle = FindFirstFileW(wpath, &dir->info);
      dir->result.d_name[0] = '\0';
    } else {
      NS_FREE(dir);
      dir = NULL;
    }
  }

  return dir;
}

static int closedir(DIR *dir) {
  int result = 0;

  if (dir != NULL) {
    if (dir->handle != INVALID_HANDLE_VALUE)
      result = FindClose(dir->handle) ? 0 : -1;

    NS_FREE(dir);
  } else {
    result = -1;
    SetLastError(ERROR_BAD_ARGUMENTS);
  }

  return result;
}

static struct dirent *readdir(DIR *dir) {
  struct dirent *result = 0;

  if (dir) {
    if (dir->handle != INVALID_HANDLE_VALUE) {
      result = &dir->result;
      (void) WideCharToMultiByte(CP_UTF8, 0, dir->info.cFileName, -1,
                                 result->d_name, sizeof(result->d_name), NULL,
                                 NULL);

      if (!FindNextFileW(dir->handle, &dir->info)) {
        (void) FindClose(dir->handle);
        dir->handle = INVALID_HANDLE_VALUE;
      }

    } else {
      SetLastError(ERROR_FILE_NOT_FOUND);
    }
  } else {
    SetLastError(ERROR_BAD_ARGUMENTS);
  }

  return result;
}
#endif /* _WIN32  POSIX opendir/closedir/readdir implementation */

static size_t ns_url_encode(const char *src, size_t s_len, char *dst,
                            size_t dst_len) {
  static const char *dont_escape = "._-$,;~()";
  static const char *hex = "0123456789abcdef";
  size_t i = 0, j = 0;

  for (i = j = 0; dst_len > 0 && i < s_len && j + 2 < dst_len - 1; i++, j++) {
    if (isalnum(*(const unsigned char *) (src + i)) ||
        strchr(dont_escape, *(const unsigned char *) (src + i)) != NULL) {
      dst[j] = src[i];
    } else if (j + 3 < dst_len) {
      dst[j] = '%';
      dst[j + 1] = hex[(*(const unsigned char *) (src + i)) >> 4];
      dst[j + 2] = hex[(*(const unsigned char *) (src + i)) & 0xf];
      j += 2;
    }
  }

  dst[j] = '\0';
  return j;
}

static void escape(const char *src, char *dst, size_t dst_len) {
  size_t n = 0;
  while (*src != '\0' && n + 5 < dst_len) {
    unsigned char ch = *(unsigned char *) src++;
    if (ch == '<') {
      n += snprintf(dst + n, dst_len - n, "%s", "&lt;");
    } else {
      dst[n++] = ch;
    }
  }
  dst[n] = '\0';
}

static void print_dir_entry(struct ns_connection *nc, const char *file_name,
                            ns_stat_t *stp) {
  char size[64], mod[64], href[MAX_PATH_SIZE * 3], path[MAX_PATH_SIZE];
  int64_t fsize = stp->st_size;
  int is_dir = S_ISDIR(stp->st_mode);
  const char *slash = is_dir ? "/" : "";

  if (is_dir) {
    snprintf(size, sizeof(size), "%s", "[DIRECTORY]");
  } else {
    /*
     * We use (double) cast below because MSVC 6 compiler cannot
     * convert unsigned __int64 to double.
     */
    if (fsize < 1024) {
      snprintf(size, sizeof(size), "%d", (int) fsize);
    } else if (fsize < 0x100000) {
      snprintf(size, sizeof(size), "%.1fk", (double) fsize / 1024.0);
    } else if (fsize < 0x40000000) {
      snprintf(size, sizeof(size), "%.1fM", (double) fsize / 1048576);
    } else {
      snprintf(size, sizeof(size), "%.1fG", (double) fsize / 1073741824);
    }
  }
  strftime(mod, sizeof(mod), "%d-%b-%Y %H:%M", localtime(&stp->st_mtime));
  escape(file_name, path, sizeof(path));
  ns_url_encode(file_name, strlen(file_name), href, sizeof(href));
  ns_printf_http_chunk(nc,
                       "<tr><td><a href=\"%s%s\">%s%s</a></td>"
                       "<td>%s</td><td name=%" INT64_FMT ">%s</td></tr>\n",
                       href, slash, path, slash, mod, is_dir ? -1 : fsize,
                       size);
}

static void scan_directory(struct ns_connection *nc, const char *dir,
                           const struct ns_serve_http_opts *opts,
                           void (*func)(struct ns_connection *, const char *,
                                        ns_stat_t *)) {
  char path[MAX_PATH_SIZE];
  ns_stat_t st;
  struct dirent *dp;
  DIR *dirp;

  if ((dirp = (opendir(dir))) != NULL) {
    while ((dp = readdir(dirp)) != NULL) {
      /* Do not show current dir and hidden files */
      if (is_file_hidden(dp->d_name, opts)) {
        continue;
      }
      snprintf(path, sizeof(path), "%s/%s", dir, dp->d_name);
      if (ns_stat(path, &st) == 0) {
        func(nc, dp->d_name, &st);
      }
    }
    closedir(dirp);
  }
}

static void send_directory_listing(struct ns_connection *nc, const char *dir,
                                   struct http_message *hm,
                                   struct ns_serve_http_opts *opts) {
  static const char *sort_js_code =
      "<script>function srt(tb, col) {"
      "var tr = Array.prototype.slice.call(tb.rows, 0),"
      "tr = tr.sort(function (a, b) { var c1 = a.cells[col], c2 = b.cells[col],"
      "n1 = c1.getAttribute('name'), n2 = c2.getAttribute('name'), "
      "t1 = a.cells[2].getAttribute('name'), "
      "t2 = b.cells[2].getAttribute('name'); "
      "return t1 < 0 && t2 >= 0 ? -1 : t2 < 0 && t1 >= 0 ? 1 : "
      "n1 ? parseInt(n2) - parseInt(n1) : "
      "c1.textContent.trim().localeCompare(c2.textContent.trim()); });";
  static const char *sort_js_code2 =
      "for (var i = 0; i < tr.length; i++) tb.appendChild(tr[i]);}"
      "window.onload = function() { "
      "var tb = document.getElementById('tb');"
      "document.onclick = function(ev){ "
      "var c = ev.target.rel; if (c) srt(tb, c)}; srt(tb, 2); };</script>";

  ns_printf(nc, "%s\r\n%s: %s\r\n%s: %s\r\n\r\n", "HTTP/1.1 200 OK",
            "Transfer-Encoding", "chunked", "Content-Type",
            "text/html; charset=utf-8");

  ns_printf_http_chunk(
      nc,
      "<html><head><title>Index of %.*s</title>%s%s"
      "<style>th,td {text-align: left; padding-right: 1em; }</style></head>"
      "<body><h1>Index of %.*s</h1><pre><table cellpadding=\"0\"><thead>"
      "<tr><th><a href=# rel=0>Name</a></th><th>"
      "<a href=# rel=1>Modified</a</th>"
      "<th><a href=# rel=2>Size</a></th></tr>"
      "<tr><td colspan=\"3\"><hr></td></tr></thead><tbody id=tb>",
      (int) hm->uri.len, hm->uri.p, sort_js_code, sort_js_code2,
      (int) hm->uri.len, hm->uri.p);
  scan_directory(nc, dir, opts, print_dir_entry);
  ns_printf_http_chunk(nc, "%s", "</tbody></body></html>");
  ns_send_http_chunk(nc, "", 0);
}
#endif /* NS_DISABLE_DIRECTORY_LISTING */

#ifndef NS_DISABLE_DAV
static void print_props(struct ns_connection *nc, const char *name,
                        ns_stat_t *stp) {
  char mtime[64], buf[MAX_PATH_SIZE * 3];
  time_t t = stp->st_mtime; /* store in local variable for NDK compile */
  gmt_time_string(mtime, sizeof(mtime), &t);
  ns_url_encode(name, strlen(name), buf, sizeof(buf));
  ns_printf(nc,
            "<d:response>"
            "<d:href>%s</d:href>"
            "<d:propstat>"
            "<d:prop>"
            "<d:resourcetype>%s</d:resourcetype>"
            "<d:getcontentlength>%" INT64_FMT
            "</d:getcontentlength>"
            "<d:getlastmodified>%s</d:getlastmodified>"
            "</d:prop>"
            "<d:status>HTTP/1.1 200 OK</d:status>"
            "</d:propstat>"
            "</d:response>\n",
            buf, S_ISDIR(stp->st_mode) ? "<d:collection/>" : "",
            (int64_t) stp->st_size, mtime);
}

static void handle_propfind(struct ns_connection *nc, const char *path,
                            ns_stat_t *stp, struct http_message *hm,
                            struct ns_serve_http_opts *opts) {
  static const char header[] =
      "HTTP/1.1 207 Multi-Status\r\n"
      "Connection: close\r\n"
      "Content-Type: text/xml; charset=utf-8\r\n\r\n"
      "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
      "<d:multistatus xmlns:d='DAV:'>\n";
  static const char footer[] = "</d:multistatus>\n";
  const struct ns_str *depth = ns_get_http_header(hm, "Depth");

  /* Print properties for the requested resource itself */
  if (S_ISDIR(stp->st_mode) &&
      strcmp(opts->enable_directory_listing, "yes") != 0) {
    ns_printf(nc, "%s", "HTTP/1.1 403 Directory Listing Denied\r\n\r\n");
  } else {
    char uri[MAX_PATH_SIZE];
    ns_send(nc, header, sizeof(header) - 1);
    snprintf(uri, sizeof(uri), "%.*s", (int) hm->uri.len, hm->uri.p);
    print_props(nc, uri, stp);
    if (S_ISDIR(stp->st_mode) && (depth == NULL || ns_vcmp(depth, "0") != 0)) {
      scan_directory(nc, path, opts, print_props);
    }
    ns_send(nc, footer, sizeof(footer) - 1);
    nc->flags |= NSF_SEND_AND_CLOSE;
  }
}

static void handle_mkcol(struct ns_connection *nc, const char *path,
                         struct http_message *hm) {
  int status_code = 500;
  if (ns_get_http_header(hm, "Content-Length") != NULL) {
    status_code = 415;
  } else if (!mkdir(path, 0755)) {
    status_code = 201;
  } else if (errno == EEXIST) {
    status_code = 405;
  } else if (errno == EACCES) {
    status_code = 403;
  } else if (errno == ENOENT) {
    status_code = 409;
  }
  send_http_error(nc, status_code, NULL);
}

static int remove_directory(const char *dir) {
  char path[MAX_PATH_SIZE];
  struct dirent *dp;
  ns_stat_t st;
  DIR *dirp;

  if ((dirp = opendir(dir)) == NULL) return 0;

  while ((dp = readdir(dirp)) != NULL) {
    if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, "..")) continue;
    snprintf(path, sizeof(path), "%s%c%s", dir, '/', dp->d_name);
    ns_stat(path, &st);
    if (S_ISDIR(st.st_mode)) {
      remove_directory(path);
    } else {
      remove(path);
    }
  }
  closedir(dirp);
  rmdir(dir);

  return 1;
}

static void handle_delete(struct ns_connection *nc, const char *path) {
  ns_stat_t st;
  if (ns_stat(path, &st) != 0) {
    send_http_error(nc, 404, NULL);
  } else if (S_ISDIR(st.st_mode)) {
    remove_directory(path);
    send_http_error(nc, 204, NULL);
  } else if (remove(path) == 0) {
    send_http_error(nc, 204, NULL);
  } else {
    send_http_error(nc, 423, NULL);
  }
}

/* Return -1 on error, 1 on success. */
static int create_itermediate_directories(const char *path) {
  const char *s = path;

  /* Create intermediate directories if they do not exist */
  while (*s) {
    if (*s == '/') {
      char buf[MAX_PATH_SIZE];
      ns_stat_t st;
      snprintf(buf, sizeof(buf), "%.*s", (int) (s - path), path);
      buf[sizeof(buf) - 1] = '\0';
      if (ns_stat(buf, &st) != 0 && mkdir(buf, 0755) != 0) {
        return -1;
      }
    }
    s++;
  }

  return 1;
}

static void handle_put(struct ns_connection *nc, const char *path,
                       struct http_message *hm) {
  ns_stat_t st;
  const struct ns_str *cl_hdr = ns_get_http_header(hm, "Content-Length");
  int rc, status_code = ns_stat(path, &st) == 0 ? 200 : 201;
  struct proto_data_http *dp = (struct proto_data_http *) nc->proto_data;

  free_http_proto_data(nc);
  if ((rc = create_itermediate_directories(path)) == 0) {
    ns_printf(nc, "HTTP/1.1 %d OK\r\nContent-Length: 0\r\n\r\n", status_code);
  } else if (rc == -1) {
    send_http_error(nc, 500, NULL);
  } else if (cl_hdr == NULL) {
    send_http_error(nc, 411, NULL);
  } else if ((dp = (struct proto_data_http *) NS_CALLOC(1, sizeof(*dp))) ==
             NULL) {
    send_http_error(nc, 500, NULL); /* LCOV_EXCL_LINE */
  } else if ((dp->fp = fopen(path, "w+b")) == NULL) {
    send_http_error(nc, 500, NULL);
    free_http_proto_data(nc);
  } else {
    const struct ns_str *range_hdr = ns_get_http_header(hm, "Content-Range");
    int64_t r1 = 0, r2 = 0;
    dp->type = DATA_PUT;
    ns_set_close_on_exec(fileno(dp->fp));
    dp->cl = to64(cl_hdr->p);
    if (range_hdr != NULL && parse_range_header(range_hdr->p, &r1, &r2) > 0) {
      status_code = 206;
      fseeko(dp->fp, r1, SEEK_SET);
      dp->cl = r2 > r1 ? r2 - r1 + 1 : dp->cl - r1;
    }
    ns_printf(nc, "HTTP/1.1 %d OK\r\nContent-Length: 0\r\n\r\n", status_code);
    nc->proto_data = dp;
    /* Remove HTTP request from the iobuf, leave only payload */
    iobuf_remove(&nc->recv_iobuf, hm->message.len - hm->body.len);
    transfer_file_data(nc);
  }
}
#endif /* NS_DISABLE_DAV */

static int is_dav_request(const struct ns_str *s) {
  return !ns_vcmp(s, "PUT") || !ns_vcmp(s, "DELETE") || !ns_vcmp(s, "MKCOL") ||
         !ns_vcmp(s, "PROPFIND");
}

static int find_index_file(char *path, size_t path_len, const char *list,
                           ns_stat_t *stp) {
  ns_stat_t st;
  size_t n = strlen(path);
  struct ns_str vec;
  int found = 0;

  /* The 'path' given to us points to the directory. Remove all trailing */
  /* directory separator characters from the end of the path, and */
  /* then append single directory separator character. */
  while (n > 0 && (path[n - 1] == '/' || path[n - 1] == '\\')) {
    n--;
  }

  /* Traverse index files list. For each entry, append it to the given */
  /* path and see if the file exists. If it exists, break the loop */
  while ((list = ns_next_comma_list_entry(list, &vec, NULL)) != NULL) {
    /* Prepare full path to the index file */
    snprintf(path + n, path_len - n, "/%.*s", (int) vec.len, vec.p);
    path[path_len - 1] = '\0';

    /* Does it exist? */
    if (!ns_stat(path, &st)) {
      /* Yes it does, break the loop */
      *stp = st;
      found = 1;
      break;
    }
  }

  /* If no index file exists, restore directory path */
  if (!found) {
    path[n] = '\0';
  }

  return found;
}

static void uri_to_path(struct http_message *hm, char *buf, size_t buf_len,
                        const struct ns_serve_http_opts *opts) {
  char uri[NS_MAX_PATH];
  struct ns_str a, b, *host_hdr = ns_get_http_header(hm, "Host");
  const char *rewrites = opts->url_rewrites;

  ns_url_decode(hm->uri.p, hm->uri.len, uri, sizeof(uri), 0);
  remove_double_dots(uri);
  snprintf(buf, buf_len, "%s%s", opts->document_root, uri);

#ifndef NS_DISABLE_DAV
  if (is_dav_request(&hm->method) && opts->dav_document_root != NULL) {
    snprintf(buf, buf_len, "%s%s", opts->dav_document_root, uri);
  }
#endif

  /* Handle URL rewrites */
  while ((rewrites = ns_next_comma_list_entry(rewrites, &a, &b)) != NULL) {
    if (a.len > 1 && a.p[0] == '@' && host_hdr != NULL &&
        host_hdr->len == a.len - 1 &&
        ns_ncasecmp(a.p + 1, host_hdr->p, a.len - 1) == 0) {
      /* This is a virtual host rewrite: @domain.name=document_root_dir */
      snprintf(buf, buf_len, "%.*s%s", (int) b.len, b.p, uri);
      break;
    } else {
      /* This is a usual rewrite, URI=directory */
      int match_len = ns_match_prefix(a.p, a.len, uri);
      if (match_len > 0) {
        snprintf(buf, buf_len, "%.*s%s", (int) b.len, b.p, uri + match_len);
        break;
      }
    }
  }
}

#ifndef NS_DISABLE_CGI
#ifdef _WIN32
struct threadparam {
  sock_t s;
  HANDLE hPipe;
};

static int wait_until_ready(sock_t sock, int for_read) {
  fd_set set;
  FD_ZERO(&set);
  FD_SET(sock, &set);
  select(sock + 1, for_read ? &set : 0, for_read ? 0 : &set, 0, 0);
  return 1;
}

static void *push_to_stdin(void *arg) {
  struct threadparam *tp = (struct threadparam *) arg;
  int n, sent, stop = 0;
  DWORD k;
  char buf[BUFSIZ];

  while (!stop && wait_until_ready(tp->s, 1) &&
         (n = recv(tp->s, buf, sizeof(buf), 0)) > 0) {
    if (n == -1 && GetLastError() == WSAEWOULDBLOCK) continue;
    for (sent = 0; !stop && sent < n; sent += k) {
      if (!WriteFile(tp->hPipe, buf + sent, n - sent, &k, 0)) stop = 1;
    }
  }
  DBG(("%s", "FORWARED EVERYTHING TO CGI"));
  CloseHandle(tp->hPipe);
  NS_FREE(tp);
  _endthread();
  return NULL;
}

static void *pull_from_stdout(void *arg) {
  struct threadparam *tp = (struct threadparam *) arg;
  int k = 0, stop = 0;
  DWORD n, sent;
  char buf[BUFSIZ];

  while (!stop && ReadFile(tp->hPipe, buf, sizeof(buf), &n, NULL)) {
    for (sent = 0; !stop && sent < n; sent += k) {
      if (wait_until_ready(tp->s, 0) &&
          (k = send(tp->s, buf + sent, n - sent, 0)) <= 0)
        stop = 1;
    }
  }
  DBG(("%s", "EOF FROM CGI"));
  CloseHandle(tp->hPipe);
  shutdown(tp->s, 2);  // Without this, IO thread may get truncated data
  closesocket(tp->s);
  NS_FREE(tp);
  _endthread();
  return NULL;
}

static void spawn_stdio_thread(sock_t sock, HANDLE hPipe,
                               void *(*func)(void *)) {
  struct threadparam *tp = (struct threadparam *) NS_MALLOC(sizeof(*tp));
  if (tp != NULL) {
    tp->s = sock;
    tp->hPipe = hPipe;
    ns_start_thread(func, tp);
  }
}

static void abs_path(const char *utf8_path, char *abs_path, size_t len) {
  wchar_t buf[MAX_PATH_SIZE], buf2[MAX_PATH_SIZE];
  to_wchar(utf8_path, buf, ARRAY_SIZE(buf));
  GetFullPathNameW(buf, ARRAY_SIZE(buf2), buf2, NULL);
  WideCharToMultiByte(CP_UTF8, 0, buf2, wcslen(buf2) + 1, abs_path, len, 0, 0);
}

static pid_t start_process(const char *interp, const char *cmd, const char *env,
                           const char *envp[], const char *dir, sock_t sock) {
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  HANDLE a[2], b[2], me = GetCurrentProcess();
  wchar_t wcmd[MAX_PATH_SIZE], full_dir[MAX_PATH_SIZE];
  char buf[MAX_PATH_SIZE], buf2[MAX_PATH_SIZE], buf5[MAX_PATH_SIZE],
      buf4[MAX_PATH_SIZE], cmdline[MAX_PATH_SIZE];
  DWORD flags = DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS;
  FILE *fp;

  memset(&si, 0, sizeof(si));
  memset(&pi, 0, sizeof(pi));

  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

  CreatePipe(&a[0], &a[1], NULL, 0);
  CreatePipe(&b[0], &b[1], NULL, 0);
  DuplicateHandle(me, a[0], me, &si.hStdInput, 0, TRUE, flags);
  DuplicateHandle(me, b[1], me, &si.hStdOutput, 0, TRUE, flags);

  if (interp == NULL && (fp = fopen(cmd, "r")) != NULL) {
    buf[0] = buf[1] = '\0';
    fgets(buf, sizeof(buf), fp);
    buf[sizeof(buf) - 1] = '\0';
    if (buf[0] == '#' && buf[1] == '!') {
      interp = buf + 2;
    }
    fclose(fp);
  }

  snprintf(buf, sizeof(buf), "%s/%s", dir, cmd);
  abs_path(buf, buf2, ARRAY_SIZE(buf2));

  abs_path(dir, buf5, ARRAY_SIZE(buf5));
  to_wchar(dir, full_dir, ARRAY_SIZE(full_dir));

  if (interp != NULL) {
    abs_path(interp, buf4, ARRAY_SIZE(buf4));
    snprintf(cmdline, sizeof(cmdline), "%s \"%s\"", buf4, buf2);
  } else {
    snprintf(cmdline, sizeof(cmdline), "\"%s\"", buf2);
  }
  to_wchar(cmdline, wcmd, ARRAY_SIZE(wcmd));

#if 0
  printf("[%ls] [%ls]\n", full_dir, wcmd);
#endif

  if (CreateProcessW(NULL, wcmd, NULL, NULL, TRUE, CREATE_NEW_PROCESS_GROUP,
                     (void *) env, full_dir, &si, &pi) != 0) {
    spawn_stdio_thread(sock, a[1], push_to_stdin);
    spawn_stdio_thread(sock, b[0], pull_from_stdout);
  } else {
    CloseHandle(a[1]);
    CloseHandle(b[0]);
    closesocket(sock);
  }
  DBG(("CGI command: [%ls] -> %p", wcmd, pi.hProcess));

  /* Not closing a[0] and b[1] because we've used DUPLICATE_CLOSE_SOURCE */
  CloseHandle(si.hStdOutput);
  CloseHandle(si.hStdInput);
  /* CloseHandle(pi.hThread); */
  /* CloseHandle(pi.hProcess); */

  return pi.hProcess;
}
#else
static pid_t start_process(const char *interp, const char *cmd, const char *env,
                           const char *envp[], const char *dir, sock_t sock) {
  char buf[500];
  pid_t pid = fork();
  (void) env;

  if (pid == 0) {
    (void) chdir(dir);
    (void) dup2(sock, 0);
    (void) dup2(sock, 1);
    closesocket(sock);

    /*
     * After exec, all signal handlers are restored to their default values,
     * with one exception of SIGCHLD. According to POSIX.1-2001 and Linux's
     * implementation, SIGCHLD's handler will leave unchanged after exec
     * if it was set to be ignored. Restore it to default action.
     */
    signal(SIGCHLD, SIG_DFL);

    if (interp == NULL) {
      execle(cmd, cmd, (char *) 0, envp); /* (char *) 0 to squash warning */
    } else {
      execle(interp, interp, cmd, (char *) 0, envp);
    }
    snprintf(buf, sizeof(buf),
             "Status: 500\r\n\r\n"
             "500 Server Error: %s%s%s: %s",
             interp == NULL ? "" : interp, interp == NULL ? "" : " ", cmd,
             strerror(errno));
    send(1, buf, strlen(buf), 0);
    exit(EXIT_FAILURE); /* exec call failed */
  }

  return pid;
}
#endif /* _WIN32 */

/*
 * Append VARIABLE=VALUE\0 string to the buffer, and add a respective
 * pointer into the vars array.
 */
static char *addenv(struct cgi_env_block *block, const char *fmt, ...) {
  int n, space;
  char *added;
  va_list ap;

  /* Calculate how much space is left in the buffer */
  space = sizeof(block->buf) - block->len - 2;
  assert(space >= 0);

  /* Make a pointer to the free space int the buffer */
  added = block->buf + block->len;

  /* Copy VARIABLE=VALUE\0 string into the free space */
  va_start(ap, fmt);
  n = vsnprintf(added, (size_t) space, fmt, ap);
  va_end(ap);

  /* Make sure we do not overflow buffer and the envp array */
  if (n > 0 && n + 1 < space &&
      block->nvars < (int) ARRAY_SIZE(block->vars) - 2) {
    /* Append a pointer to the added string into the envp array */
    block->vars[block->nvars++] = added;
    /* Bump up used length counter. Include \0 terminator */
    block->len += n + 1;
  }

  return added;
}

static void addenv2(struct cgi_env_block *blk, const char *name) {
  const char *s;
  if ((s = getenv(name)) != NULL) addenv(blk, "%s=%s", name, s);
}

static void prepare_cgi_environment(struct ns_connection *nc, const char *prog,
                                    const struct http_message *hm,
                                    const struct ns_serve_http_opts *opts,
                                    struct cgi_env_block *blk) {
  const char *s, *slash;
  struct ns_str *h;
  char *p;
  size_t i;

  blk->len = blk->nvars = 0;
  blk->nc = nc;

  if ((s = getenv("SERVER_NAME")) != NULL) {
    addenv(blk, "SERVER_NAME=%s", s);
  } else {
    char buf[100];
    ns_sock_to_str(nc->sock, buf, sizeof(buf), 3);
    addenv(blk, "SERVER_NAME=%s", buf);
  }
  addenv(blk, "SERVER_ROOT=%s", opts->document_root);
  addenv(blk, "DOCUMENT_ROOT=%s", opts->document_root);
  addenv(blk, "SERVER_SOFTWARE=%s/%s", "Fossa", NS_FOSSA_VERSION);

  /* Prepare the environment block */
  addenv(blk, "%s", "GATEWAY_INTERFACE=CGI/1.1");
  addenv(blk, "%s", "SERVER_PROTOCOL=HTTP/1.1");
  addenv(blk, "%s", "REDIRECT_STATUS=200"); /* For PHP */

  /* TODO(lsm): fix this for IPv6 case */
  /*addenv(blk, "SERVER_PORT=%d", ri->remote_port); */

  addenv(blk, "REQUEST_METHOD=%.*s", (int) hm->method.len, hm->method.p);
#if 0
  addenv(blk, "REMOTE_ADDR=%s", ri->remote_ip);
  addenv(blk, "REMOTE_PORT=%d", ri->remote_port);
#endif
  addenv(blk, "REQUEST_URI=%.*s%s%.*s", (int) hm->uri.len, hm->uri.p,
         hm->query_string.len == 0 ? "" : "?", (int) hm->query_string.len,
         hm->query_string.p);

/* SCRIPT_NAME */
#if 0
  if (nc->path_info != NULL) {
    addenv(blk, "SCRIPT_NAME=%.*s",
           (int) (strlen(ri->uri) - strlen(nc->path_info)), ri->uri);
    addenv(blk, "PATH_INFO=%s", nc->path_info);
  } else {
#endif
  s = strrchr(prog, '/');
  slash = hm->uri.p + hm->uri.len;
  while (slash > hm->uri.p && *slash != '/') {
    slash--;
  }
  addenv(blk, "SCRIPT_NAME=%.*s%s", (int) (slash - hm->uri.p), hm->uri.p,
         s == NULL ? prog : s);
#if 0
  }
#endif

  addenv(blk, "SCRIPT_FILENAME=%s", prog);
  addenv(blk, "PATH_TRANSLATED=%s", prog);
  addenv(blk, "HTTPS=%s", nc->ssl != NULL ? "on" : "off");

  if ((h = ns_get_http_header((struct http_message *) hm, "Content-Type")) !=
      NULL) {
    addenv(blk, "CONTENT_TYPE=%.*s", (int) h->len, h->p);
  }

  if (hm->query_string.len > 0) {
    addenv(blk, "QUERY_STRING=%.*s", (int) hm->query_string.len,
           hm->query_string.p);
  }

  if ((h = ns_get_http_header((struct http_message *) hm, "Content-Length")) !=
      NULL) {
    addenv(blk, "CONTENT_LENGTH=%.*s", (int) h->len, h->p);
  }

  addenv2(blk, "PATH");
  addenv2(blk, "TMP");
  addenv2(blk, "TEMP");
  addenv2(blk, "TMPDIR");
  addenv2(blk, "PERLLIB");
  addenv2(blk, NS_ENV_EXPORT_TO_CGI);

#if defined(_WIN32)
  addenv2(blk, "COMSPEC");
  addenv2(blk, "SYSTEMROOT");
  addenv2(blk, "SystemDrive");
  addenv2(blk, "ProgramFiles");
  addenv2(blk, "ProgramFiles(x86)");
  addenv2(blk, "CommonProgramFiles(x86)");
#else
  addenv2(blk, "LD_LIBRARY_PATH");
#endif /* _WIN32 */

  /* Add all headers as HTTP_* variables */
  for (i = 0; hm->header_names[i].len > 0; i++) {
    p = addenv(blk, "HTTP_%.*s=%.*s", (int) hm->header_names[i].len,
               hm->header_names[i].p, (int) hm->header_values[i].len,
               hm->header_values[i].p);

    /* Convert variable name into uppercase, and change - to _ */
    for (; *p != '=' && *p != '\0'; p++) {
      if (*p == '-') *p = '_';
      *p = (char) toupper(*(unsigned char *) p);
    }
  }

  blk->vars[blk->nvars++] = NULL;
  blk->buf[blk->len++] = '\0';

  assert(blk->nvars < (int) ARRAY_SIZE(blk->vars));
  assert(blk->len > 0);
  assert(blk->len < (int) sizeof(blk->buf));
}

static void cgi_ev_handler(struct ns_connection *cgi_nc, int ev,
                           void *ev_data) {
  struct ns_connection *nc = (struct ns_connection *) cgi_nc->user_data;
  (void) ev_data;

  if (nc == NULL) return;

  switch (ev) {
    case NS_RECV:
      /*
       * CGI script does not output reply line, like "HTTP/1.1 CODE XXXXX\n"
       * It outputs headers, then body. Headers might include "Status"
       * header, which changes CODE, and it might include "Location" header
       * which changes CODE to 302.
       *
       * Therefore we do not send the output from the CGI script to the user
       * until all CGI headers are parsed (by setting NSF_DONT_SEND flag).
       *
       * Here we parse the output from the CGI script, and if all headers has
       * been received, amend the reply line, and clear NSF_DONT_SEND flag,
       * which makes data to be sent to the user.
       */
      if (nc->flags & NSF_USER_1) {
        struct iobuf *io = &cgi_nc->recv_iobuf;
        int len = get_request_len(io->buf, io->len);

        if (len == 0) break;
        if (len < 0 || io->len > NS_MAX_HTTP_REQUEST_SIZE) {
          cgi_nc->flags |= NSF_CLOSE_IMMEDIATELY;
          send_http_error(nc, 500, "Bad headers");
        } else {
          struct http_message hm;
          struct ns_str *h;
          parse_http_headers(io->buf, io->buf + io->len, io->len, &hm);
          /*printf("=== %d [%.*s]\n", k, k, io->buf);*/
          if (ns_get_http_header(&hm, "Location") != NULL) {
            ns_printf(nc, "%s", "HTTP/1.1 302 Moved\r\n");
          } else if ((h = ns_get_http_header(&hm, "Status")) != NULL) {
            ns_printf(nc, "HTTP/1.1 %.*s\r\n", (int) h->len, h->p);
          } else {
            ns_printf(nc, "%s", "HTTP/1.1 200 OK\r\n");
          }
        }
        nc->flags &= ~NSF_USER_1;
      }
      if (!(nc->flags & NSF_USER_1)) {
        ns_send(nc, cgi_nc->recv_iobuf.buf, cgi_nc->recv_iobuf.len);
        iobuf_remove(&cgi_nc->recv_iobuf, cgi_nc->recv_iobuf.len);
      }
      break;
    case NS_CLOSE:
      free_http_proto_data(nc);
      nc->flags |= NSF_SEND_AND_CLOSE;
      nc->user_data = NULL;
      break;
  }
}

static void handle_cgi(struct ns_connection *nc, const char *prog,
                       const struct http_message *hm,
                       const struct ns_serve_http_opts *opts) {
  struct proto_data_http *dp;
  struct cgi_env_block blk;
  char dir[MAX_PATH_SIZE];
  const char *p;
  sock_t fds[2];

  prepare_cgi_environment(nc, prog, hm, opts, &blk);
  /*
   * CGI must be executed in its own directory. 'dir' must point to the
   * directory containing executable program, 'p' must point to the
   * executable program name relative to 'dir'.
   */
  if ((p = strrchr(prog, '/')) == NULL) {
    snprintf(dir, sizeof(dir), "%s", ".");
  } else {
    snprintf(dir, sizeof(dir), "%.*s", (int) (p - prog), prog);
    prog = p + 1;
  }

  /*
   * Try to create socketpair in a loop until success. ns_socketpair()
   * can be interrupted by a signal and fail.
   * TODO(lsm): use sigaction to restart interrupted syscall
   */
  do {
    ns_socketpair(fds, SOCK_STREAM);
  } while (fds[0] == INVALID_SOCKET);

  free_http_proto_data(nc);
  if ((dp = (struct proto_data_http *) NS_CALLOC(1, sizeof(*dp))) == NULL) {
    send_http_error(nc, 500, "OOM"); /* LCOV_EXCL_LINE */
  } else if (start_process(opts->cgi_interpreter, prog, blk.buf, blk.vars, dir,
                           fds[1]) != 0) {
    size_t n = nc->recv_iobuf.len - (hm->message.len - hm->body.len);
    dp->type = DATA_CGI;
    dp->cgi_nc = ns_add_sock(nc->mgr, fds[0], cgi_ev_handler);
    dp->cgi_nc->user_data = nc;
    nc->flags |= NSF_USER_1;
    /* Push POST data to the CGI */
    if (n > 0 && n < nc->recv_iobuf.len) {
      ns_send(dp->cgi_nc, hm->body.p, n);
    }
    iobuf_remove(&nc->recv_iobuf, nc->recv_iobuf.len);
  } else {
    closesocket(fds[0]);
    send_http_error(nc, 500, "CGI failure");
  }

#ifndef _WIN32
  closesocket(fds[1]); /* On Windows, CGI stdio thread closes that socket */
#endif
}
#endif

void ns_send_http_file(struct ns_connection *nc, char *path,
                       size_t path_buf_len, struct http_message *hm,
                       struct ns_serve_http_opts *opts) {
  int stat_result, is_directory, is_dav = is_dav_request(&hm->method);
  uint32_t remote_ip = ntohl(*(uint32_t *) &nc->sa.sin.sin_addr);
  ns_stat_t st;

  stat_result = ns_stat(path, &st);
  is_directory = !stat_result && S_ISDIR(st.st_mode);

  if (ns_check_ip_acl(opts->ip_acl, remote_ip) != 1) {
    /* Not allowed to connect */
    nc->flags |= NSF_CLOSE_IMMEDIATELY;
  } else if (is_dav && opts->dav_document_root == NULL) {
    send_http_error(nc, 501, NULL);
  } else if (!is_authorized(hm, path, is_directory, opts)) {
    ns_printf(nc,
              "HTTP/1.1 401 Unauthorized\r\n"
              "WWW-Authenticate: Digest qop=\"auth\", "
              "realm=\"%s\", nonce=\"%lu\"\r\n"
              "Content-Length: 0\r\n\r\n",
              opts->auth_domain, (unsigned long) time(NULL));
  } else if ((stat_result != 0 || is_file_hidden(path, opts)) && !is_dav) {
    ns_printf(nc, "%s", "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
  } else if (is_directory && path[strlen(path) - 1] != '/' && !is_dav) {
    ns_printf(nc,
              "HTTP/1.1 301 Moved\r\nLocation: %.*s/\r\n"
              "Content-Length: 0\r\n\r\n",
              (int) hm->uri.len, hm->uri.p);
#ifndef NS_DISABLE_DAV
  } else if (!ns_vcmp(&hm->method, "PROPFIND")) {
    handle_propfind(nc, path, &st, hm, opts);
  } else if (!ns_vcmp(&hm->method, "MKCOL")) {
    handle_mkcol(nc, path, hm);
  } else if (!ns_vcmp(&hm->method, "DELETE")) {
    handle_delete(nc, path);
  } else if (!ns_vcmp(&hm->method, "PUT")) {
    handle_put(nc, path, hm);
#endif
  } else if (S_ISDIR(st.st_mode) &&
             !find_index_file(path, path_buf_len, opts->index_files, &st)) {
    if (strcmp(opts->enable_directory_listing, "yes") == 0) {
#ifndef NS_DISABLE_DIRECTORY_LISTING
      send_directory_listing(nc, path, hm, opts);
#else
      send_http_error(nc, 501, NULL);
#endif
    } else {
      send_http_error(nc, 403, NULL);
    }
  } else if (ns_match_prefix(opts->cgi_file_pattern,
                             strlen(opts->cgi_file_pattern), path) > 0) {
#if !defined(NS_DISABLE_CGI)
    handle_cgi(nc, path, hm, opts);
#else
    send_http_error(nc, 501, NULL);
#endif /* NS_DISABLE_CGI */
  } else {
    ns_send_http_file2(nc, path, &st, hm, opts);
  }
}

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
 *syntax
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
void ns_serve_http(struct ns_connection *nc, struct http_message *hm,
                   struct ns_serve_http_opts opts) {
  char path[NS_MAX_PATH];
  uri_to_path(hm, path, sizeof(path), &opts);
  if (opts.per_directory_auth_file == NULL) {
    opts.per_directory_auth_file = ".htpasswd";
  }
  if (opts.enable_directory_listing == NULL) {
    opts.enable_directory_listing = "yes";
  }
  if (opts.cgi_file_pattern == NULL) {
    opts.cgi_file_pattern = "**.cgi$|**.php$";
  }
  if (opts.index_files == NULL) {
    opts.index_files = "index.html,index.htm,index.shtml,index.cgi,index.php";
  }
  ns_send_http_file(nc, path, sizeof(path), hm, &opts);
}

#endif /* NS_DISABLE_FILESYSTEM */

/*
 * Helper function that creates outbound HTTP connection.
 *
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
struct ns_connection *ns_connect_http(struct ns_mgr *mgr,
                                      ns_event_handler_t ev_handler,
                                      const char *url,
                                      const char *extra_headers,
                                      const char *post_data) {
  struct ns_connection *nc;
  char addr[1100], path[4096]; /* NOTE: keep sizes in sync with sscanf below */
  int use_ssl = 0;

  if (memcmp(url, "http://", 7) == 0) {
    url += 7;
  } else if (memcmp(url, "https://", 8) == 0) {
    url += 8;
    use_ssl = 1;
#ifndef NS_ENABLE_SSL
    return NULL; /* SSL is not enabled, cannot do HTTPS URLs */
#endif
  }

  addr[0] = path[0] = '\0';

  /* addr buffer size made smaller to allow for port to be prepended */
  sscanf(url, "%1095[^/]/%4095s", addr, path);
  if (strchr(addr, ':') == NULL) {
    strncat(addr, use_ssl ? ":443" : ":80", sizeof(addr) - (strlen(addr) + 1));
  }

  if ((nc = ns_connect(mgr, addr, ev_handler)) != NULL) {
    ns_set_protocol_http_websocket(nc);

    if (use_ssl) {
#ifdef NS_ENABLE_SSL
      ns_set_ssl(nc, NULL, NULL);
#endif
    }

    ns_printf(nc,
              "%s /%s HTTP/1.1\r\nHost: %s\r\nContent-Length: %lu\r\n%s\r\n%s",
              post_data == NULL ? "GET" : "POST", path, addr,
              post_data == NULL ? 0 : strlen(post_data),
              extra_headers == NULL ? "" : extra_headers,
              post_data == NULL ? "" : post_data);
  }

  return nc;
}

#endif /* NS_DISABLE_HTTP_WEBSOCKET */
