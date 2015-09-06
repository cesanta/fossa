/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#ifndef NS_DISABLE_HTTP

#include "internal.h"

enum http_proto_data_type { DATA_NONE, DATA_FILE, DATA_PUT, DATA_CGI };

struct proto_data_http {
  FILE *fp;         /* Opened file. */
  int64_t cl;       /* Content-Length. How many bytes to send. */
  int64_t sent;     /* How many bytes have been already sent. */
  int64_t body_len; /* How many bytes of chunked body was reassembled. */
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

static int ns_mkdir(const char *path, uint32_t mode) {
#ifndef _WIN32
  return mkdir(path, mode);
#else
  (void) mode;
  return _mkdir(path);
#endif
}

static struct ns_str get_mime_type(const char *path, const char *dflt,
                                   const struct ns_serve_http_opts *opts) {
  const char *ext, *overrides;
  size_t i, path_len;
  struct ns_str r, k, v;

  path_len = strlen(path);

  overrides = opts->custom_mime_types;
  while ((overrides = ns_next_comma_list_entry(overrides, &k, &v)) != NULL) {
    ext = path + (path_len - k.len);
    if (path_len > k.len && ns_vcasecmp(&k, ext) == 0) {
      return v;
    }
  }

  for (i = 0; static_builtin_mime_types[i].extension != NULL; i++) {
    ext = path + (path_len - static_builtin_mime_types[i].ext_len);
    if (path_len > static_builtin_mime_types[i].ext_len && ext[-1] == '.' &&
        ns_casecmp(ext, static_builtin_mime_types[i].extension) == 0) {
      r.p = static_builtin_mime_types[i].mime_type;
      r.len = strlen(r.p);
      return r;
    }
  }

  r.p = dflt;
  r.len = strlen(r.p);
  return r;
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
      k->len = v->len = 0;
      break;
    }

    if (!ns_ncasecmp(k->p, "Content-Length", 14)) {
      req->body.len = to64(v->p);
      req->message.len = len + req->body.len;
    }
  }

  return s;
}

int ns_parse_http(const char *s, int n, struct http_message *hm, int is_req) {
  const char *end, *qs;
  int len = get_request_len(s, n);

  if (len <= 0) return len;

  memset(hm, 0, sizeof(*hm));
  hm->message.p = s;
  hm->body.p = s + len;
  hm->message.len = hm->body.len = (size_t) ~0;
  end = s + len;

  /* Request is fully buffered. Skip leading whitespaces. */
  while (s < end && isspace(*(unsigned char *) s)) s++;

  if (is_req) {
    /* Parse request line: method, URI, proto */
    s = ns_skip(s, end, " ", &hm->method);
    s = ns_skip(s, end, " ", &hm->uri);
    s = ns_skip(s, end, "\r\n", &hm->proto);
    if (hm->uri.p <= hm->method.p || hm->proto.p <= hm->uri.p) return -1;

    /* If URI contains '?' character, initialize query_string */
    if ((qs = (char *) memchr(hm->uri.p, '?', hm->uri.len)) != NULL) {
      hm->query_string.p = qs + 1;
      hm->query_string.len = &hm->uri.p[hm->uri.len] - (qs + 1);
      hm->uri.len = qs - hm->uri.p;
    }
  } else {
    s = ns_skip(s, end, " ", &hm->proto);
    if (end - s < 4 || s[3] != ' ') return -1;
    hm->resp_code = atoi(s);
    if (hm->resp_code < 100 || hm->resp_code >= 600) return -1;
    s += 4;
    s = ns_skip(s, end, "\r\n", &hm->resp_status_msg);
  }

  s = parse_http_headers(s, end, len, hm);

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
  if (hm->body.len == (size_t) ~0 && is_req &&
      ns_vcasecmp(&hm->method, "PUT") != 0 &&
      ns_vcasecmp(&hm->method, "POST") != 0) {
    hm->body.len = 0;
    hm->message.len = len;
  }

  return len;
}

struct ns_str *ns_get_http_header(struct http_message *hm, const char *name) {
  size_t i, len = strlen(name);

  for (i = 0; i < ARRAY_SIZE(hm->header_names); i++) {
    struct ns_str *h = &hm->header_names[i], *v = &hm->header_values[i];
    if (h->p != NULL && h->len == len && !ns_ncasecmp(h->p, name, len))
      return v;
  }

  return NULL;
}

#ifndef NS_DISABLE_HTTP_WEBSOCKET

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
  uint64_t i, data_len = 0, frame_len = 0, buf_len = nc->recv_mbuf.len, len,
              mask_len = 0, header_len = 0;
  unsigned char *p = (unsigned char *) nc->recv_mbuf.buf, *buf = p,
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
        mbuf_resize(&nc->recv_mbuf, nc->recv_mbuf.size + sizeof(*sizep));
        p[0] &= ~0x0f; /* Next frames will be treated as continuation */
        buf = p + 1 + sizeof(*sizep);
        *sizep = 0; /* TODO(lsm): fix. this can stomp over frame data */
      }

      /* Append this frame to the reassembled buffer */
      memmove(buf, wsm.data, e - wsm.data);
      (*sizep) += wsm.size;
      nc->recv_mbuf.len -= wsm.data - buf;

      /* On last fragmented frame - call user handler and remove data */
      if (wsm.flags & 0x80) {
        wsm.data = p + 1 + sizeof(*sizep);
        wsm.size = *sizep;
        handle_incoming_websocket_frame(nc, &wsm);
        mbuf_remove(&nc->recv_mbuf, 1 + sizeof(*sizep) + *sizep);
      }
    } else {
      /* TODO(lsm): properly handle OOB control frames during defragmentation */
      handle_incoming_websocket_frame(nc, &wsm);
      mbuf_remove(&nc->recv_mbuf, (size_t) frame_len); /* Cleanup frame */
    }

    /* If client closes, close too */
    if ((buf[0] & 0x0f) == WEBSOCKET_OP_CLOSE) {
      nc->flags |= NSF_SEND_AND_CLOSE;
    }
  }

  return ok;
}

struct ws_mask_ctx {
  size_t pos; /* zero means unmasked */
  uint32_t mask;
};

static uint32_t ws_random_mask() {
/*
 * The spec requires WS client to generate hard to
 * guess mask keys. From RFC6455, Section 5.3:
 *
 * The unpredictability of the masking key is essential to prevent
 * authors of malicious applications from selecting the bytes that appear on
 * the wire.
 *
 * Hence this feature is essential when the actual end user of this API
 * is untrusted code that wouldn't have access to a lower level net API
 * anyway (e.g. web browsers). Hence this feature is low prio for most
 * fossa use cases and thus can be disabled, e.g. when porting to a platform
 * that lacks random().
 */
#if NS_DISABLE_WS_RANDOM_MASK
  return 0xefbeadde; /* generated with a random number generator, I swear */
#else
  if (sizeof(long) >= 4) {
    return (uint32_t) random();
  } else if (sizeof(long) == 2) {
    return (uint32_t) random() << 16 | (uint32_t) random();
  }
#endif
}

static void ns_send_ws_header(struct ns_connection *nc, int op, size_t len,
                              struct ws_mask_ctx *ctx) {
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

  /* client connections enable masking */
  if (nc->listener == NULL) {
    header[1] |= 1 << 7; /* set masking flag */
    ns_send(nc, header, header_len);
    ctx->mask = ws_random_mask();
    ns_send(nc, &ctx->mask, sizeof(ctx->mask));
    ctx->pos = nc->send_mbuf.len;
  } else {
    ns_send(nc, header, header_len);
    ctx->pos = 0;
  }
}

static void ws_mask_frame(struct mbuf *mbuf, struct ws_mask_ctx *ctx) {
  size_t i;
  if (ctx->pos == 0) return;
  for (i = 0; i < (mbuf->len - ctx->pos); i++) {
    mbuf->buf[ctx->pos + i] ^= ((char *) &ctx->mask)[i % 4];
  }
}

void ns_send_websocket_frame(struct ns_connection *nc, int op, const void *data,
                             size_t len) {
  struct ws_mask_ctx ctx;
  ns_send_ws_header(nc, op, len, &ctx);
  ns_send(nc, data, len);

  ws_mask_frame(&nc->send_mbuf, &ctx);

  if (op == WEBSOCKET_OP_CLOSE) {
    nc->flags |= NSF_SEND_AND_CLOSE;
  }
}

void ns_send_websocket_framev(struct ns_connection *nc, int op,
                              const struct ns_str *strv, int strvcnt) {
  struct ws_mask_ctx ctx;
  int i;
  int len = 0;
  for (i = 0; i < strvcnt; i++) {
    len += strv[i].len;
  }

  ns_send_ws_header(nc, op, len, &ctx);

  for (i = 0; i < strvcnt; i++) {
    ns_send(nc, strv[i].p, strv[i].len);
  }

  ws_mask_frame(&nc->send_mbuf, &ctx);

  if (op == WEBSOCKET_OP_CLOSE) {
    nc->flags |= NSF_SEND_AND_CLOSE;
  }
}

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
  cs_sha1_ctx sha_ctx;

  snprintf(buf, sizeof(buf), "%.*s%s", (int) key->len, key->p, magic);

  cs_sha1_init(&sha_ctx);
  cs_sha1_update(&sha_ctx, (unsigned char *) buf, strlen(buf));
  cs_sha1_final((unsigned char *) sha, &sha_ctx);

  ns_base64_encode((unsigned char *) sha, sizeof(sha), b64_sha);
  ns_printf(nc, "%s%s%s",
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: ",
            b64_sha, "\r\n\r\n");
}

#endif /* NS_DISABLE_HTTP_WEBSOCKET */

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
    struct mbuf *io = &nc->send_mbuf;
    if (io->len < sizeof(buf)) {
      to_read = sizeof(buf) - io->len;
    }

    if (left > 0 && to_read > (size_t) left) {
      to_read = left;
    }

    if (to_read == 0) {
      /* Rate limiting. send_mbuf is too full, wait until it's drained. */
    } else if (dp->sent < dp->cl && (n = fread(buf, 1, to_read, dp->fp)) > 0) {
      ns_send(nc, buf, n);
      dp->sent += n;
    } else {
      free_http_proto_data(nc);
    }
  } else if (dp->type == DATA_PUT) {
    struct mbuf *io = &nc->recv_mbuf;
    size_t to_write =
        left <= 0 ? 0 : left < (int64_t) io->len ? (size_t) left : io->len;
    size_t n = fwrite(io->buf, 1, to_write, dp->fp);
    if (n > 0) {
      mbuf_remove(io, n);
      dp->sent += n;
    }
    if (n == 0 || dp->sent >= dp->cl) {
      free_http_proto_data(nc);
    }
  } else if (dp->type == DATA_CGI) {
    /* This is POST data that needs to be forwarded to the CGI process */
    if (dp->cgi_nc != NULL) {
      ns_forward(nc, dp->cgi_nc);
    } else {
      nc->flags |= NSF_SEND_AND_CLOSE;
    }
  }
}

/*
 * Parse chunked-encoded buffer. Return 0 if the buffer is not encoded, or
 * if it's incomplete. If the chunk is fully buffered, return total number of
 * bytes in a chunk, and store data in `data`, `data_len`.
 */
static size_t parse_chunk(char *buf, size_t len, char **chunk_data,
                          size_t *chunk_len) {
  unsigned char *s = (unsigned char *) buf;
  size_t n = 0; /* scanned chunk length */
  size_t i = 0; /* index in s */

  /* Scan chunk length. That should be a hexadecimal number. */
  while (i < len && isxdigit(s[i])) {
    n *= 16;
    n += (s[i] >= '0' && s[i] <= '9') ? s[i] - '0' : tolower(s[i]) - 'a' + 10;
    i++;
  }

  /* Skip new line */
  if (i == 0 || i + 2 > len || s[i] != '\r' || s[i + 1] != '\n') {
    return 0;
  }
  i += 2;

  /* Record where the data is */
  *chunk_data = (char *) s + i;
  *chunk_len = n;

  /* Skip data */
  i += n;

  /* Skip new line */
  if (i == 0 || i + 2 > len || s[i] != '\r' || s[i + 1] != '\n') {
    return 0;
  }
  return i + 2;
}

NS_INTERNAL size_t ns_handle_chunked(struct ns_connection *nc,
                                     struct http_message *hm, char *buf,
                                     size_t blen) {
  struct proto_data_http *dp;
  char *data;
  size_t i, n, data_len, body_len, zero_chunk_received = 0;

  /* If not allocated, allocate proto_data to hold reassembled offset */
  if (nc->proto_data == NULL &&
      (nc->proto_data = NS_CALLOC(1, sizeof(*dp))) == NULL) {
    nc->flags |= NSF_CLOSE_IMMEDIATELY;
    return 0;
  }

  /* Find out piece of received data that is not yet reassembled */
  dp = (struct proto_data_http *) nc->proto_data;
  body_len = dp->body_len;
  assert(blen >= body_len);

  /* Traverse all fully buffered chunks */
  for (i = body_len; (n = parse_chunk(buf + i, blen - i, &data, &data_len)) > 0;
       i += n) {
    /* Collapse chunk data to the rest of HTTP body */
    memmove(buf + body_len, data, data_len);
    body_len += data_len;
    hm->body.len = body_len;

    if (data_len == 0) {
      zero_chunk_received = 1;
      i += n;
      break;
    }
  }

  if (i > body_len) {
    /* Shift unparsed content to the parsed body */
    assert(i <= blen);
    memmove(buf + body_len, buf + i, blen - i);
    memset(buf + body_len + blen - i, 0, i - body_len);
    nc->recv_mbuf.len -= i - body_len;
    dp->body_len = body_len;

    /* Send NS_HTTP_CHUNK event */
    nc->flags &= ~NSF_DELETE_CHUNK;
    nc->handler(nc, NS_HTTP_CHUNK, hm);

    /* Delete processed data if user set NSF_DELETE_CHUNK flag */
    if (nc->flags & NSF_DELETE_CHUNK) {
      memset(buf, 0, body_len);
      memmove(buf, buf + body_len, blen - i);
      nc->recv_mbuf.len -= body_len;
      hm->body.len = dp->body_len = 0;
    }

    if (zero_chunk_received) {
      hm->message.len = dp->body_len + blen - i;
    }
  }

  return body_len;
}

static void http_handler(struct ns_connection *nc, int ev, void *ev_data) {
  struct mbuf *io = &nc->recv_mbuf;
  struct http_message hm;
  int req_len;
  const int is_req = (nc->listener != NULL);
#ifndef NS_DISABLE_HTTP_WEBSOCKET
  struct ns_str *vec;
#endif
  /*
   * For HTTP messages without Content-Length, always send HTTP message
   * before NS_CLOSE message.
   */
  if (ev == NS_CLOSE && io->len > 0 &&
      ns_parse_http(io->buf, io->len, &hm, is_req) > 0) {
    hm.message.len = io->len;
    hm.body.len = io->buf + io->len - hm.body.p;
    nc->handler(nc, is_req ? NS_HTTP_REQUEST : NS_HTTP_REPLY, &hm);
    free_http_proto_data(nc);
  }

  if (nc->proto_data != NULL) {
    transfer_file_data(nc);
  }

  nc->handler(nc, ev, ev_data);

  if (ev == NS_RECV) {
    struct ns_str *s;
    req_len = ns_parse_http(io->buf, io->len, &hm, is_req);

    if (req_len > 0 &&
        (s = ns_get_http_header(&hm, "Transfer-Encoding")) != NULL &&
        ns_vcasecmp(s, "chunked") == 0) {
      ns_handle_chunked(nc, &hm, io->buf + req_len, io->len - req_len);
    }

    if (req_len < 0 || (req_len == 0 && io->len >= NS_MAX_HTTP_REQUEST_SIZE)) {
      nc->flags |= NSF_CLOSE_IMMEDIATELY;
    } else if (req_len == 0) {
      /* Do nothing, request is not yet fully buffered */
    }
#ifndef NS_DISABLE_HTTP_WEBSOCKET
    else if (nc->listener == NULL &&
             ns_get_http_header(&hm, "Sec-WebSocket-Accept")) {
      /* We're websocket client, got handshake response from server. */
      /* TODO(lsm): check the validity of accept Sec-WebSocket-Accept */
      mbuf_remove(io, req_len);
      nc->proto_handler = websocket_handler;
      nc->flags |= NSF_IS_WEBSOCKET;
      nc->handler(nc, NS_WEBSOCKET_HANDSHAKE_DONE, NULL);
      websocket_handler(nc, NS_RECV, ev_data);
    } else if (nc->listener != NULL &&
               (vec = ns_get_http_header(&hm, "Sec-WebSocket-Key")) != NULL) {
      /* This is a websocket request. Switch protocol handlers. */
      mbuf_remove(io, req_len);
      nc->proto_handler = websocket_handler;
      nc->flags |= NSF_IS_WEBSOCKET;

      /* Send handshake */
      nc->handler(nc, NS_WEBSOCKET_HANDSHAKE_REQUEST, &hm);
      if (!(nc->flags & NSF_CLOSE_IMMEDIATELY)) {
        if (nc->send_mbuf.len == 0) {
          ws_handshake(nc, vec);
        }
        nc->handler(nc, NS_WEBSOCKET_HANDSHAKE_DONE, NULL);
        websocket_handler(nc, NS_RECV, ev_data);
      }
    }
#endif /* NS_DISABLE_HTTP_WEBSOCKET */
    else if (hm.message.len <= io->len) {
      /* Whole HTTP message is fully buffered, call event handler */
      nc->handler(nc, nc->listener ? NS_HTTP_REQUEST : NS_HTTP_REPLY, &hm);
      mbuf_remove(io, hm.message.len);
    }
  }
}

void ns_set_protocol_http_websocket(struct ns_connection *nc) {
  nc->proto_handler = http_handler;
}

#ifndef NS_DISABLE_HTTP_WEBSOCKET

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

#endif /* NS_DISABLE_HTTP_WEBSOCKET */

#ifndef NS_DISABLE_FILESYSTEM
static void send_http_error(struct ns_connection *nc, int code,
                            const char *reason) {
  if (reason == NULL) {
    reason = "";
  }
  ns_printf(nc, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n", code, reason);
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
    if (ns_match_prefix(opts->ssi_pattern, strlen(opts->ssi_pattern), path) >
        0) {
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

static void do_ssi_call(struct ns_connection *nc, char *tag) {
  ns_call(nc, NS_SSI_CALL, tag);
}

/*
 * SSI directive has the following format:
 * <!--#directive parameter=value parameter=value -->
 */
static void send_ssi_file(struct ns_connection *nc, const char *path, FILE *fp,
                          int include_level,
                          const struct ns_serve_http_opts *opts) {
  static const struct ns_str btag = NS_STR("<!--#");
  static const struct ns_str d_include = NS_STR("include");
  static const struct ns_str d_call = NS_STR("call");
  static const struct ns_str d_exec = NS_STR("exec");
  char buf[BUFSIZ], *p = buf + btag.len; /* p points to SSI directive */
  int ch, offset, len, in_ssi_tag;

  if (include_level > 10) {
    ns_printf(nc, "SSI #include level is too deep (%s)", path);
    return;
  }

  in_ssi_tag = len = offset = 0;
  while ((ch = fgetc(fp)) != EOF) {
    if (in_ssi_tag && ch == '>' && buf[len - 1] == '-' && buf[len - 2] == '-') {
      size_t i = len - 2;
      in_ssi_tag = 0;

      /* Trim closing --> */
      buf[i--] = '\0';
      while (i > 0 && buf[i] == ' ') {
        buf[i--] = '\0';
      }

      /* Handle known SSI directives */
      if (memcmp(p, d_include.p, d_include.len) == 0) {
        do_ssi_include(nc, path, p + d_include.len + 1, include_level, opts);
      } else if (memcmp(p, d_call.p, d_call.len) == 0) {
        do_ssi_call(nc, p + d_call.len + 1);
#ifndef NS_DISABLE_POPEN
      } else if (memcmp(p, d_exec.p, d_exec.len) == 0) {
        do_ssi_exec(nc, p + d_exec.len + 1);
#endif
      } else {
        /* Silently ignore unknown SSI directive. */
      }
      len = 0;
    } else if (in_ssi_tag) {
      if (len == (int) btag.len && memcmp(buf, btag.p, btag.len) != 0) {
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
  struct ns_str mime_type;

  if ((fp = fopen(path, "rb")) == NULL) {
    send_http_error(nc, 404, "Not Found");
  } else {
    ns_set_close_on_exec(fileno(fp));

    mime_type = get_mime_type(path, "text/plain", opts);
    ns_printf(nc,
              "HTTP/1.1 200 OK\r\n"
              "Content-Type: %.*s\r\n"
              "Connection: close\r\n\r\n",
              (int) mime_type.len, mime_type.p);
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

static int parse_range_header(const struct ns_str *header, int64_t *a,
                              int64_t *b) {
  /*
   * There is no snscanf. Headers are not guaranteed to be NUL-terminated,
   * so we have this. Ugh.
   */
  int result;
  char *p = (char *) NS_MALLOC(header->len + 1);
  if (p == NULL) return 0;
  memcpy(p, header->p, header->len);
  p[header->len] = '\0';
  result = sscanf(p, "bytes=%" INT64_FMT "-%" INT64_FMT, a, b);
  NS_FREE(p);
  return result;
}

static void ns_send_http_file2(struct ns_connection *nc, const char *path,
                               ns_stat_t *st, struct http_message *hm,
                               struct ns_serve_http_opts *opts) {
  struct proto_data_http *dp;
  struct ns_str mime_type;

  free_http_proto_data(nc);
  if ((dp = (struct proto_data_http *) NS_CALLOC(1, sizeof(*dp))) == NULL) {
    send_http_error(nc, 500, "Server Error"); /* LCOV_EXCL_LINE */
  } else if ((dp->fp = fopen(path, "rb")) == NULL) {
    NS_FREE(dp);
    nc->proto_data = NULL;
    send_http_error(nc, 500, "Server Error");
  } else if (ns_match_prefix(opts->ssi_pattern, strlen(opts->ssi_pattern),
                             path) > 0) {
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
        (n = parse_range_header(range_hdr, &r1, &r2)) > 0 && r1 >= 0 &&
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
    mime_type = get_mime_type(path, "text/plain", opts);
    ns_printf(nc,
              "HTTP/1.1 %d %s\r\n"
              "Date: %s\r\n"
              "Last-Modified: %s\r\n"
              "Accept-Ranges: bytes\r\n"
              "Content-Type: %.*s\r\n"
              "Content-Length: %" INT64_FMT
              "\r\n"
              "%s"
              "Etag: %s\r\n"
              "\r\n",
              status_code, status_message, current_time, last_modified,
              (int) mime_type.len, mime_type.p, cl, range, etag);
    nc->proto_data = (void *) dp;
    dp->cl = cl;
    dp->type = DATA_FILE;
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

void ns_send_http_chunk(struct ns_connection *nc, const char *buf, size_t len) {
  char chunk_size[50];
  int n;

  n = snprintf(chunk_size, sizeof(chunk_size), "%lX\r\n", (unsigned long) len);
  ns_send(nc, chunk_size, n);
  ns_send(nc, buf, len);
  ns_send(nc, "\r\n", 2);
}

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

void ns_printf_html_escape(struct ns_connection *nc, const char *fmt, ...) {
  char mem[500], *buf = mem;
  int i, j, len;
  va_list ap;

  va_start(ap, fmt);
  len = ns_avprintf(&buf, sizeof(mem), fmt, ap);
  va_end(ap);

  if (len >= 0) {
    for (i = j = 0; i < len; i++) {
      if (buf[i] == '<' || buf[i] == '>') {
        ns_send(nc, buf + j, i - j);
        ns_send(nc, buf[i] == '<' ? "&lt;" : "&gt;", 4);
        j = i + 1;
      }
    }
    ns_send(nc, buf + j, i - j);
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
  /* TODO(rojer): Remove when cesanta/dev/issues/197 is fixed. */
  nc->flags |= NSF_SEND_AND_CLOSE;
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
  } else if (!ns_mkdir(path, 0755)) {
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
      if (ns_stat(buf, &st) != 0 && ns_mkdir(buf, 0755) != 0) {
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
    if (range_hdr != NULL && parse_range_header(range_hdr, &r1, &r2) > 0) {
      status_code = 206;
      fseeko(dp->fp, r1, SEEK_SET);
      dp->cl = r2 > r1 ? r2 - r1 + 1 : dp->cl - r1;
    }
    ns_printf(nc, "HTTP/1.1 %d OK\r\nContent-Length: 0\r\n\r\n", status_code);
    nc->proto_data = dp;
    /* Remove HTTP request from the mbuf, leave only payload */
    mbuf_remove(&nc->recv_mbuf, hm->message.len - hm->body.len);
    transfer_file_data(nc);
  }
}
#endif /* NS_DISABLE_DAV */

static int is_dav_request(const struct ns_str *s) {
  return !ns_vcmp(s, "PUT") || !ns_vcmp(s, "DELETE") || !ns_vcmp(s, "MKCOL") ||
         !ns_vcmp(s, "PROPFIND");
}

/*
 * Given a directory path, find one of the files specified in the
 * comma-separated list of index files `list`.
 * First found index file wins. If an index file is found, then gets
 * appended to the `path`, stat-ed, and result of `stat()` passed to `stp`.
 * If index file is not found, then `path` and `stp` remain unchanged.
 */
NS_INTERNAL int find_index_file(char *path, size_t path_len, const char *list,
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

  /* If no index file exists, restore directory path, keep trailing slash. */
  if (!found) {
    path[n] = '\0';
    strncat(path + n, "/", path_len - n);
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
  return select(sock + 1, for_read ? &set : 0, for_read ? 0 : &set, 0, 0) == 1;
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
      /* Trim leading spaces: https://github.com/cesanta/mongoose/issues/489 */
      while (*interp != '\0' && isspace(*(unsigned char *) interp)) {
        interp++;
      }
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
  /* TODO(lsm): check if we need close process and thread handles too */
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
    /*
     * In Linux `chdir` declared with `warn_unused_result` attribute
     * To shutup compiler we have yo use result in some way
     */
    int tmp = chdir(dir);
    (void) tmp;
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
  char *added = block->buf + block->len;
  va_list ap;

  /* Calculate how much space is left in the buffer */
  space = sizeof(block->buf) - (block->len + 2);
  if (space > 0) {
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
        struct mbuf *io = &cgi_nc->recv_mbuf;
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
        ns_forward(cgi_nc, nc);
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
    size_t n = nc->recv_mbuf.len - (hm->message.len - hm->body.len);
    dp->type = DATA_CGI;
    dp->cgi_nc = ns_add_sock(nc->mgr, fds[0], cgi_ev_handler);
    dp->cgi_nc->user_data = nc;
    nc->flags |= NSF_USER_1;
    /* Push POST data to the CGI */
    if (n > 0 && n < nc->recv_mbuf.len) {
      ns_send(dp->cgi_nc, hm->body.p, n);
    }
    mbuf_remove(&nc->recv_mbuf, nc->recv_mbuf.len);
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
  if (opts.ssi_pattern == NULL) {
    opts.ssi_pattern = "**.shtml$|**.shtm$";
  }
  if (opts.index_files == NULL) {
    opts.index_files = "index.html,index.htm,index.shtml,index.cgi,index.php";
  }
  ns_send_http_file(nc, path, sizeof(path), hm, &opts);
}

#endif /* NS_DISABLE_FILESYSTEM */

struct ns_connection *ns_connect_http(struct ns_mgr *mgr,
                                      ns_event_handler_t ev_handler,
                                      const char *url,
                                      const char *extra_headers,
                                      const char *post_data) {
  struct ns_connection *nc;
  char addr[1100], path[4096]; /* NOTE: keep sizes in sync with sscanf below */
  int use_ssl = 0, addr_len = 0;

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
    addr_len = strlen(addr);
    strncat(addr, use_ssl ? ":443" : ":80", sizeof(addr) - (addr_len + 1));
  }

  if ((nc = ns_connect(mgr, addr, ev_handler)) != NULL) {
    ns_set_protocol_http_websocket(nc);

    if (use_ssl) {
#ifdef NS_ENABLE_SSL
      ns_set_ssl(nc, NULL, NULL);
#endif
    }

    if (addr_len) {
      /* Do not add port. See https://github.com/cesanta/fossa/pull/304 */
      addr[addr_len] = '\0';
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

static size_t get_line_len(const char *buf, size_t buf_len) {
  size_t len = 0;
  while (len < buf_len && buf[len] != '\n') len++;
  return buf[len] == '\n' ? len + 1 : 0;
}

size_t ns_parse_multipart(const char *buf, size_t buf_len, char *var_name,
                          size_t var_name_len, char *file_name,
                          size_t file_name_len, const char **data,
                          size_t *data_len) {
  static const char cd[] = "Content-Disposition: ";
  size_t hl, bl, n, ll, pos, cdl = sizeof(cd) - 1;

  if (buf == NULL || buf_len <= 0) return 0;
  if ((hl = get_request_len(buf, buf_len)) <= 0) return 0;
  if (buf[0] != '-' || buf[1] != '-' || buf[2] == '\n') return 0;

  /* Get boundary length */
  bl = get_line_len(buf, buf_len);

  /* Loop through headers, fetch variable name and file name */
  var_name[0] = file_name[0] = '\0';
  for (n = bl; (ll = get_line_len(buf + n, hl - n)) > 0; n += ll) {
    if (ns_ncasecmp(cd, buf + n, cdl) == 0) {
      struct ns_str header;
      header.p = buf + n + cdl;
      header.len = ll - (cdl + 2);
      ns_http_parse_header(&header, "name", var_name, var_name_len);
      ns_http_parse_header(&header, "filename", file_name, file_name_len);
    }
  }

  /* Scan through the body, search for terminating boundary */
  for (pos = hl; pos + (bl - 2) < buf_len; pos++) {
    if (buf[pos] == '-' && !memcmp(buf, &buf[pos], bl - 2)) {
      if (data_len != NULL) *data_len = (pos - 2) - hl;
      if (data != NULL) *data = buf + hl;
      return pos;
    }
  }

  return 0;
}

#endif /* NS_DISABLE_HTTP */
