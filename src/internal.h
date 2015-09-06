/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#ifndef NS_INTERNAL_HEADER_INCLUDED
#define NS_INTERNAL_HEADER_INCLUDED

#ifndef NS_MALLOC
#define NS_MALLOC malloc
#endif

#ifndef NS_CALLOC
#define NS_CALLOC calloc
#endif

#ifndef NS_REALLOC
#define NS_REALLOC realloc
#endif

#ifndef NS_FREE
#define NS_FREE free
#endif

#ifndef MBUF_REALLOC
#define MBUF_REALLOC NS_REALLOC
#endif

#ifndef MBUF_FREE
#define MBUF_FREE NS_FREE
#endif

#define NS_SET_PTRPTR(_ptr, _v) \
  do {                          \
    if (_ptr) *(_ptr) = _v;     \
  } while (0)

#ifndef NS_INTERNAL
#define NS_INTERNAL static
#endif

#if !defined(NS_MGR_EV_MGR) && defined(__linux__)
#define NS_MGR_EV_MGR 1 /* epoll() */
#endif
#if !defined(NS_MGR_EV_MGR)
#define NS_MGR_EV_MGR 0 /* select() */
#endif

#ifdef PICOTCP
#define NO_LIBC
#define NS_DISABLE_FILESYSTEM
#define NS_DISABLE_POPEN
#define NS_DISABLE_CGI
#define NS_DISABLE_DIRECTORY_LISTING
#define NS_DISABLE_SOCKETPAIR
#define NS_DISABLE_PFS
#endif

#include "../fossa.h"

/* internals that need to be accessible in unit tests */
NS_INTERNAL struct ns_connection *ns_finish_connect(struct ns_connection *nc,
                                                    int proto,
                                                    union socket_address *sa,
                                                    struct ns_add_sock_opts);

NS_INTERNAL int ns_parse_address(const char *str, union socket_address *sa,
                                 int *proto, char *host, size_t host_len);
NS_INTERNAL void ns_call(struct ns_connection *, int ev, void *ev_data);
NS_INTERNAL void ns_forward(struct ns_connection *, struct ns_connection *);
NS_INTERNAL void ns_add_conn(struct ns_mgr *mgr, struct ns_connection *c);
NS_INTERNAL void ns_remove_conn(struct ns_connection *c);

#ifndef NS_DISABLE_FILESYSTEM
NS_INTERNAL int find_index_file(char *, size_t, const char *, ns_stat_t *);
#endif

#ifdef _WIN32
void to_wchar(const char *path, wchar_t *wbuf, size_t wbuf_len);
#endif

/*
 * Reassemble the content of the buffer (buf, blen) which should be
 * in the HTTP chunked encoding, by collapsing data chunks to the
 * beginning of the buffer.
 *
 * If chunks get reassembled, modify hm->body to point to the reassembled
 * body and fire NS_HTTP_CHUNK event. If handler sets NSF_DELETE_CHUNK
 * in nc->flags, delete reassembled body from the mbuf.
 *
 * Return reassembled body size.
 */
NS_INTERNAL size_t ns_handle_chunked(struct ns_connection *nc,
                                     struct http_message *hm, char *buf,
                                     size_t blen);

/* Forward declarations for testing. */
extern void *(*test_malloc)(size_t);
extern void *(*test_calloc)(size_t, size_t);

#endif /* NS_INTERNAL_HEADER_INCLUDED */
