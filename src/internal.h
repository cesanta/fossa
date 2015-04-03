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

#define NS_SET_PTRPTR(_ptr, _v) \
  do {                          \
    if (_ptr) *(_ptr) = _v;     \
  } while (0)

#ifndef NS_INTERNAL
#define NS_INTERNAL static
#endif

#include "../fossa.h"

/* internals that need to be accessible in unit tests */
NS_INTERNAL struct ns_connection *ns_finish_connect(struct ns_connection *nc,
                                                    int proto,
                                                    union socket_address *sa,
                                                    struct ns_add_sock_opts);

NS_INTERNAL int ns_parse_address(const char *str, union socket_address *sa,
                                 int *proto, char *host, size_t host_len);

#ifdef _WIN32
NS_INTERNAL void to_wchar(const char *path, wchar_t *wbuf, size_t wbuf_len);
#endif

#endif /* NS_INTERNAL_HEADER_INCLUDED */
