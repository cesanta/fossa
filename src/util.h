/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#ifndef NS_UTIL_HEADER_DEFINED
#define NS_UTIL_HEADER_DEFINED

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef MAX_PATH_SIZE
#define MAX_PATH_SIZE 500
#endif

const char *ns_skip(const char *, const char *, const char *, struct ns_str *);
int ns_ncasecmp(const char *s1, const char *s2, size_t len);
int ns_casecmp(const char *s1, const char *s2);
int ns_vcmp(const struct ns_str *str2, const char *str1);
int ns_vcasecmp(const struct ns_str *str2, const char *str1);
void ns_base64_decode(const unsigned char *s, int len, char *dst);
void ns_base64_encode(const unsigned char *src, int src_len, char *dst);
int ns_stat(const char *path, ns_stat_t *st);
FILE *ns_fopen(const char *path, const char *mode);
int ns_open(const char *path, int flag, int mode);
void *ns_start_thread(void *(*thread_func)(void *), void *thread_func_param);
void ns_set_close_on_exec(sock_t);
void ns_sock_to_str(sock_t sock, char *buf, size_t len, int flags);
int ns_hexdump(const void *buf, int len, char *dst, int dst_len);
void ns_hexdump_connection(struct ns_connection *nc, const char *path,
                           int num_bytes, int ev);
int ns_avprintf(char **buf, size_t size, const char *fmt, va_list ap);
int ns_is_big_endian(void);
const char *ns_next_comma_list_entry(const char *list, struct ns_str *val,
                                     struct ns_str *eq_val);
int ns_match_prefix(const char *pattern, int pattern_len, const char *str);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* NS_UTIL_HEADER_DEFINED */
