/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

/*
 * === Utilities
 */

#ifndef NS_UTIL_HEADER_DEFINED
#define NS_UTIL_HEADER_DEFINED

#include <stdio.h>

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef MAX_PATH_SIZE
#define MAX_PATH_SIZE 500
#endif

/*
 * Fetch substring from input string `s`, `end` into `v`.
 * Skips initial delimiter characters. Records first non-delimiter character
 * as the beginning of substring `v`. Then scans the rest of the string
 * until a delimiter character or end-of-string is found.
 * `delimiters` is a 0-terminated string containing delimiter characters.
 * Either one of `delimiters` or `end_string` terminates the search.
 * Return an `s` pointer, advanced forward where parsing stopped.
 */
const char *ns_skip(const char *s, const char *end_string,
                    const char *delimiters, struct ns_str *v);

/*
 * Cross-platform version of `strncasecmp()`.
 */
int ns_ncasecmp(const char *s1, const char *s2, size_t len);

/*
 * Cross-platform version of `strcasecmp()`.
 */
int ns_casecmp(const char *s1, const char *s2);

/*
 * Cross-platform version of `strcmp()` where where first string is
 * specified by `struct ns_str`.
 */
int ns_vcmp(const struct ns_str *str2, const char *str1);

/*
 * Cross-platform version of `strncasecmp()` where first string is
 * specified by `struct ns_str`.
 */
int ns_vcasecmp(const struct ns_str *str2, const char *str1);

/*
 * Decode base64-encoded string `s`, `len` into the destination `dst`.
 * Destination has to have enough space to hold decoded buffer.
 * Decoding stops either when all string has been decoded, or invalid
 * character appeared.
 * Destination is '\0'-terminated.
 * Return number of decoded characters. On success, that should be equal to
 * `len`. On error (invalid character) the return value is smaller then `len`.
 */
int ns_base64_decode(const unsigned char *s, int len, char *dst);

/*
 * Base64-encode chunk of memory `src`, `src_len` into the destination `dst`.
 * Destination has to have enough space to hold encoded buffer.
 * Destination is '\0'-terminated.
 */
void ns_base64_encode(const unsigned char *src, int src_len, char *dst);

#ifndef NS_DISABLE_FILESYSTEM
/*
 * Perform a 64-bit `stat()` call against given file.
 *
 * `path` should be UTF8 encoded.
 *
 * Return value is the same as for `stat()` syscall.
 */
int ns_stat(const char *path, ns_stat_t *st);

/*
 * Open the given file and return a file stream.
 *
 * `path` and `mode` should be UTF8 encoded.
 *
 * Return value is the same as for the `fopen()` call.
 */
FILE *ns_fopen(const char *path, const char *mode);

/*
 * Open the given file and return a file stream.
 *
 * `path` should be UTF8 encoded.
 *
 * Return value is the same as for the `open()` syscall.
 */
int ns_open(const char *path, int flag, int mode);
#endif /* NS_DISABLE_FILESYSTEM */

#ifdef NS_ENABLE_THREADS
/*
 * Start a new detached thread.
 * Arguments and semantic is the same as pthead's `pthread_create()`.
 * `thread_func` is a thread function, `thread_func_param` is a parameter
 * that is passed to the thread function.
 */
void *ns_start_thread(void *(*thread_func)(void *), void *thread_func_param);
#endif

void ns_set_close_on_exec(sock_t);

#define NS_SOCK_STRINGIFY_IP 1
#define NS_SOCK_STRINGIFY_PORT 2
#define NS_SOCK_STRINGIFY_REMOTE 4
/*
 * Convert socket's local or remote address into string.
 *
 * The `flags` parameter is a bit mask that controls the behavior,
 * see `NS_SOCK_STRINGIFY_*` definitions.
 *
 * - NS_SOCK_STRINGIFY_IP - print IP address
 * - NS_SOCK_STRINGIFY_PORT - print port number
 * - NS_SOCK_STRINGIFY_REMOTE - print remote peer's IP/port, not local address
 *
 * If both port number and IP address are printed, they are separated by `:`.
 * If compiled with `-DNS_ENABLE_IPV6`, IPv6 addresses are supported.
 */
void ns_sock_to_str(sock_t sock, char *buf, size_t len, int flags);

/*
 * Convert socket's address into string.
 *
 * `flags` is NS_SOCK_STRINGIFY_IP and/or NS_SOCK_STRINGIFY_PORT.
 */
void ns_sock_addr_to_str(const union socket_address *sa, char *buf, size_t len,
                         int flags);

/*
 * Generates human-readable hexdump of memory chunk.
 *
 * Takes a memory buffer `buf` of length `len` and creates a hex dump of that
 * buffer in `dst`. Generated output is a-la hexdump(1).
 * Return length of generated string, excluding terminating `\0`. If returned
 * length is bigger than `dst_len`, overflow bytes are discarded.
 */
int ns_hexdump(const void *buf, int len, char *dst, int dst_len);

/*
 * Generates human-readable hexdump of the data sent or received by connection.
 * `path` is a file name where hexdump should be written. `num_bytes` is
 * a number of bytes sent/received. `ev` is one of the `NS_*` events sent to
 * an event handler. This function is supposed to be called from the
 * event handler.
 */
void ns_hexdump_connection(struct ns_connection *nc, const char *path,
                           int num_bytes, int ev);
/*
 * Print message to buffer. If buffer is large enough to hold the message,
 * return buffer. If buffer is to small, allocate large enough buffer on heap,
 * and return allocated buffer.
 * This is a supposed use case:
 *
 *    char buf[5], *p = buf;
 *    p = ns_avprintf(&p, sizeof(buf), "%s", "hi there");
 *    use_p_somehow(p);
 *    if (p != buf) {
 *      free(p);
 *    }
 *
 * The purpose of this is to avoid malloc-ing if generated strings are small.
 */
int ns_avprintf(char **buf, size_t size, const char *fmt, va_list ap);

/*
 * Return true if target platform is big endian.
 */
int ns_is_big_endian(void);

/*
 * A helper function for traversing a comma separated list of values.
 * It returns a list pointer shifted to the next value, or NULL if the end
 * of the list found.
 * Value is stored in val vector. If value has form "x=y", then eq_val
 * vector is initialized to point to the "y" part, and val vector length
 * is adjusted to point only to "x".
 * If list is just a comma separated list of entries, like "aa,bb,cc" then
 * `eq_val` will contain zero-length string.
 *
 * The purpose of this function is to parse comma separated string without
 * any copying/memory allocation.
 */
const char *ns_next_comma_list_entry(const char *list, struct ns_str *val,
                                     struct ns_str *eq_val);

/*
 * Match 0-terminated string against a glob pattern.
 * Match is case-insensitive. Return number of bytes matched, or -1 if no match.
 */
int ns_match_prefix(const char *pattern, int pattern_len, const char *str);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* NS_UTIL_HEADER_DEFINED */
