/*
 * Copyright (c) 2014 Cesanta Software Limited
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

#ifndef NS_IOBUF_HEADER_INCLUDED
#define NS_IOBUF_HEADER_INCLUDED

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* IO buffer */
struct iobuf {
  char *buf;   /* Buffer pointer */
  size_t len;  /* Data length. Data is located between offset 0 and len. */
  size_t size; /* Buffer size allocated by realloc(1). Must be >= len */
};

void iobuf_init(struct iobuf *, size_t initial_size);
void iobuf_free(struct iobuf *);
size_t iobuf_append(struct iobuf *, const void *data, size_t data_size);
size_t iobuf_insert(struct iobuf *, size_t, const void *, size_t);
void iobuf_remove(struct iobuf *, size_t data_size);
void iobuf_resize(struct iobuf *, size_t new_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* NS_IOBUF_HEADER_INCLUDED */
