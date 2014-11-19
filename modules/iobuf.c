/* Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 *
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

/*
 * == IO Buffers
 */

#include "../fossa.h"
#include "internal.h"

/* Initializes an IO buffer. */
void iobuf_init(struct iobuf *iobuf, size_t initial_size) {
  iobuf->len = iobuf->size = 0;
  iobuf->buf = NULL;
  iobuf_resize(iobuf, initial_size);
}

/* Frees the space allocated for the iobuffer and resets the iobuf structure. */
void iobuf_free(struct iobuf *iobuf) {
  if (iobuf != NULL) {
    NS_FREE(iobuf->buf);
    iobuf_init(iobuf, 0);
  }
}

/*
 * Appends data to the IO buffer.
 *
 * It returns the amount of bytes appended.
 */
size_t iobuf_append(struct iobuf *io, const void *buf, size_t len) {
  char *p = NULL;

  assert(io != NULL);
  assert(io->len <= io->size);

  if (io->len + len <= io->size) {
    memcpy(io->buf + io->len, buf, len);
    io->len += len;
  } else if ((p = (char *) NS_REALLOC(io->buf, io->len + len)) != NULL) {
    io->buf = p;
    memcpy(io->buf + io->len, buf, len);
    io->len += len;
    io->size = io->len;
  } else {
    len = 0;
  }

  return len;
}

/*
 * Inserts data at the beginning of the IO buffer
 *
 * Existing data will be shifted forwards and the buffer will
 * be grown if necessary.
 * It returns the amount of bytes prepended.
 */
size_t iobuf_prepend(struct iobuf *io, const void *buf, size_t len) {
  char *p = NULL;

  assert(io != NULL);
  assert(io->len <= io->size);

  /* check overflow */
  if (~(size_t)0 - (size_t)io->buf < len)
    return 0;

  if (io->len + len <= io->size) {
    memmove(io->buf + len, io->buf, io->len);
    memcpy(io->buf, buf, len);
    io->len += len;
  } else if ((p = (char *) NS_REALLOC(io->buf, io->len + len)) != NULL) {
    io->buf = p;
    memmove(io->buf + len, io->buf, io->len);
    memcpy(io->buf, buf, len);
    io->len += len;
    io->size = io->len;
  } else {
    len = 0;
  }

  return len;
}

/* Removes `n` bytes from the beginning of the buffer. */
void iobuf_remove(struct iobuf *io, size_t n) {
  if (n > 0 && n <= io->len) {
    memmove(io->buf, io->buf + n, io->len - n);
    io->len -= n;
  }
}

/*
 * Resize an IO buffer.
 *
 * If `new_size` is smaller than buffer's `len`, the
 * resize is not performed.
 */
void iobuf_resize(struct iobuf *io, size_t new_size) {
  char *p;
  if ((new_size > io->size || (new_size < io->size && new_size >= io->len)) &&
      (p = (char *) NS_REALLOC(io->buf, new_size)) != NULL) {
    io->size = new_size;
    io->buf = p;
  }
}
