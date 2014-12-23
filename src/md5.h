/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#ifndef MD5_HEADER_DEFINED
#define MD5_HEADER_DEFINED

typedef struct MD5Context {
  uint32_t buf[4];
  uint32_t bits[2];
  unsigned char in[64];
} MD5_CTX;

void MD5_Init(MD5_CTX *c);
void MD5_Update(MD5_CTX *c, const unsigned char *data, size_t len);
void MD5_Final(unsigned char *md, MD5_CTX *c);

#endif
