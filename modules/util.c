// Copyright (c) 2014 Cesanta Software Limited
// All rights reserved

#include "net_skeleton.h"
#include "util.h"

const char *ns_skip(const char *s, const char *end,
                    const char *delims, struct ns_str *v) {
  v->p = s;
  while (s < end && strchr(delims, * (unsigned char *) s) == NULL) s++;
  v->len = s - v->p;
  while (s < end && strchr(delims, * (unsigned char *) s) != NULL) s++;
  return s;
}

static int lowercase(const char *s) {
  return tolower(* (const unsigned char *) s);
}

int ns_ncasecmp(const char *s1, const char *s2, size_t len) {
  int diff = 0;

  if (len > 0)
    do {
      diff = lowercase(s1++) - lowercase(s2++);
    } while (diff == 0 && s1[-1] != '\0' && --len > 0);

  return diff;
}

int ns_vcasecmp(const struct ns_str *str2, const char *str1) {
  size_t n1 = strlen(str1), n2 = str2->len;
  return n1 == n2 ? ns_ncasecmp(str1, str2->p, n1) : n1 > n2 ? 1 : -1;
}

int ns_vcmp(const struct ns_str *str2, const char *str1) {
  size_t n1 = strlen(str1), n2 = str2->len;
  return n1 == n2 ? memcmp(str1, str2->p, n2) : n1 > n2 ? 1 : -1;
}

void ns_base64_encode(const unsigned char *src, int src_len, char *dst) {
  static const char *b64 =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  int i, j, a, b, c;

  for (i = j = 0; i < src_len; i += 3) {
    a = src[i];
    b = i + 1 >= src_len ? 0 : src[i + 1];
    c = i + 2 >= src_len ? 0 : src[i + 2];

    dst[j++] = b64[a >> 2];
    dst[j++] = b64[((a & 3) << 4) | (b >> 4)];
    if (i + 1 < src_len) {
      dst[j++] = b64[(b & 15) << 2 | (c >> 6)];
    }
    if (i + 2 < src_len) {
      dst[j++] = b64[c & 63];
    }
  }
  while (j % 4 != 0) {
    dst[j++] = '=';
  }
  dst[j++] = '\0';
}

// Convert one byte of encoded base64 input stream to 6-bit chunk
static unsigned char from_b64(unsigned char ch) {
  // Inverse lookup map
  static const unsigned char tab[128] = {
    255, 255, 255, 255, 255, 255, 255, 255, //  0
    255, 255, 255, 255, 255, 255, 255, 255, //  8
    255, 255, 255, 255, 255, 255, 255, 255, //  16
    255, 255, 255, 255, 255, 255, 255, 255, //  24
    255, 255, 255, 255, 255, 255, 255, 255, //  32
    255, 255, 255,  62, 255, 255, 255,  63, //  40
     52,  53,  54,  55,  56,  57,  58,  59, //  48
     60,  61, 255, 255, 255, 200, 255, 255, //  56   '=' is 200, on index 61
    255,   0,   1,   2,   3,   4,   5,   6, //  64
      7,   8,   9,  10,  11,  12,  13,  14, //  72
     15,  16,  17,  18,  19,  20,  21,  22, //  80
     23,  24,  25, 255, 255, 255, 255, 255, //  88
    255,  26,  27,  28,  29,  30,  31,  32, //  96
     33,  34,  35,  36,  37,  38,  39,  40, //  104
     41,  42,  43,  44,  45,  46,  47,  48, //  112
     49,  50,  51, 255, 255, 255, 255, 255, //  120
  };
  return tab[ch & 127];
}

void ns_base64_decode(const unsigned char *s, int len, char *dst) {
  unsigned char a, b, c, d;
  while (len >= 4 &&
         (a = from_b64(s[0])) != 255 &&
         (b = from_b64(s[1])) != 255 &&
         (c = from_b64(s[2])) != 255 &&
         (d = from_b64(s[3])) != 255) {
    if (a == 200 || b == 200) break;  // '=' can't be there
    *dst++ = a << 2 | b >> 4;
    if (c == 200) break;
    *dst++ = b << 4 | c >> 2;
    if (d == 200) break;
    *dst++ = c << 6 | d;
    s += 4;
    len -=4;
  }
  *dst = 0;
}
