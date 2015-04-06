/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include <Arduino.h>
#include <stdio.h>

long long int to64(const char* str) {
  long long int res = 0;
  char negative = 0;

  while (isspace(*str)) str++;

  if (*str == '+') {
    str++;
  } else if (*str == '-') {
    negative = 1;
    str++;
  }

  while (*str >= '0' && *str <= '9') {
    res = res * 10 + (*str - '0');
    str++;
  }

  return negative ? -res : res;
}

char* strerror(int errnum) {
  /* TODO(alashkin): show real error message */
  const char frmstr[] = "Error: %d";
  static char retbuf[sizeof(frmstr) + 11];

  snprintf(retbuf, sizeof(retbuf), frmstr, errnum);
  return retbuf;
}

/*
 * Returns the number of seconds since the Arduino board
 * began running the current program.
 * So, this function
 * 1. doesn't support anything but NULL as a parameter
 * 2. suitable only to detect timeouts etc.
 * If time(NULL) is logged, result would be something
 * like "1970-01-01..." etc)
 */

time_t time(time_t* timer) {
  return millis() / 1000;
}
