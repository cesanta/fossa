/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */
#include <Arduino.h>

void blink(int times, int ms) {
  static int inited = 0;
  int i;

  if (!inited) {
    DDRB |= 0x80;
    inited = 1;
  }

  for (i = 0; i < times; i++) {
    PORTB |= 0x80;
    delay(ms);
    PORTB &= 0x7F;
    delay(ms);
  }
}

extern unsigned int __heap_start;
extern void *__brkval;

struct __freelist {
  size_t sz;
  struct __freelist *nx;
};

extern struct __freelist *__flp;

int get_freelistsize() {
  struct __freelist *current;
  int total = 0;
  for (current = __flp; current; current = current->nx) {
    total += 2;
    total += (int) current->sz;
  }
  return total;
}

int get_freememsize() {
  int free_memory;
  if ((int) __brkval == 0) {
    free_memory = ((int) &free_memory) - ((int) &__heap_start);
  } else {
    free_memory = ((int) &free_memory) - ((int) __brkval);
    free_memory += get_freelistsize();
  }
  return free_memory;
}
