/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#ifndef AVRDEBUG_HEADER_INCLUDED
#define AVRDEBUG_HEADER_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif
/* Blinks ($times) times with ($ms) delay */
void blink(int times, int ms);

/* Returns free meory size */
int get_freememsize();

#if defined(AVR_ENABLE_DEBUG) && defined(AVR_ENABLE_DEBUG_FUNC)

#define DUMPINIT() Serial.begin(9600)
#define DUMPSTR(msg) Serial.println(msg)
#define DUMPDEC(num) Serial.println(num, DEC)
#define DUMPFREEMEM()         \
  Serial.print("Free mem: "); \
  Serial.println(get_freememsize())

#define DUMPFUNCNAME() Serial.println(__func__)

#define BLINK(t, m) blink(t, m);

#else

#define DUMPINIT()
#define DUMPFUNCNAME()
#define DUMPFREEMEM()
#define BLINK(t, m)
#define DUMPSTR(msg)
#define DUMPDEC(num)

#endif

#ifdef __cplusplus
}
#endif

#endif /* NS_AVRDEBUG_HEADER_INCLUDED */
