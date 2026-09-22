#ifndef __DEFINES_H__
#define __DEFINES_H__

#define OUTPUTPATH "/mnt/usb0/%s.dec"
#define INPUTPATH "/mnt/usb0/safe.PS4UPDATE.PUP"

/* Shared prototype. The original source relied on an implicit declaration
 * from main.c, which modern GCC (>=14) rejects as an error. */
uint8_t GetElapsed(uint64_t ResetInterval);

/*
#define DEBUG_SOCKET
#define DEBUG_ADDR IP(192,168,1,100);
#define DEBUG_PORT 9023
*/

#endif