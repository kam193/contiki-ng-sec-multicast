/* This file is temporary only for developing time and should be removed before release */

#ifndef TMP_DEBUG_H_
#define TMP_DEBUG_H_

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"

void
check(int code, char desc[])
{
  if(code != 0) {
    PRINTF("ERROR: %d! In: %s\n", code, desc);
    /* exit(code); */
  }
}
void
print_chars(int len, unsigned char buffer[])
{
  PRINTF("Out: %i    ", len);
  /* for(int i = 0; i < len; i++) { */
  /*   PRINTF("%c", buffer[i]); */
  /* } */
  PRINTF("%.*s", len, buffer);
  PRINTF("\n");
}
#endif