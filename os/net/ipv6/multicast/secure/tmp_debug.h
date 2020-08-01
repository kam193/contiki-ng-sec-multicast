/* This file is temporary only for developing time and should be removed before release */

#ifndef TMP_DEBUG_H_
#define TMP_DEBUG_H_

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"

void check(int code, char desc[]);
void print_chars(int len, const unsigned char buffer[]);
void print_hex(int len, const unsigned char buffer[]);

#endif