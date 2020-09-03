
#ifndef COMMON_H_
#define COMMON_H_

#include <stdlib.h>
#include "net/ipv6/uip.h"

#include "contiki.h"
#include "errors.h"

/* IS_0 if expr is 0, otherwise return -1 */
#define CHECK_0(expr)   if((expr) != 0) { return ERR_OTHER; }

#define CHECK_1(expr)   if((expr) != 1) { return ERR_OTHER; }

#define RANDOM_CHAR()   (uint8_t)(random_rand() % 256)

#define RANDOMIZE()     (random_rand() % 400) - 200

typedef void (*request_handler_t)(const uip_ipaddr_t *sender_addr,
                                  uint16_t sender_port,
                                  const uint8_t *data,
                                  uint16_t datalen);

void generate_random_chars(uint8_t *dest, size_t length);

#endif