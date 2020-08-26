
#ifndef ENCODINGS_H_
#define ENCODINGS_H_

#include "contiki.h"
#include <stdint.h>

/* Descriptors for specific types */

struct secure_descriptor {
  unsigned char aes_key[16];
  unsigned char aes_vi[16];
};

#endif