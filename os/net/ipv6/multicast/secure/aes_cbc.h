
#ifndef AES_CBC_H_
#define AES_CBC_H_

#include "contiki.h"
#include <stdint.h>
#include "common_engine.h"

/* AES-CBC DRIVER */

struct secure_descriptor { /* aes___ */
  unsigned char aes_key[16];
  unsigned char aes_vi[16];
};

extern const secure_mode_driver_t aes_cbc_driver;

#endif