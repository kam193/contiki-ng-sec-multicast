
#ifndef ENCODINGS_H_
#define ENCODINGS_H_

#include "contiki.h"
#include <stdint.h>
#include "common_engine.h"

/******************************************************************************/
/* AES-CBC SUPPORT */

struct secure_descriptor { /* aes___ */
  unsigned char aes_key[16];
  unsigned char aes_vi[16];
};

extern const secure_mode_driver_t aes_cbc_driver;

#endif