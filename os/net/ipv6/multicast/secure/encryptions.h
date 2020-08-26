
#ifndef ENCODINGS_H_
#define ENCODINGS_H_

#include "contiki.h"
#include <stdint.h>

/* Descriptors for specific types */

struct secure_descriptor {
  unsigned char aes_key[16];
  unsigned char aes_vi[16];
};

/* RSA - expected 100-chars length. TODO: make checks */
struct rsa_public_descriptor {
  size_t n_length;
  size_t e_length;
  unsigned char *n;
  unsigned char *e;
};

struct rsa_private_descriptor {
  size_t key_length;
  unsigned char *key_der;
};

#endif