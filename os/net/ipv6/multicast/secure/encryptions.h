
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

/* Coordinator processing */
int init_aes_cbc_descriptor(struct sec_certificate *descriptor);
int aes_cbc_descriptor_to_bytes(struct sec_certificate *cert, uint8_t *buff, uint32_t *size);
int aes_cbc_refresh_key(struct sec_certificate *key_descriptor);

/* Local processing */
int aes_cbc_bytes_to_descriptor(struct sec_certificate *cert, const uint8_t *data, uint16_t size);
int aes_cbc_copy_descriptor(struct sec_certificate *dest, struct sec_certificate *src);

int aes_cbc_encrypt(struct sec_certificate *cert, uint16_t message_len, unsigned char *out_buffer, uint32_t *out_len);
int aes_cbc_decrypt(struct sec_certificate *cert, unsigned char *message, uint16_t message_len, unsigned char *out_buffer, uint32_t *out_len);

#endif