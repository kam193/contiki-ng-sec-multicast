/**
 * \file    Header for providing secure functions for messages
 *
 *
 * \author  Kamil Mańkowski
 *
 */

#ifndef ENGINE_H_
#define ENGINE_H_

#include "contiki.h"
#include <stdint.h>

#include "net/ipv6/uip.h"

/* Configurations and constants */

#ifndef SEC_MAX_GROUP_DESCRIPTORS
#define SEC_MAX_GROUP_DESCRIPTORS 3
#endif

/* Encoding types */

#define SEC_MODE_NONE         0 /* TODO: implement */
#define SEC_MODE_AES_CBC      1

/* Flags to use in certificates and/or engine */

#define SEC_FLAG_DECRYPT      (1 << 0)
#define SEC_FLAG_ENCRYPT      (1 << 1)
#define SEC_FLAG_MANUALLY_SET (1 << 2)

/* Structures */

struct sec_certificate {
  uip_ip6addr_t group_addr;
  uint8_t mode;
  uint8_t flags;
  void *secure_descriptor;
};

struct secure_descriptor {
  unsigned char aes_key[16];
  unsigned char aes_vi[16];
};

struct sec_info {
  uint8_t flags;
  struct sec_certificate certificate;
};

/* Functions */

int add_cerificate(struct sec_certificate *certificate);
int encrypt_message(uip_ip6addr_t *dest_addr, unsigned char *message, uint32_t message_len, unsigned char *out_buffer, uint32_t *out_len);
int decrypt_message(uip_ip6addr_t *dest_addr, unsigned char *message, uint32_t message_len, unsigned char *out_buffer, uint32_t *out_len);

/* Helper functions */

int copy_certificate(struct sec_certificate *dest, struct sec_certificate *src);

#endif /* ENGINE_H_ */
