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

/* Structures */

struct secure_descriptor {
  unsigned char aes_key[16];
  unsigned char aes_vi[16];
};

struct sec_group_descriptor {
  uip_ip6addr_t group_addr;
  struct secure_descriptor secure_descr;
};

/* Functions */

int set_secure_descriptor(uip_ip6addr_t *group_addr, struct secure_descriptor *descriptor);
int encrypt_message(uip_ip6addr_t *dest_addr, unsigned char *message, uint32_t message_len, unsigned char *out_buffer, uint32_t *out_len);
int decrypt_message(uip_ip6addr_t *dest_addr, unsigned char *message, uint32_t message_len, unsigned char *out_buffer, uint32_t *out_len);

#endif /* ENGINE_H_ */
