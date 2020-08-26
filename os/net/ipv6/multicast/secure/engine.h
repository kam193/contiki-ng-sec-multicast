/**
 * \file
 *    Header for providing secure functions for messages
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
#include "errors.h"

/* Configurations and constants */

#ifndef SEC_MAX_GROUP_DESCRIPTORS
#define SEC_MAX_GROUP_DESCRIPTORS 3
#endif

#ifndef SEC_MAX_QUEUE_SIZE
#define SEC_MAX_QUEUE_SIZE 5
#endif

#define TIMESTAMP_SIZE        4
#define KEY_REQUEST_DATA_SIZE (TIMESTAMP_SIZE + sizeof(uip_ip6addr_t))

/* When retry get cert */
#ifndef SEC_QUEUE_RETRY_TIME
#define SEC_QUEUE_RETRY_TIME 300
#endif

#ifndef SEC_QUEUE_MAX_RETRY
#define SEC_QUEUE_MAX_RETRY 3
#endif

/* Encoding types */

#define SEC_MODE_NONE         0 /* TODO: implement */
#define SEC_MODE_AES_CBC      1
#define SEC_MODE_RSA_PRIV     2
#define SEC_MODE_RSA_PUB      3

/* Flags to use in certificates and/or engine */

#define SEC_FLAG_DECRYPT      (1 << 0)
#define SEC_FLAG_ENCRYPT      (1 << 1)

#define SEC_FLAG_MANUALLY_SET (1 << 2)

/* Certificate exchange constants */

#ifndef RP_CERT_SERVER_PORT
#define RP_CERT_SERVER_PORT 5050
#endif

#ifndef CERT_ANSWER_PORT
#define CERT_ANSWER_PORT 6060
#endif

#define CERT_EXCHANGE_REQUEST 1
#define CERT_EXCHANGE_ANSWER  2
#define CE_RP_PUB_REQUEST     3
#define CE_RP_PUB_ANSWER      4

/* Structures */

struct sec_certificate {
  uip_ip6addr_t group_addr;
  uint8_t mode;
  uint32_t valid_until;
  void *secure_descriptor;
};

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

/* Functions */

int add_cerificate(struct sec_certificate *certificate);

int encrypt_message(uip_ip6addr_t *dest_addr, unsigned char *message, uint32_t message_len, unsigned char *out_buffer, uint32_t *out_len);
int decrypt_message(uip_ip6addr_t *dest_addr, unsigned char *message, uint32_t message_len, unsigned char *out_buffer, uint32_t *out_len);

/* Certificate Exchange */

int get_certificate_for(uip_ip6addr_t *mcast_addr);
int get_rp_cert();

/* API for storing data in queues */
int cache_out_packet();
int queue_in_packet();

/* Helper functions */

int copy_certificate(struct sec_certificate *dest, struct sec_certificate *src);

#endif /* ENGINE_H_ */
