/**
 * \file
 *    Headers for Authorization Service (authorization part).
 *
 *
 * \author  Kamil Mańkowski
 *
 */

#ifndef AUTHORIZATION_H_
#define AUTHORIZATION_H_

#include "contiki.h"
#include "net/ipv6/uip.h"

#define CERT_HASH_LEN 32

#define CE_SERVER_PUB       1
#define CE_NODE_PUB         2

struct ca_cert {
  uint16_t size;
  uint8_t *pub;
};
typedef struct ca_cert ca_cert_t;

struct device_cert {
  uint8_t owner_addr[16];
  uint8_t flags;
  uint8_t pub_len;
  uint8_t signature_len;
  uint8_t *pub;
  uint8_t *signature;
  /* Optional private data */
  uint8_t priv_len;
  uint8_t *priv;
};
typedef struct device_cert device_cert_t;

int auth_import_ca_cert(const ca_cert_t *cert);
int auth_verify_cert(const device_cert_t *cert);
int auth_import_own_cert(const device_cert_t *cert);
const device_cert_t *auth_own_pub_cert();
bool is_auth_ca_cert();

int auth_decode_cert(device_cert_t *dest_cert, const uint8_t *src_data, uint16_t src_len);
int auth_encode_cert(uint8_t *dest_data, uint16_t *dest_len, const device_cert_t *src_cert);

int auth_encrypt_data(uint8_t *dest_data, uint32_t *dest_len,
                         const uint8_t *src_data, uint32_t src_len,
                         const device_cert_t *receiver_pub);
int auth_decrypt_data(uint8_t *dest_data, uint32_t *dest_len,
                         const uint8_t *src_data, uint32_t src_len,
                         const device_cert_t *sender_pub);
uint8_t auth_count_padding(uint8_t size);

int auth_copy_pub_cert(device_cert_t *dest, const device_cert_t *src);

void auth_free_device_cert(device_cert_t *cert);
void auth_free_service();

#endif
