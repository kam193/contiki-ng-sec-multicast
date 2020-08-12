/**
 * \file    Headers for Certificate Exchange
 *
 *
 * \author  Kamil Mańkowski
 *
 */

#ifndef CERTEXCH_H_
#define CERTEXCH_H_

#include "contiki.h"
#include "net/ipv6/uip.h"

#define CE_HASH_LEN 32

#define CE_PUB_RP_CERT      1
#define CE_PUB_CLIENT_CERT  2

typedef void (*request_handler_t)(const uip_ipaddr_t *sender_addr,
                                  uint16_t sender_port,
                                  const uint8_t *data,
                                  uint16_t datalen);

struct ca_cert {
  uint16_t size;
  uint8_t *pub;
};

struct ce_certificate {
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

int certexch_import_ca_key(const struct ca_cert *cert);
int certexch_verify_cert(const struct ce_certificate *cert);
int certexch_import_own_cert(const struct ce_certificate *cert);
const struct ce_certificate *certexch_own_pub_cert();

int certexch_import_rp_cert(const struct ce_certificate *cert);
const struct ce_certificate *certexch_rp_pub_cert();

int certexch_decode_cert(struct ce_certificate *dest_cert, const uint8_t *src_data, uint16_t src_len);
int certexch_encode_cert(uint8_t *dest_data, uint16_t *dest_len, const struct ce_certificate *src_cert);

int certexch_encode_data(uint8_t *dest_data, uint32_t *dest_len,
                         const uint8_t *src_data, uint32_t src_len,
                         const struct ce_certificate *receiver_pub);
int certexch_decode_data(uint8_t *dest_data, uint32_t *dest_len,
                         const uint8_t *src_data, uint32_t src_len,
                         const struct ce_certificate *sender_pub);
uint8_t certexch_count_padding(uint8_t size);

void free_ce_certificate(struct ce_certificate *cert);

#endif
