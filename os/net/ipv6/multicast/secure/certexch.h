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

#define CE_HASH_LEN 32

#define CE_PUB_RP_CERT      1
#define CE_PUB_CLIENT_CERT  2

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
int certexch_verify_cert(struct ce_certificate *cert);

#endif
