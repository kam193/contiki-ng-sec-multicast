/**
 * \file
 *         This file provides funtions for certificate exchange process
 *
 * \author  Kamil Mańkowski
 *
 */

#include "contiki.h"
#include "certexch.h"
#include "os/lib/heapmem.h"

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hash.h>

#include "./common.h"
#include "tmp_debug.h"

static ecc_key ca_pub;
static ecc_key own_key;
static struct ce_certificate own_pub;
static struct ce_certificate *rp_pub_cert = NULL;

int
count_cert_hash(const struct ce_certificate *cert, uint8_t *out)
{
  Sha256 sha256;
  CHECK_0(wc_InitSha256(&sha256));

  /* Count header of certificate */
  CHECK_0(wc_Sha256Update(&sha256, (uint8_t *)cert, 17));
  /* Update with pub key */
  CHECK_0(wc_Sha256Update(&sha256, cert->pub, cert->pub_len));
  CHECK_0(wc_Sha256Final(&sha256, out));

  wc_Sha256Free(&sha256);
  return 0;
}
int
copy_pub_certificate(struct ce_certificate *dest, const struct ce_certificate *src)
{
  /* TODO: checks */
  /* Copy header */
  memcpy(dest, src, 19);
  dest->priv_len = 0;

  dest->pub = malloc(dest->pub_len);
  memcpy(dest->pub, src->pub, dest->pub_len);

  dest->signature = malloc(dest->signature_len);
  memcpy(dest->signature, src->signature, dest->signature_len);

  return 0;
}
/*---------------------------------------------------------------------------*/
int
certexch_import_ca_key(const struct ca_cert *cert)
{
  CHECK_0(wc_ecc_init(&ca_pub));
  CHECK_0(wc_ecc_import_x963(cert->pub, cert->size, &ca_pub));
  return 0;
}
int
certexch_verify_cert(const struct ce_certificate *cert)
{
  /* CHECK_1(ca_pub.state != 0); // TODO: check if CA created */
  int verification_result = 0;
  uint8_t hash[32];

  CHECK_0(count_cert_hash(cert, hash));
  CHECK_0(wc_ecc_verify_hash(cert->signature, cert->signature_len, hash, 32,
                             &verification_result, &ca_pub));

  if(verification_result == 1) {
    return 0;
  }
  return -1;
}
int
certexch_import_own_cert(const struct ce_certificate *cert)
{
  CHECK_0(certexch_verify_cert(cert));
  CHECK_0(copy_pub_certificate(&own_pub, cert));

  CHECK_0(wc_ecc_init(&own_key));
  CHECK_0(wc_ecc_import_private_key(cert->priv, cert->priv_len,
                                    cert->pub, cert->pub_len,
                                    &own_key));
  return 0;
}
const struct ce_certificate *
certexch_own_pub_cert()
{
  return &own_pub;
}
int
certexch_import_rp_cert(const struct ce_certificate *cert)
{
  rp_pub_cert = malloc(sizeof(struct ce_certificate));
  return copy_pub_certificate(rp_pub_cert, cert);
}
const struct ce_certificate *
certexch_rp_pub_cert()
{
  return rp_pub_cert;
}
void
free_ce_certificate(struct ce_certificate *cert)
{
  if(cert->pub) {
    free(cert->pub);
    cert->pub = NULL;
  }
  // if(cert->priv) {
  //   free(cert->priv);
  //   cert->pub = NULL;
  // }
  if(cert->signature) {
    free(cert->signature);
    cert->pub = NULL;
  }
  cert->pub_len = 0;
  cert->signature_len = 0;
  cert->priv_len = 0;
}
/*---------------------------------------------------------------------------*/
/* ENCODING/DECODING CERTIFICATES */
/* Format is ADDR | TYPE | PUB_LEN | SIGN_LEN | *PUB | *SIGN */
/* Private part is skiped */
/*---------------------------------------------------------------------------*/
int
certexch_decode_cert(struct ce_certificate *dest_cert, const uint8_t *src_data, uint16_t src_len)
{
  uint16_t part_size = sizeof(uip_ip6addr_t) + 3;
  CHECK_1(src_len >= part_size);
  memcpy(dest_cert, src_data, sizeof(uip_ip6addr_t) + 3);

  CHECK_1(src_len >= part_size + dest_cert->pub_len + dest_cert->signature_len);
  dest_cert->pub = malloc(dest_cert->pub_len);
  memcpy(dest_cert->pub, src_data + part_size, dest_cert->pub_len);

  part_size += dest_cert->pub_len;
  dest_cert->signature = malloc(dest_cert->signature_len);
  memcpy(dest_cert->signature, src_data + part_size, dest_cert->signature_len);
  return 0;
}
/*---------------------------------------------------------------------------*/
/* Encode cert to bytes stream */
/*---------------------------------------------------------------------------*/
int
certexch_encode_cert(uint8_t *dest_data, uint16_t *dest_len, const struct ce_certificate *src_cert)
{
  uint32_t result_size = sizeof(uip_ip6addr_t) + 3; /* Header */

  if(result_size + src_cert->pub_len + src_cert->signature_len > *dest_len) {
    return -1;
  }

  memcpy(dest_data, src_cert, sizeof(uip_ip6addr_t) + 3);
  memcpy(dest_data + result_size, src_cert->pub, src_cert->pub_len);
  result_size += src_cert->pub_len;
  memcpy(dest_data + result_size, src_cert->signature, src_cert->signature_len);
  *dest_len = result_size + src_cert->signature_len;
  return 0;
}