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

ecc_key ca_pub;
ecc_key own_key;
struct ce_certificate own_pub;

int
count_cert_hash(struct ce_certificate *cert, uint8_t *out)
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
copy_pub_certificate(struct ce_certificate *dest, struct ce_certificate *src)
{
  /* TODO: checks */
  /* Copy header */
  memcpy(dest, src, 17);
  dest->priv_len = 0;

  dest->pub = heapmem_realloc(dest->pub, dest->pub_len);
  memcpy(dest->pub, src->pub, dest->pub_len);

  dest->signature = heapmem_realloc(dest->signature, dest->signature_len);
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
certexch_verify_cert(struct ce_certificate *cert)
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
certexch_import_own_cert(struct ce_certificate *cert)
{
  CHECK_0(certexch_verify_cert(cert));
  CHECK_0(copy_pub_certificate(&own_pub, cert));

  CHECK_0(wc_ecc_init(&own_key));
  CHECK_0(wc_ecc_import_private_key(cert->priv, cert->priv_len,
                                    cert->pub, cert->pub_len,
                                    &own_key));
  return 0;
}