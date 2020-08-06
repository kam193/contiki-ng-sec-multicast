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
  PRINTF("%d\n", ca_pub.state);
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