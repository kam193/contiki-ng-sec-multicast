/*
 * Copyright (c) 2020, Kamil Mańkowski
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/**
 * \addtogroup sec-multicast-auth
 * @{
 */
/**
 * \file
 * This file implements funtions for authorization based on certificates
 *
 * \author Kamil Mańkowski <kam193@wp.pl>
 *
 */

#include "contiki.h"
#include "authorization.h"
#include "os/lib/heapmem.h"

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hash.h>

#include "./helpers.h"

#include "sys/log.h"
#define LOG_MODULE  "sec_multicast"
#define LOG_LEVEL   LOG_LEVEL_SEC_MULTICAST

static ecc_key ca_pub;
static ecc_key own_key;
static device_cert_t own_pub;

int
count_cert_hash(const device_cert_t *cert, uint8_t *out)
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
auth_copy_pub_cert(device_cert_t *dest, const device_cert_t *src)
{
  /* TODO: checks */
  /* Copy header */
  memcpy(dest, src, 19);
  dest->priv_len = 0;
  dest->priv = NULL;

  dest->pub = malloc(dest->pub_len);
  memcpy(dest->pub, src->pub, dest->pub_len);

  dest->signature = malloc(dest->signature_len);
  memcpy(dest->signature, src->signature, dest->signature_len);

  return 0;
}
/*---------------------------------------------------------------------------*/
bool
is_auth_ca_cert()
{
  return wc_ecc_check_key(&ca_pub) == 0;
}
/*---------------------------------------------------------------------------*/
int
auth_import_ca_cert(const ca_cert_t *cert)
{
  CHECK_0(wc_ecc_init(&ca_pub));
  CHECK_0(wc_ecc_import_x963(cert->pub, cert->size, &ca_pub));
  return 0;
}
int
auth_verify_cert(const device_cert_t *cert)
{
  if(!is_auth_ca_cert()) {
    return ERR_NOT_INITIALIZED;
  }
  int verification_result = 0;
  uint8_t hash[CERT_HASH_LEN];

  CHECK_0(count_cert_hash(cert, hash));
  CHECK_0(wc_ecc_verify_hash(cert->signature, cert->signature_len, hash, CERT_HASH_LEN,
                             &verification_result, &ca_pub));

  if(verification_result == 1) {
    return 0;
  }
  return ERR_VERIFY_FAILED;
}
int
auth_import_own_cert(const device_cert_t *cert)
{
  CHECK_0(auth_verify_cert(cert));
  CHECK_0(auth_copy_pub_cert(&own_pub, cert));

  CHECK_0(wc_ecc_init(&own_key));
  CHECK_0(wc_ecc_import_private_key(cert->priv, cert->priv_len,
                                    cert->pub, cert->pub_len,
                                    &own_key));
  return 0;
}
const device_cert_t *
auth_own_pub_cert()
{
  if(own_pub.pub_len == 0 || wc_ecc_check_key(&own_key) != 0) {
    return NULL;
  }
  return &own_pub;
}
void
auth_free_device_cert(device_cert_t *cert)
{
  if(cert->pub) {
    free(cert->pub);
    cert->pub = NULL;
  }
  if(cert->priv) {
    free(cert->priv);
    cert->pub = NULL;
  }
  if(cert->signature) {
    free(cert->signature);
    cert->signature = NULL;
  }
  cert->pub_len = 0;
  cert->signature_len = 0;
  cert->priv_len = 0;
}
void
auth_free_service()
{
  auth_free_device_cert(&own_pub);
  wc_ecc_free(&ca_pub);
  wc_ecc_free(&own_key);
}
/*---------------------------------------------------------------------------*/
/* ENCRYPTION BASED ON CERTS */
/*---------------------------------------------------------------------------*/
uint8_t
auth_count_padding(uint8_t size)
{
  uint8_t padded_size = (size / 16) * 16;
  if(padded_size < size) {
    padded_size += 16;
  }
  return padded_size;
}
int
auth_encrypt_data(uint8_t *dest_data, uint32_t *dest_len,
                  const uint8_t *src_data, uint32_t src_len,
                  const device_cert_t *receiver_pub)
{
  if(receiver_pub == NULL) {
    return ERR_INCORRECT_DATA;
  }
  if(wc_ecc_check_key(&own_key) != 0) {
    return ERR_NOT_INITIALIZED;
  }
  ecc_key receiver;
  CHECK_0(wc_ecc_init(&receiver));
  CHECK_0(wc_ecc_import_x963(receiver_pub->pub, receiver_pub->pub_len, &receiver));
  int ret;
  ret = wc_ecc_encrypt(&own_key, &receiver, src_data, src_len, dest_data, dest_len, NULL);
  if(ret != 0) {
    LOG_ERR("Encryption error: %d\n", ret);
    return ERR_OTHER;
  }
  wc_ecc_free(&receiver);
  return 0;
}
int
auth_decrypt_data(uint8_t *dest_data, uint32_t *dest_len,
                  const uint8_t *src_data, uint32_t src_len,
                  const device_cert_t *sender_pub)
{
  if(sender_pub == NULL) {
    return ERR_INCORRECT_DATA;
  }
  if(wc_ecc_check_key(&own_key) != 0) {
    return ERR_NOT_INITIALIZED;
  }
  ecc_key sender;
  CHECK_0(wc_ecc_init(&sender));
  CHECK_0(wc_ecc_import_x963(sender_pub->pub, sender_pub->pub_len, &sender));
  int ret;
  ret = wc_ecc_decrypt(&own_key, &sender, src_data, src_len, dest_data, dest_len, NULL);
  if(ret != 0) {
    LOG_ERR("Decryption error %d\n", ret);
    return -1;
  }
  wc_ecc_free(&sender);
  return 0;
}
/*---------------------------------------------------------------------------*/
/* ENCODING/DECODING CERTIFICATES */
/* Format is ADDR | TYPE | PUB_LEN | SIGN_LEN | *PUB | *SIGN */
/* Private part is skiped */
/*---------------------------------------------------------------------------*/
int
auth_decode_cert(device_cert_t *dest_cert, const uint8_t *src_data, uint16_t src_len)
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

  dest_cert->priv_len = 0;
  dest_cert->priv = NULL;
  return 0;
}
/*---------------------------------------------------------------------------*/
/* Encode cert to bytes stream */
/*---------------------------------------------------------------------------*/
int
auth_encode_cert(uint8_t *dest_data, uint16_t *dest_len, const device_cert_t *src_cert)
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
/** @} */