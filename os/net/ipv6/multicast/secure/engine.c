/**
 * \file
 *         This file provides funtions for secure communications
 *
 * \author  Kamil Mańkowski
 *
 */

#include "contiki.h"
#include "contiki-net.h"

#include "net/ipv6/multicast/uip-mcast6.h"
#include "net/ipv6/multicast/secure/sec_multicast.h"
#include "net/packetbuf.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/rsa.h>

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"

#include "engine.h"

/* TODO: descriptors db should have an marker if field is free or not */
struct sec_info group_descriptors[SEC_MAX_GROUP_DESCRIPTORS];
uint32_t first_free = 0;
uint32_t return_code = 0;

/*---------------------------------------------------------------------------*/
/* Private functions                                                         */
/*---------------------------------------------------------------------------*/
static struct sec_certificate *
get_certificate(uip_ip6addr_t *group_addr)
{
  /* TODO: check mode */
  for(uint32_t i = 0; i < first_free; ++i) {
    if(uip_ip6addr_cmp(&group_descriptors[i].certificate.group_addr, group_addr)) {
      return &group_descriptors[i].certificate;
    }
  }

  return NULL;
}
/*---------------------------------------------------------------------------*/
/* AES helpers                                                               */
/*---------------------------------------------------------------------------*/
int
aes_cbc_encrypt(struct sec_certificate *cert, unsigned char *message,
                uint32_t message_len, unsigned char *out_buffer, uint32_t *out_len)
{
  /* TODO: Data need to be aligned! */
  struct secure_descriptor *current_descriptor = cert->secure_descriptor;

  Aes encryption_engine;
  if((return_code = wc_AesSetKey(&encryption_engine, current_descriptor->aes_key,
                                 AES_BLOCK_SIZE, current_descriptor->aes_vi, AES_ENCRYPTION)) != 0) {
    return return_code;
  }

  if((return_code = wc_AesCbcEncrypt(&encryption_engine, out_buffer, message, message_len)) != 0) {
    return return_code;
  }

  *out_len = message_len;
  return 0;
}
/*---------------------------------------------------------------------------*/
int
aes_cbc_decrypt(struct sec_certificate *cert, unsigned char *message,
                uint32_t message_len, unsigned char *out_buffer, uint32_t *out_len)
{
  /* TODO: Data need to be aligned! */
  struct secure_descriptor *current_descriptor = cert->secure_descriptor;

  Aes encryption_engine;
  if((return_code = wc_AesSetKey(&encryption_engine, current_descriptor->aes_key,
                                 AES_BLOCK_SIZE, current_descriptor->aes_vi, AES_DECRYPTION)) != 0) {
    return return_code;
  }

  if((return_code = wc_AesCbcDecrypt(&encryption_engine, out_buffer, message, message_len)) != 0) {
    return return_code;
  }

  *out_len = message_len;
  return 0;
}
/*---------------------------------------------------------------------------*/
/* RSA helpers                                                               */
/*---------------------------------------------------------------------------*/
int
rsa_encrypt(struct sec_certificate *cert, unsigned char *message,
            uint32_t message_len, unsigned char *out_buffer, uint32_t *out_len)
{
  WC_RNG rng;
  RsaKey key; /* TODO: implement on load cert */
  int ret;
  struct rsa_public_descriptor *desc = cert->secure_descriptor;

  /* TODO: macro for code like this */
  if((return_code = wc_InitRng(&rng)) != 0) {
    return return_code;
  }
  if((return_code = wc_InitRsaKey(&key, NULL)) != 0) {
    return return_code;
  }
  if((return_code = wc_RsaPublicKeyDecodeRaw(desc->n, desc->n_length, desc->e, desc->e_length, &key)) != 0) {
    return return_code;
  }

  ret = wc_RsaPublicEncrypt(message, message_len, out_buffer, *out_len, &key, &rng);
  if(ret >= 0) {
    *out_len = ret;
  }

  wc_FreeRng(&rng);
  return 0;
}
/*---------------------------------------------------------------------------*/
int
rsa_decrypt(struct sec_certificate *cert, unsigned char *message,
            uint32_t message_len, unsigned char *out_buffer, uint32_t *out_len)
{
  WC_RNG rng;
  RsaKey key; /* TODO: implement on load cert */
  int ret;
  word32 key_index;
  struct rsa_private_descriptor *desc = cert->secure_descriptor;

  /* TODO: macro for code like this */
  if((return_code = wc_InitRng(&rng)) != 0) {
    return return_code;
  }
  if((return_code = wc_InitRsaKey(&key, NULL)) != 0) {
    return return_code;
  }
  key_index = 0;
  if((return_code = wc_RsaPrivateKeyDecode(desc->key_der, &key_index, &key, desc->key_length)) != 0) {
    return return_code;
  }

  key.rng = &rng;
  ret = wc_RsaPrivateDecrypt(message, message_len, out_buffer, *out_len, &key);
  if(ret >= 0) {
    *out_len = ret;
  }

  wc_FreeRng(&rng);
  return 0;
}
/*---------------------------------------------------------------------------*/
/* Public functions - helpers                                                */
/*---------------------------------------------------------------------------*/
int
copy_certificate(struct sec_certificate *dest, struct sec_certificate *src)
{
  /* TODO: safe allocate */
  /* TODO: macro for short malloc and copy */
  memcpy(dest, src, sizeof(struct sec_certificate));
  if(src->mode == SEC_MODE_AES_CBC) {
    dest->secure_descriptor = malloc(sizeof(struct secure_descriptor));
    memcpy(dest->secure_descriptor, src->secure_descriptor, sizeof(struct secure_descriptor));
  } else if(src->mode == SEC_MODE_RSA_PRIV) {
    dest->secure_descriptor = malloc(sizeof(struct rsa_private_descriptor));
    memcpy(dest->secure_descriptor, src->secure_descriptor, sizeof(struct rsa_private_descriptor));

    struct rsa_private_descriptor *src_dsc = src->secure_descriptor, *dest_dsc = dest->secure_descriptor;
    dest_dsc->key_der = malloc(sizeof(char) * dest_dsc->key_length);
    memcpy(dest_dsc->key_der, src_dsc->key_der, dest_dsc->key_length);
  } else if(src->mode == SEC_MODE_RSA_PUB) {
    dest->secure_descriptor = malloc(sizeof(struct rsa_public_descriptor));
    memcpy(dest->secure_descriptor, src->secure_descriptor, sizeof(struct rsa_public_descriptor));

    struct rsa_public_descriptor *src_dsc = src->secure_descriptor, *dest_dsc = dest->secure_descriptor;
    dest_dsc->n = malloc(sizeof(char) * dest_dsc->n_length);
    memcpy(dest_dsc->n, src_dsc->n, dest_dsc->n_length);
    dest_dsc->e = malloc(sizeof(char) * dest_dsc->e_length);
    memcpy(dest_dsc->e, src_dsc->e, dest_dsc->e_length);
  }

  return 0;
}
/*---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/
/* Public functions - main features                                          */
/*---------------------------------------------------------------------------*/
int
add_cerificate(struct sec_certificate *certificate)
{
  uint32_t current;
  if(first_free >= SEC_MAX_GROUP_DESCRIPTORS) {
    return -1;
  }

  current = first_free++;
  group_descriptors[current].flags = SEC_FLAG_MANUALLY_SET;
  copy_certificate(&group_descriptors[current].certificate, certificate);

  PRINTF("Certificate for ");
  PRINT6ADDR(&certificate->group_addr);
  PRINTF(" is set\n");

  return 0;
}
/*---------------------------------------------------------------------------*/
int
encrypt_message(uip_ip6addr_t *dest_addr, unsigned char *message, uint32_t message_len,
                unsigned char *out_buffer, uint32_t *out_len)
{
  /* TODO: Data need to be aligned! */
  struct sec_certificate *cert;
  if((cert = get_certificate(dest_addr)) == NULL) {
    return -1;
  }

  switch(cert->mode) {
  case SEC_MODE_AES_CBC:
    return aes_cbc_encrypt(cert, message, message_len, out_buffer, out_len);
  case SEC_MODE_RSA_PUB:
    return rsa_encrypt(cert, message, message_len, out_buffer, out_len);

  default:
    return -1;
  }
}
/*---------------------------------------------------------------------------*/
int
decrypt_message(uip_ip6addr_t *dest_addr, unsigned char *message, uint32_t message_len,
                unsigned char *out_buffer, uint32_t *out_len)
{
  /* TODO: Data need to be aligned! */
  struct sec_certificate *cert;
  if((cert = get_certificate(dest_addr)) == NULL) {
    return -1;
  }

  switch(cert->mode) {
  case SEC_MODE_AES_CBC:
    return aes_cbc_decrypt(cert, message, message_len, out_buffer, out_len);
  case SEC_MODE_RSA_PRIV:
    return rsa_decrypt(cert, message, message_len, out_buffer, out_len);

  default:
    return -1;
  }
}