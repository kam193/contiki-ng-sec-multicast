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
static struct secure_descriptor *
get_secure_descriptor(uip_ip6addr_t *group_addr)
{
  for(uint32_t i = 0; i < first_free; ++i) {
    if(uip_ip6addr_cmp(&group_descriptors[i].certificate.group_addr, group_addr)) {
      return group_descriptors[i].certificate.secure_descriptor;
    }
  }

  return NULL;
}
/*---------------------------------------------------------------------------*/
/* Public functions - helpers                                                */
/*---------------------------------------------------------------------------*/
int
copy_certificate(struct sec_certificate *dest, struct sec_certificate *src)
{
  /* TODO: safe allocate */
  memcpy(dest, src, sizeof(struct sec_certificate));
  if(src->mode == SEC_MODE_AES_CBC) {
    dest->secure_descriptor = malloc(sizeof(struct secure_descriptor));
    memcpy(dest->secure_descriptor, src->secure_descriptor, sizeof(struct secure_descriptor));
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
  struct secure_descriptor *current_descriptor;
  if((current_descriptor = get_secure_descriptor(dest_addr)) == NULL) {
    return -1;
  }

  Aes encryption_engine;
  if((return_code = wc_AesSetKey(&encryption_engine, current_descriptor->aes_key, AES_BLOCK_SIZE, current_descriptor->aes_vi, AES_ENCRYPTION)) != 0) {
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
decrypt_message(uip_ip6addr_t *dest_addr, unsigned char *message, uint32_t message_len,
                unsigned char *out_buffer, uint32_t *out_len)
{
  /* TODO: Data need to be aligned! */
  struct secure_descriptor *current_descriptor;
  if((current_descriptor = get_secure_descriptor(dest_addr)) == NULL) {
    return -1;
  }

  Aes encryption_engine;
  if((return_code = wc_AesSetKey(&encryption_engine, current_descriptor->aes_key, AES_BLOCK_SIZE, current_descriptor->aes_vi, AES_DECRYPTION)) != 0) {
    return return_code;
  }

  if((return_code = wc_AesCbcDecrypt(&encryption_engine, out_buffer, message, message_len)) != 0) {
    return return_code;
  }

  *out_len = message_len;
  return 0;
}