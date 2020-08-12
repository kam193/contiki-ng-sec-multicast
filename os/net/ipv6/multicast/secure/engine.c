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
#include "net/routing/rpl-classic/rpl.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/rsa.h>

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"
#include "tmp_debug.h"

#include "engine.h"
#include "certexch.h"

static struct simple_udp_connection certexch_conn;
static bool certexch_initialized = false;

/* TODO: descriptors db should have an marker if field is free or not */
struct sec_info group_descriptors[SEC_MAX_GROUP_DESCRIPTORS];
uint32_t first_free = 0;
uint32_t return_code = 0;

static uint8_t buffer[1000];

/*---------------------------------------------------------------------------*/
/* CERTIFICATE EXCHANGE                                                      */
/*---------------------------------------------------------------------------*/
static int
decode_bytes_to_cert(struct sec_certificate *cert, const uint8_t *data, uint16_t size)
{
  uint16_t decoded = 0;
  /* Decode header */
  if(sizeof(uip_ip6addr_t) + 2 > size - decoded) {
    return -1;
  }
  memcpy(cert, data, sizeof(uip_ip6addr_t) + 2);
  decoded += sizeof(uip_ip6addr_t) + 2;

  switch(cert->mode) {
  case SEC_MODE_AES_CBC:
    if(sizeof(struct secure_descriptor) > size - decoded) {
      return -1;
    }
    cert->secure_descriptor = malloc(sizeof(struct secure_descriptor)); /* TODO: check */
    memcpy(cert->secure_descriptor, data + decoded, sizeof(struct secure_descriptor));
    decoded += sizeof(struct secure_descriptor);
    break;

  case SEC_MODE_RSA_PUB:
    if(2 * sizeof(size_t) > size - decoded) {
      return -1;
    }
    cert->secure_descriptor = malloc(sizeof(struct rsa_public_descriptor)); /* TODO: check */
    struct rsa_public_descriptor *desc = cert->secure_descriptor;

    memcpy(desc, data + decoded, 2 * sizeof(size_t));
    decoded += 2 * sizeof(size_t);

    if(desc->n_length + desc->e_length > size - decoded) {
      return -1;
    }

    desc->n = malloc(desc->n_length); /* TODO: Check */
    memcpy(desc->n, data + decoded, desc->n_length);
    decoded += desc->n_length;

    desc->e = malloc(desc->e_length); /* TODO: Check */
    memcpy(desc->e, data + decoded, desc->e_length);
    decoded += desc->e_length;
    break;

  default:
    break;
  }

  // if(decoded != size) {
  //   PRINTF("Invalid decoding. Size %u vs. decoded %u\n", size, decoded);
  //   return -2;
  // }
  return 0;
}
/*---------------------------------------------------------------------------*/
static void
rp_public_cert_answer_handler(const uip_ipaddr_t *sender_addr,
                              uint16_t sender_port,
                              const uint8_t *data,
                              uint16_t datalen)
{
  struct ce_certificate tmp;
  if(datalen < 3) {
    return;
  }
  uint16_t cert_len = (uint16_t)(data[1]);
  PRINTF("Pub len %d\n", cert_len);
  print_hex(datalen, data);
  if(certexch_decode_cert(&tmp, data + 2, (uint16_t)(data[1])) != 0) {
    PRINTF("RP PUB decode error\n");

    return;
  }
  if(certexch_verify_cert(&tmp) != 0) {
    PRINTF("RP PUB verify error\n");

    return;
  }
  certexch_import_rp_cert(&tmp);
  free_ce_certificate(&tmp);
  PRINTF("GOT RP PUB!\n");
}
/*---------------------------------------------------------------------------*/
static void
ce_answer_handler(const uip_ipaddr_t *sender_addr,
                  uint16_t sender_port,
                  const uint8_t *data,
                  uint16_t datalen)
{
  /* TODO: allocate and free temporary cert */
  print_hex(datalen, data);
  uint32_t out_size = sizeof(buffer);
  if(certexch_decode_data(buffer, &out_size, data+1, datalen-1, certexch_rp_pub_cert()) != 0){
    PRINTF("Decrypting answer failed\n");
    return;
  }
  print_hex(out_size, buffer);
  struct sec_certificate cert;
  if(decode_bytes_to_cert(&cert, buffer, out_size) != 0) {
    PRINTF("Decoding cert fails.\n");
    return;
  }
  add_cerificate(&cert);
}
static void
cert_exchange_answer_callback(struct simple_udp_connection *c,
                              const uip_ipaddr_t *sender_addr,
                              uint16_t sender_port,
                              const uip_ipaddr_t *receiver_addr,
                              uint16_t receiver_port,
                              const uint8_t *data,
                              uint16_t datalen)
{
  request_handler_t handler;

  /* TODO: max data len */
  uint8_t flags = *(data);

  switch(flags) {
  case CERT_EXCHANGE_ANSWER:
    handler = ce_answer_handler;
    break;

  case CE_RP_PUB_ANSWER:
    handler = rp_public_cert_answer_handler;
    break;

  default:
    PRINTF("CertExch: Invalid message, skipped\n");
    return;
  }
  handler(sender_addr, sender_port, data, datalen);
}
static void
cert_exchange_init()
{
  if(certexch_initialized) {
    return;
  }

  simple_udp_register(&certexch_conn, CERT_ANSWER_PORT, NULL,
                      RP_CERT_SERVER_PORT, cert_exchange_answer_callback);
  certexch_initialized = true;
}
int
get_certificate_for(uip_ip6addr_t *mcast_addr)
{
  /* Message format: TYPE | CERT_LEN | TIMESTAMP[2] | ADDR[16] | *PUB_CERT */
  /* TODO: Retry and timeout */
  cert_exchange_init();
  
  buffer[0] = CERT_EXCHANGE_REQUEST;
  
  /* Type & cert len are not padded, timestamp+addr -> encrypted and padded */
  uint32_t padded_size = certexch_count_padding(2 + sizeof(uip_ip6addr_t));
  uint8_t *tmp = malloc(padded_size);
  
  memcpy((tmp + 2), mcast_addr, sizeof(uip_ip6addr_t));
  /* TODO: Padding should be random! */
  memset(tmp + 2 + sizeof(uip_ip6addr_t), 0, padded_size - 2 - sizeof(uip_ip6addr_t));

  uint32_t size = sizeof(buffer) - padded_size;
  if(certexch_encode_data(buffer+2, &size, tmp, padded_size, certexch_rp_pub_cert()) != 0){
    PRINTF("Encoding error\n");
    return -1;
  }
  size += 2;
  free(tmp);

  uint16_t cert_len = sizeof(buffer) - size;
  certexch_encode_cert(buffer + size, &cert_len, certexch_own_pub_cert());
  buffer[1] = (uint8_t)cert_len;

  /* TODO: wait until reachable */
  uip_ip6addr_t root_addr;
  NETSTACK_ROUTING.get_root_ipaddr(&root_addr);

  /* TODO: Am I root? */
  simple_udp_sendto(&certexch_conn, buffer, size + cert_len, &root_addr);
  PRINTF("CertExch: Send request for %d ", size);
  PRINT6ADDR(mcast_addr);
  PRINTF("\n");
  return 0;
}
int
get_rp_cert()
{
  cert_exchange_init();
  uint8_t data = CE_RP_PUB_REQUEST;

  /* TODO: wait until reachable */
  uip_ip6addr_t root_addr;
  NETSTACK_ROUTING.get_root_ipaddr(&root_addr);

  /* TODO: Am I root? */
  simple_udp_sendto(&certexch_conn, &data, 1, &root_addr);
  PRINTF("CertExch: Send request for RP pub cert\n");
  return 0;
}
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
    PRINTF("No more space for cer\n");
    return -1;
  }
  /* TODO: check if not exists yet */

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