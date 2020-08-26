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
#include "net/routing/routing.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/rsa.h>

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"
#include "tmp_debug.h"

#include "common.h"
#include "engine.h"
#include "certexch.h"
#include "rp.h"

static struct simple_udp_connection certexch_conn;
static bool certexch_initialized = false;

struct sec_info {
  bool occupied;
  struct sec_certificate certificate;
};
typedef struct sec_info sec_info_t;
/* TODO: descriptors db should have an marker if field is free or not */
sec_info_t group_descriptors[SEC_MAX_GROUP_DESCRIPTORS];
uint32_t first_free = 0;
uint32_t return_code = 0;

static uint8_t buffer[1000];

extern uint16_t uip_slen;

struct waiting_out {
  clock_time_t time_cached;
  uint16_t slen;
  uint8_t retry_count;
  uint8_t data[UIP_BUFSIZE - UIP_IPUDPH_LEN];
  struct uip_udp_conn *conn;
};
typedef struct waiting_out waiting_out_t;

static waiting_out_t out_queue[SEC_MAX_QUEUE_SIZE];
static uint16_t out_queue_free = SEC_MAX_QUEUE_SIZE;

struct waiting_in {
  clock_time_t time_cached;
  uint16_t len;
  uint8_t retry_count;
  uint8_t data[UIP_BUFSIZE];
};
typedef struct waiting_in waiting_in_t;

static waiting_in_t in_queue[SEC_MAX_QUEUE_SIZE];
static uint16_t in_queue_free = SEC_MAX_QUEUE_SIZE;
#define IN_QUEUE_ADDR(i) ((struct uip_ip_hdr *)(&in_queue[i].data))->destipaddr

static struct etimer queue_timeout;
uip_ip6addr_t expected;
#define NEW_KEY_EVENT 0x61

PROCESS(secure_engine, "Secure engine");

/*---------------------------------------------------------------------------*/
/* CERTIFICATE EXCHANGE                                                      */
/*---------------------------------------------------------------------------*/
static int
decode_bytes_to_cert(struct sec_certificate *cert, const uint8_t *data, uint16_t size)
{
  uint16_t decoded = 0;
  /* Decode header */
  if(sizeof(uip_ip6addr_t) + 1 + sizeof(uint32_t) > size - decoded) {
    return -1;
  }
  memcpy(cert, data, sizeof(uip_ip6addr_t) + 1);
  decoded += sizeof(uip_ip6addr_t) + 1;
  memcpy(&cert->valid_until, data+decoded, sizeof(uint32_t));
  decoded += sizeof(uint32_t);

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
  uint32_t out_size = sizeof(buffer);
  if(certexch_decode_data(buffer, &out_size, data + 1, datalen - 1, certexch_rp_pub_cert()) != 0) {
    PRINTF("Decrypting answer failed\n");
    return;
  }
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
  process_start(&secure_engine, NULL);
  certexch_initialized = true;
}
/* Cache OUT packet and wait for group key */
int
cache_out_packet()
{
  cert_exchange_init();
  for(size_t i = 0; i < SEC_MAX_QUEUE_SIZE; ++i) {
    if(out_queue[i].slen == 0) {
      memcpy(out_queue[i].data, &uip_buf[UIP_IPUDPH_LEN], uip_slen);
      out_queue[i].conn = uip_udp_conn;
      out_queue[i].slen = uip_slen;
      out_queue[i].time_cached = clock_time();
      out_queue[i].retry_count = 0;
      out_queue_free--;
      return 0;
    }
  }
  return ERR_LIMIT_EXCEEDED;
}
/* Cache IN packet and wait for group key */
int
queue_in_packet()
{
  cert_exchange_init();
  size_t i = 0;
  for(; i < SEC_MAX_QUEUE_SIZE; ++i) {
    if(in_queue[i].len == 0) {
      memcpy(in_queue[i].data, &uip_buf, uip_len);
      in_queue[i].len = uip_len;
      in_queue[i].time_cached = clock_time();
      in_queue[i].retry_count = 0;
      in_queue_free--;
      return 0;
    }
  }
  return ERR_LIMIT_EXCEEDED;
}
static int
local_get_key(const uip_ip6addr_t *mcast_addr)
{
  PRINTF("Handle local key request for ");
  PRINT6ADDR(mcast_addr);
  PRINTF("\n");
  struct sec_certificate *certificate;
  CHECK_0(get_group_secure_description(mcast_addr, &certificate));
  return add_cerificate(certificate);
}
int
get_certificate_for(uip_ip6addr_t *mcast_addr)
{
  if(NETSTACK_ROUTING.node_is_root() == 1) {
    return local_get_key(mcast_addr);
  }

  /* Message format: TYPE | CERT_LEN | TIMESTAMP[4] | ADDR[16] | *PUB_CERT */
  cert_exchange_init();

  buffer[0] = CERT_EXCHANGE_REQUEST;

  /* Type & cert len are not padded, timestamp+addr -> encrypted and padded */
  uint32_t padded_size = certexch_count_padding(KEY_REQUEST_DATA_SIZE);
  uint8_t *tmp = malloc(padded_size);

  unsigned int timestamp = clock_seconds();
  memcpy(tmp, &timestamp, TIMESTAMP_SIZE);
  memcpy((tmp + TIMESTAMP_SIZE), mcast_addr, sizeof(uip_ip6addr_t));
  /* TODO: Padding should be random! */
  memset(tmp + KEY_REQUEST_DATA_SIZE, 0, padded_size - KEY_REQUEST_DATA_SIZE);

  uint32_t size = sizeof(buffer) - padded_size;
  if(certexch_encode_data(buffer + 2, &size, tmp, padded_size, certexch_rp_pub_cert()) != 0) {
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
  for(uint32_t i = 0; i < SEC_MAX_GROUP_DESCRIPTORS; ++i) {
    if (group_descriptors[i].occupied == false){
      continue;
    }
    if(uip_ip6addr_cmp(&group_descriptors[i].certificate.group_addr, group_addr)) {
      // if (clock_seconds() >= group_descriptors[i].certificate){

      //   return NULL;
      // }
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
  /* TODO: should be public? Rather not */
  /* TODO: check if not exists yet */

  uint32_t current;
  for(current = 0; current < SEC_MAX_GROUP_DESCRIPTORS; ++current) {
    if(group_descriptors[current].occupied == true) {
      continue;
    }
    group_descriptors[current].occupied = true;
    copy_certificate(&group_descriptors[current].certificate, certificate);

    PRINTF("Certificate for ");
    PRINT6ADDR(&certificate->group_addr);
    PRINTF(" is set\n");

    process_post(&secure_engine, NEW_KEY_EVENT, &certificate->group_addr);

    return 0;
  }
  PRINTF("No more space for cer\n");
  return ERR_LIMIT_EXCEEDED;
}
/*---------------------------------------------------------------------------*/
int
encrypt_message(uip_ip6addr_t *dest_addr, unsigned char *message, uint32_t message_len,
                unsigned char *out_buffer, uint32_t *out_len)
{
  /* TODO: Data need to be aligned! */
  struct sec_certificate *cert;
  if((cert = get_certificate(dest_addr)) == NULL) {
    return ERR_GROUP_NOT_KNOWN;
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
    return ERR_GROUP_NOT_KNOWN;
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
/*---------------------------------------------------------------------------*/
/* MANAGING QUEUE */
/*---------------------------------------------------------------------------*/

/* Delivery queued IN packet to upper layers */
static void
delivery_in_packet(size_t i)
{
  memcpy(&uip_buf, in_queue[i].data, in_queue[i].len);
  uip_len = in_queue[i].len;
  PRINTF("Delivery queued packet. Time waiting: %d\n", clock_time() - in_queue[i].time_cached);
  uip_process(UIP_DATA);
  in_queue[i].len = 0;
  in_queue_free += 1;
}
/* New group key was delivered - check if can process packets from IN queue */
static void
process_new_key_queue_in(uip_ip6addr_t *group)
{
  if(in_queue_free == SEC_MAX_QUEUE_SIZE) {
    return;
  }
  for(size_t i = 0; i < SEC_MAX_QUEUE_SIZE; ++i) {
    if(in_queue[i].len != 0 && uip_ipaddr_cmp(group, &IN_QUEUE_ADDR(i))) {
      delivery_in_packet(i);
    }
  }
}
/* Time to retry. Re-request key and remove timeouted packets, IN queue */
static void
retry_on_queue_in()
{
  if(in_queue_free == SEC_MAX_QUEUE_SIZE) {
    return;
  }

  time_t time_diff;
  for(size_t i = 0; i < SEC_MAX_QUEUE_SIZE; ++i) {
    if(in_queue[i].len == 0) {
      continue;
    }
    time_diff = clock_time() - in_queue[i].time_cached;
    if(time_diff >= (in_queue[i].retry_count + 1) * SEC_QUEUE_RETRY_TIME) {
      if(get_certificate(&IN_QUEUE_ADDR(i)) != NULL) {
        delivery_in_packet(i);
      } else if(in_queue[i].retry_count >= SEC_QUEUE_MAX_RETRY) {
        PRINTF("IN packet timeouted after %d. Dropped\n", time_diff);
        in_queue[i].len = 0;
        in_queue_free++;
      } else {
        in_queue[i].retry_count++;
        PRINTF("Retry request (attempt %d) group key for ", in_queue[i].retry_count);
        PRINT6ADDR(&IN_QUEUE_ADDR(i));
        PRINTF("\n");
        get_certificate_for(&IN_QUEUE_ADDR(i));
      }
    }
  }
}
/* Send queued OUT packet to the network */
static void
delivery_out_packet(size_t i)
{
  uip_udp_packet_send(out_queue[i].conn, out_queue[i].data, out_queue[i].slen);
  PRINTF("Send queued packet. Time waiting: %d\n", clock_time() - out_queue[i].time_cached);
  out_queue[i].slen = 0;
  out_queue_free++;
}
/* New group key delivered - check if can send packets from OUT queue */
static void
process_new_key_queue_out(uip_ip6addr_t *group)
{
  if(out_queue_free == SEC_MAX_QUEUE_SIZE) {
    return;
  }
  for(size_t i = 0; i < SEC_MAX_QUEUE_SIZE; ++i) {
    if(out_queue[i].slen != 0 && uip_ip6addr_cmp(group, &out_queue[i].conn->ripaddr)) {
      delivery_out_packet(i);
    }
  }
}
/* Time to retry. Re-request group key for OUT cached packets and clean up timeouted */
static void
retry_on_queue_out()
{
  if(out_queue_free == SEC_MAX_QUEUE_SIZE) {
    return;
  }
  time_t time_diff;
  for(size_t i = 0; i < SEC_MAX_QUEUE_SIZE; ++i) {
    if(out_queue[i].slen == 0) {
      continue;
    }
    time_diff = clock_time() - out_queue[i].time_cached;
    if(time_diff >= (out_queue[i].retry_count + 1) * SEC_QUEUE_RETRY_TIME) {
      if(get_certificate(&out_queue[i].conn->ripaddr) != NULL) {
        delivery_out_packet(i);
      } else if(out_queue[i].retry_count >= SEC_QUEUE_MAX_RETRY) {
        PRINTF("OUT packet timeouted after %d. Dropped\n", time_diff);
        out_queue[i].slen = 0;
        out_queue_free++;
      } else {
        out_queue[i].retry_count++;
        PRINTF("Retry request (attempt %d) group key for ", out_queue[i].retry_count);
        PRINT6ADDR(&out_queue[i].conn->ripaddr);
        PRINTF("\n");
        get_certificate_for(&out_queue[i].conn->ripaddr);
      }
    }
  }
}
PROCESS_THREAD(secure_engine, ev, data)
{
  PROCESS_BEGIN();
  /* TODO: close handler - free resources */

  etimer_set(&queue_timeout, SEC_QUEUE_RETRY_TIME);

  while(1) {
    PROCESS_WAIT_EVENT();
    switch(ev) {
    case NEW_KEY_EVENT:
      process_new_key_queue_in(data);
      process_new_key_queue_out(data);
      break;

    case PROCESS_EVENT_TIMER:
      if(data == &queue_timeout) {
        retry_on_queue_in();
        retry_on_queue_out();
        etimer_set(&queue_timeout, SEC_QUEUE_RETRY_TIME);
      }
      break;

    default:
      break;
    }
  }

  PROCESS_END();
}