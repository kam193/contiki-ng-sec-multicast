/**
 * \file
 *         This is Local Secure Functions Module. It provides the functions
 *         needed for processing secure multicas communications on end devices.
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

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"
#include "tmp_debug.h"

#include "helpers.h"
#include "engine.h"
#include "authorization.h"
#include "remote_engine.h"
#include "common_engine.h"
#include "encryptions.h"
#include "end_device.h"

static bool certexch_initialized = false;

struct sec_info {
  bool occupied;
  struct sec_certificate certificate;
};
typedef struct sec_info sec_info_t;
/* TODO: descriptors db should have an marker if field is free or not */
sec_info_t group_descriptors[SEC_MAX_GROUP_DESCRIPTORS];
uint32_t first_free = 0;

/* TODO: extract, maybe made shared buffer? */
uint8_t buffer[UIP_BUFSIZE];

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
int
decode_bytes_to_security_descriptor(struct sec_certificate *cert, const uint8_t *data, uint16_t size)
{
  uint16_t decoded = 0;
  /* Decode header */
  if(sizeof(uip_ip6addr_t) + 1 + sizeof(uint32_t) > size - decoded) {
    return -1;
  }
  memcpy(cert, data, sizeof(uip_ip6addr_t) + 1);
  decoded += sizeof(uip_ip6addr_t) + 1;
  memcpy(&cert->valid_until, data + decoded, sizeof(uint32_t));
  decoded += sizeof(uint32_t);

  switch(cert->mode) {
  case SEC_MODE_AES_CBC:
    return aes_cbc_bytes_to_descriptor(cert, data + decoded, size - decoded);
    break;

  default:
    break;
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
static void
cert_exchange_init()
{
  if(certexch_initialized) {
    return;
  }
  init_communication_service();
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
  for(size_t i = 0; i < SEC_MAX_QUEUE_SIZE; ++i) {
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
  return import_group_security_descriptor(certificate);
}
int
get_certificate_for(const uip_ip6addr_t *mcast_addr)
{
  if(NETSTACK_ROUTING.node_is_root() == 1) {
    return local_get_key(mcast_addr);
  }
  cert_exchange_init();
  return send_request_group_key(mcast_addr);
}
/*---------------------------------------------------------------------------*/
/* Private functions                                                         */
/*---------------------------------------------------------------------------*/
struct sec_certificate *
get_certificate(uip_ip6addr_t *group_addr)
{
  for(uint32_t i = 0; i < SEC_MAX_GROUP_DESCRIPTORS; ++i) {
    if(group_descriptors[i].occupied == false) {
      continue;
    }
    if(uip_ip6addr_cmp(&group_descriptors[i].certificate.group_addr, group_addr)) {
      if(group_descriptors[i].certificate.valid_until < clock_seconds()) {
        PRINTF("Group key is expired.\n");
        group_descriptors[i].occupied = false;
        return NULL;
      }
      return &group_descriptors[i].certificate;
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
  memcpy(dest, src, sizeof(struct sec_certificate));
  if(src->mode == SEC_MODE_AES_CBC) {
    return aes_cbc_copy_descriptor(dest, src);
  }
  return 0;
}
/*---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/
/* Public functions - main features                                          */
/*---------------------------------------------------------------------------*/
int
import_group_security_descriptor(struct sec_certificate *certificate)
{
  if(get_certificate(&certificate->group_addr) != NULL) {
    return ERR_GROUP_EXISTS;
  }

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
static int
encrypt_message(struct sec_certificate *cert, unsigned char *message, uint16_t message_len,
                unsigned char *out_buffer, uint32_t *out_len)
{
  /* First, we need to store a data_len in encoded data in case of any padding */
  memcpy(buffer, &message_len, sizeof(uint16_t));
  memcpy(buffer + sizeof(uint16_t), message, message_len);

  switch(cert->mode) {
  case SEC_MODE_AES_CBC:
    return aes_cbc_encrypt(cert, message_len + sizeof(uint16_t), out_buffer, out_len);

  default:
    return -1;
  }
}
/*---------------------------------------------------------------------------*/
int
process_outcomming_packet(uip_ip6addr_t *dest_addr, uint8_t *message, uint16_t message_len, uint8_t *out_buffer, uint32_t *out_len)
{
  struct sec_certificate *cert;
  if((cert = get_certificate(dest_addr)) == NULL) {
    PRINTF("Cert needed. Cache and request\n");
    if(cache_out_packet() == ERR_LIMIT_EXCEEDED) {
      PRINTF("Waiting OUT queue limit exceeded, packet dropped\n");
    } else {
      get_certificate_for(dest_addr);
    }
    return DROP_PACKET;
  }
  if(encrypt_message(cert, message, message_len, out_buffer, out_len) != 0) {
    return DROP_PACKET;
  }
  return PROCESS_UPPER;
}
/*---------------------------------------------------------------------------*/
static int
decrypt_message(struct sec_certificate *cert, uint8_t *message, uint16_t message_len,
                unsigned char *out_buffer, uint32_t *out_len)
{
  uint32_t max_length = *out_len;
  switch(cert->mode) {
  case SEC_MODE_AES_CBC:
    CHECK_0(aes_cbc_decrypt(cert, message, message_len, out_buffer, out_len));
    break;

  default:
    return -1;
  }

  /* Get len of original message and remove it from the packet */
  uint16_t original_length = *(uint16_t *)(out_buffer);
  for(size_t i = 0; i < MIN(original_length, max_length - sizeof(uint16_t)); ++i) {
    out_buffer[i] = out_buffer[i + sizeof(uint16_t)];
  }
  *out_len = MIN(original_length, max_length);
  return 0;
}
/*---------------------------------------------------------------------------*/
int
process_incoming_packet(uip_ip6addr_t *dest_addr, uint8_t *message, uint16_t message_len, uint8_t *out_buffer, uint32_t *out_len)
{
  struct sec_certificate *cert;
  if((cert = get_certificate(dest_addr)) == NULL) {
    PRINTF("Cert needed. Cache and request\n");
    if(queue_in_packet() == ERR_LIMIT_EXCEEDED) {
      PRINTF("Waiting IN queue limit exceeded, packet dropped\n");
    } else {
      get_certificate_for(dest_addr);
    }
    return DROP_PACKET;
  }
  if(decrypt_message(cert, message, message_len, out_buffer, out_len) != 0) {
    return DROP_PACKET;
  }
  return PROCESS_UPPER;
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
  in_queue[i].len = 0;
  in_queue_free += 1;
  uip_process(UIP_DATA);
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
        etimer_set(&queue_timeout, SEC_QUEUE_RETRY_TIME + RANDOMIZE());
      }
      break;

    default:
      break;
    }
  }

  PROCESS_END();
}