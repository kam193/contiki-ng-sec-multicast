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
 * \addtogroup sec-multicast-engine
 * @{
 */
/**
 * \file
 * This is Local Secure Functions Module. It provides the functions
 * needed for processing secure multicas communications on end devices.
 *
 * \author Kamil Mańkowski <kam193@wp.pl>
 *
 */

#include "contiki.h"
#include "contiki-net.h"
#include "net/packetbuf.h"
#include "net/routing/routing.h"

#include "engine.h"

#include "helpers.h"
#include "remote_engine.h"
#include "common_engine.h"
#include "end_device.h"

#include "sys/log.h"
#define LOG_MODULE  "sec_multicast"
#define LOG_LEVEL   LOG_LEVEL_SEC_MULTICAST

static bool certexch_initialized = false;

struct sec_info {
  bool occupied;
  group_security_descriptor_t certificate;
};
typedef struct sec_info sec_info_t;
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

static const secure_mode_driver_t *mode_drivers[] = { SEC_MODE_DRIVERS_PTR_LIST };

PROCESS(secure_engine, "Secure engine");

/*---------------------------------------------------------------------------*/
/* GROUP DESCRIPTORS EXCHANGE                                                */
/*---------------------------------------------------------------------------*/
int
decode_bytes_to_security_descriptor(group_security_descriptor_t *cert, const uint8_t *data, uint16_t size)
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

  const secure_mode_driver_t *driver = get_mode_driver(cert->mode);
  if(driver == NULL) {
    return ERR_UNSUPPORTED_MODE;
  }
  return driver->descriptor_from_bytes(cert, data + decoded, size - decoded);
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
  LOG_INFO("Handle local key request for ");
  LOG_6ADDR(LOG_LEVEL_INFO, mcast_addr);
  LOG_INFO("\n");
  group_security_descriptor_t *certificate;
  CHECK_0(get_group_security_descriptor(mcast_addr, &certificate));
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
group_security_descriptor_t *
get_certificate(uip_ip6addr_t *group_addr)
{
  for(uint32_t i = 0; i < SEC_MAX_GROUP_DESCRIPTORS; ++i) {
    if(group_descriptors[i].occupied == false) {
      continue;
    }
    if(uip_ip6addr_cmp(&group_descriptors[i].certificate.group_addr, group_addr)) {
      if(group_descriptors[i].certificate.valid_until <= clock_seconds()) {
        LOG_DBG("Group key is expired.\n");
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
copy_group_descriptor(group_security_descriptor_t *dest, group_security_descriptor_t *src)
{
  const secure_mode_driver_t *driver = get_mode_driver(src->mode);
  if(driver == NULL) {
    return ERR_UNSUPPORTED_MODE;
  }
  memcpy(dest, src, sizeof(group_security_descriptor_t));
  return driver->copy_descriptor(dest, src);
}
const secure_mode_driver_t *
get_mode_driver(uint8_t mode)
{
  for(size_t i = 0; i < sizeof(mode_drivers); ++i) {
    if(mode_drivers[i]->mode == mode) {
      return mode_drivers[i];
    }
  }
  return NULL;
}
/*---------------------------------------------------------------------------*/
/* Public functions - main features                                          */
/*---------------------------------------------------------------------------*/
int
import_group_security_descriptor(group_security_descriptor_t *certificate)
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
    copy_group_descriptor(&group_descriptors[current].certificate, certificate);

    LOG_DBG("Group descriptor for ");
    LOG_6ADDR(LOG_LEVEL_DBG, &certificate->group_addr);
    LOG_DBG(" is set\n");

    process_post(&secure_engine, NEW_KEY_EVENT, &certificate->group_addr);

    return 0;
  }
  LOG_ERR("No more space for group descriptors\n");
  return ERR_LIMIT_EXCEEDED;
}
/*---------------------------------------------------------------------------*/
static int
encrypt_message(group_security_descriptor_t *cert, unsigned char *message, uint16_t message_len,
                unsigned char *out_buffer, uint32_t *out_len)
{
  const secure_mode_driver_t *driver = get_mode_driver(cert->mode);
  if(driver == NULL) {
    return ERR_UNSUPPORTED_MODE;
  }
  return driver->encrypt(cert, message, message_len, out_buffer, out_len);
}
/*---------------------------------------------------------------------------*/
int
process_outcomming_packet(uip_ip6addr_t *dest_addr, uint8_t *message, uint16_t message_len, uint8_t *out_buffer, uint32_t *out_len)
{
  group_security_descriptor_t *cert;
  if((cert = get_certificate(dest_addr)) == NULL) {
    LOG_DBG("Group descriptor needed. Cache and request\n");
    if(cache_out_packet() == ERR_LIMIT_EXCEEDED) {
      LOG_ERR("Waiting OUT queue limit exceeded, packet dropped\n");
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
decrypt_message(group_security_descriptor_t *cert, uint8_t *message, uint16_t message_len,
                unsigned char *out_buffer, uint32_t *out_len)
{
  const secure_mode_driver_t *driver = get_mode_driver(cert->mode);
  if(driver == NULL) {
    return ERR_UNSUPPORTED_MODE;
  }
  CHECK_0(driver->decrypt(cert, message, message_len, out_buffer, out_len));
  return 0;
}
/*---------------------------------------------------------------------------*/
int
process_incoming_packet(uip_ip6addr_t *dest_addr, uint8_t *message, uint16_t message_len, uint8_t *out_buffer, uint32_t *out_len)
{
  group_security_descriptor_t *cert;
  if((cert = get_certificate(dest_addr)) == NULL) {
    LOG_DBG("Group descriptor needed. Cache and request\n");
    if(queue_in_packet() == ERR_LIMIT_EXCEEDED) {
      LOG_ERR("Waiting IN queue limit exceeded, packet dropped\n");
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
  LOG_DBG("Delivery queued packet. Time waiting: %d\n", clock_time() - in_queue[i].time_cached);
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
        LOG_ERR("IN packet timeouted after %d. Dropped\n", time_diff);
        in_queue[i].len = 0;
        in_queue_free++;
      } else {
        in_queue[i].retry_count++;
        LOG_DBG("Retry request (attempt %d) group key for ", in_queue[i].retry_count);
        LOG_6ADDR(LOG_LEVEL_DBG, &IN_QUEUE_ADDR(i));
        LOG_DBG("\n");
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
  LOG_DBG("Send queued packet. Time waiting: %d\n", clock_time() - out_queue[i].time_cached);
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
        LOG_ERR("OUT packet timeouted after %d. Dropped\n", time_diff);
        out_queue[i].slen = 0;
        out_queue_free++;
      } else {
        out_queue[i].retry_count++;
        LOG_DBG("Retry request (attempt %d) group key for ", out_queue[i].retry_count);
        LOG_6ADDR(LOG_LEVEL_DBG, &out_queue[i].conn->ripaddr);
        LOG_DBG("\n");
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
/** @} */