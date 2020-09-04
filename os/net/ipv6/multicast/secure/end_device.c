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
 * Implementation of the authorization and communication features
 * specific to use by node.
 *
 * \author Kamil Mańkowski <kam193@wp.pl>
 *
 */

#include "contiki.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include "net/routing/routing.h"

#include "end_device.h"

#include "helpers.h"
#include "engine.h"
#include "authorization.h"

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"

#define RETRY_PAUSE 1000
#define MAX_RETRY   100

static device_cert_t *rp_pub_cert = NULL;
static struct simple_udp_connection certexch_conn;
bool initialized = false;

extern uint8_t buffer[UIP_BUFSIZE];

PROCESS(getting_root_cert, "Get root cert");

/*---------------------------------------------------------------------------*/
static int
import_root_cert(const device_cert_t *cert)
{
  if(!(cert->flags & CERT_SERVER_PUB)) {
    return ERR_INCORRECT_DATA;
  }
  rp_pub_cert = malloc(sizeof(device_cert_t));
  return auth_copy_pub_cert(rp_pub_cert, cert);
}
/*---------------------------------------------------------------------------*/
static const device_cert_t *
root_pub_cert()
{
  return rp_pub_cert;
}
/*---------------------------------------------------------------------------*/
static void
rp_public_cert_answer_handler(const uip_ipaddr_t *sender_addr,
                              uint16_t sender_port,
                              const uint8_t *data,
                              uint16_t datalen)
{
  device_cert_t tmp;
  if(datalen < 3) {
    return;
  }
  if(auth_decode_cert(&tmp, data + 2, (uint16_t)(data[1])) != 0) {
    PRINTF("RP PUB decode error\n");
    return;
  }
  if(auth_verify_cert(&tmp) != 0) {
    PRINTF("RP PUB verify error\n");
    return;
  }
  import_root_cert(&tmp);
  auth_free_device_cert(&tmp);
  PRINTF("GOT RP PUB!\n");
}
/*---------------------------------------------------------------------------*/
static void
ce_answer_handler(const uip_ipaddr_t *sender_addr,
                  uint16_t sender_port,
                  const uint8_t *data,
                  uint16_t datalen)
{
  uint32_t out_size = sizeof(buffer);
  if(auth_decrypt_data(buffer, &out_size, data + 1, datalen - 1, root_pub_cert()) != 0) {
    PRINTF("Decrypting answer failed\n");
    return;
  }
  group_security_descriptor_t cert;
  if(decode_bytes_to_security_descriptor(&cert, buffer, out_size) != 0) {
    PRINTF("Decoding cert fails.\n");
    return;
  }
  import_group_security_descriptor(&cert);
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
  PRINTF("Get data %d\n", flags);

  switch(flags) {
  case GROUP_DESCRIPTOR_ANSWER:
    handler = ce_answer_handler;
    break;

  case SERVER_CERT_ANSWER:
    handler = rp_public_cert_answer_handler;
    break;

  default:
    PRINTF("CertExch: Invalid message, skipped\n");
    return;
  }
  handler(sender_addr, sender_port, data, datalen);
}
/*---------------------------------------------------------------------------*/
void
init_communication_service()
{
  if(!initialized) {
    simple_udp_register(&certexch_conn, GROUP_SEC_NODE_PORT, NULL,
                        GROUP_SEC_SERVER_PORT, cert_exchange_answer_callback);
    initialized = true;
  }
}
/*---------------------------------------------------------------------------*/
static void
send_to_coordinator(const uint8_t *data, uint16_t len)
{
  init_communication_service();
  /* TODO: wait until reachable */
  uip_ip6addr_t root_addr;
  NETSTACK_ROUTING.get_root_ipaddr(&root_addr);
  simple_udp_sendto(&certexch_conn, data, len, &root_addr);
}
/*---------------------------------------------------------------------------*/
int
send_request_group_key(const uip_ip6addr_t *mcast_addr)
{
  /* Message format: TYPE | CERT_LEN | TIMESTAMP[4] | ADDR[16] | *PUB_CERT */
  buffer[0] = GROUP_DESCRIPTOR_REQUEST;

  /* Type & cert len are not padded, timestamp+addr -> encrypted and padded */
  uint32_t padded_size = auth_count_padding(KEY_REQUEST_DATA_SIZE);
  uint8_t *tmp = malloc(padded_size);

  uint32_t timestamp = clock_seconds();
  memcpy(tmp, &timestamp, TIMESTAMP_SIZE);
  memcpy((tmp + TIMESTAMP_SIZE), mcast_addr, sizeof(uip_ip6addr_t));
  /*   memset(tmp + KEY_REQUEST_DATA_SIZE, RANDOM_CHAR(), padded_size - KEY_REQUEST_DATA_SIZE); */
  for(size_t shift = KEY_REQUEST_DATA_SIZE; shift < padded_size; ++shift) {
    *(tmp + shift) = RANDOM_CHAR();
  }

  uint32_t size = sizeof(buffer) - padded_size;
  if(auth_encrypt_data(buffer + 2, &size, tmp, padded_size, root_pub_cert()) != 0) {
    PRINTF("Encoding error\n");
    return -1;
  }
  size += 2;
  free(tmp);

  uint16_t cert_len = sizeof(buffer) - size;
  auth_encode_cert(buffer + size, &cert_len, auth_own_pub_cert());
  buffer[1] = (uint8_t)cert_len;

  send_to_coordinator(buffer, size + cert_len);
  PRINTF("CertExch: Send request for %d ", size);
  PRINT6ADDR(mcast_addr);
  PRINTF("\n");
  return 0;
}
/*---------------------------------------------------------------------------*/
int
get_root_cert()
{
  if(process_is_running(&getting_root_cert)) {
    process_exit(&getting_root_cert);
  }

  free_root_cert();

  process_start(&getting_root_cert, NULL);
  PRINTF("Starting requesting root cert\n");
  return 0;
}
/*---------------------------------------------------------------------------*/
void
free_root_cert()
{
  if(is_root_cert()) {
    free(rp_pub_cert);
    rp_pub_cert = NULL;
  }
}
/*---------------------------------------------------------------------------*/
bool
is_root_cert()
{
  return rp_pub_cert != NULL;
}
/*---------------------------------------------------------------------------*/
static void
send_root_cert_request()
{
  uint8_t data = SERVER_CERT_REQUEST;
  send_to_coordinator(&data, 1);
  PRINTF("CertExch: Send request for RP pub cert\n");
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(getting_root_cert, ev, data)
{
  static struct etimer timer;
  static int retries;

  PROCESS_BEGIN();
  retries = 0;

  /* FIRST, ensure root is reachable. This can take a quite long time */
  uip_ipaddr_t root_addr;
  while(1) {
    if(NETSTACK_ROUTING.node_is_reachable() && NETSTACK_ROUTING.get_root_ipaddr(&root_addr)) {
      break;
    }
    if(retries >= MAX_RETRY) {
      PRINTF("Cannot get root address, giving up after %d\n", retries);
      PROCESS_EXIT();
    }
    ++retries;
    etimer_set(&timer, RETRY_PAUSE + RANDOMIZE());
    PROCESS_YIELD_UNTIL(etimer_expired(&timer));
  }
  PRINTF("Root is reachable\n");

  /* Now, get the certificate */
  retries = 0;
  send_root_cert_request();
  etimer_set(&timer, RETRY_PAUSE);

  while(1) {
    PROCESS_YIELD_UNTIL(etimer_expired(&timer));
    if(is_root_cert()) {
      PRINTF("Root cert got, finishing\n");
      break;
    }
    if(retries > MAX_RETRY) {
      PRINTF("Cannot get root cert. Giving up\n");
      break;
    }
    ++retries;
    PRINTF("Sending retry %d request root cert\n", retries);
    send_root_cert_request();
    etimer_set(&timer, RETRY_PAUSE + RANDOMIZE());
  }
  PROCESS_END();
}
/** @} */