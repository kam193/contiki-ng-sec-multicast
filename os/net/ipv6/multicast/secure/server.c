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
 * Implementation of the Authorization and Communication Service (server part).
 *
 * \author Kamil Mańkowski <kam193@wp.pl>
 *
 */

#include "contiki.h"
#include "contiki-net.h"
#include "net/ipv6/simple-udp.h"

#include "server.h"

#include "remote_engine.h"
#include "authorization.h"
#include "helpers.h"

#include "sys/log.h"
#define LOG_MODULE  "sec_multicast"
#define LOG_LEVEL   LOG_LEVEL_SEC_MULTICAST

#define REQUEST_LEN_MIN 2 + 32
#define MAX_ANSWER_LENGTH 1000

static struct simple_udp_connection cert_exch;
static uint8_t buffer[MAX_ANSWER_LENGTH];
static uint8_t second_buffer[MAX_ANSWER_LENGTH];

static void
rp_public_cert_request_handler(const uip_ipaddr_t *sender_addr,
                               uint16_t sender_port,
                               const uint8_t *data,
                               uint16_t datalen)
{
  if(datalen != 1) {
    return;
  }
  uint16_t out_size = sizeof(buffer);
  buffer[0] = SERVER_CERT_ANSWER;
  if(auth_encode_cert(buffer + 2, &out_size, auth_own_pub_cert()) != 0) {
    LOG_ERR("Failed encoding own (root) certificate to pub\n");
    return;
  }
  buffer[1] = out_size;
  LOG_DBG("Sending root cert answer to ");
  LOG_6ADDR(LOG_LEVEL_DBG, sender_addr);
  LOG_DBG("\n");
  simple_udp_sendto(&cert_exch, buffer, out_size + 2, sender_addr);
}
/*---------------------------------------------------------------------------*/
static void
ce_request_handler(const uip_ipaddr_t *sender_addr,
                   uint16_t sender_port,
                   const uint8_t *data,
                   uint16_t datalen)
{
  group_security_descriptor_t *cert;
  device_cert_t client_cert;
  if(datalen < REQUEST_LEN_MIN) {
    LOG_ERR("Invalid message, skipped\n");
    return;
  }

  uint8_t cert_len = data[1];
  if(auth_decode_cert(&client_cert, data + (datalen - cert_len), cert_len) != 0) {
    LOG_ERR("Decoding node cert failed\n");
    return;
  }

  if(auth_verify_cert(&client_cert) != 0) {
    LOG_ERR("Failed verify node cert\n");
    return;
  }

  uint8_t tmp[32];
  uint32_t out_size = sizeof(tmp);
  if(auth_decrypt_data(tmp, &out_size, data + 2, datalen - cert_len - 2, &client_cert) != 0) {
    LOG_ERR("Decripting request from node failed\n");
    return;
  }

  uip_ip6addr_t mcast_addr;
  memcpy(&mcast_addr, tmp + TIMESTAMP_SIZE, sizeof(uip_ip6addr_t));

  unsigned long request_timestamp;
  memcpy(&request_timestamp, tmp, TIMESTAMP_SIZE);
  LOG_DBG("Got descriptor request for group: ");
  LOG_6ADDR(LOG_LEVEL_DBG, &mcast_addr);
  LOG_DBG("\n");

  if(get_group_security_descriptor(&mcast_addr, &cert) != 0) {
    LOG_ERR("Requested descriptor not found\n");
    return;
  }
  LOG_DBG("Sending descriptor answer to ");
  LOG_6ADDR(LOG_LEVEL_DBG, sender_addr);
  LOG_DBG("\n");

  out_size = sizeof(second_buffer);
  memset(second_buffer, 0, out_size);
  if(encode_security_descriptor_to_bytes(cert, request_timestamp, second_buffer, &out_size) != 0) {
    LOG_ERR("Encoding group descriptor failed\n");
    return;
  }
  out_size = auth_count_padding(out_size);
  /* TODO: set padding to buffer */
  uint32_t response_len = sizeof(buffer) - 1;
  if(auth_encrypt_data(buffer + 1, &response_len, second_buffer, out_size, &client_cert) != 0) {
    LOG_ERR("Encrypting response failed\n");
    return;
  }

  buffer[0] = GROUP_DESCRIPTOR_ANSWER;
  response_len += 1;
  simple_udp_sendto(&cert_exch, buffer, response_len, sender_addr);
  auth_free_device_cert(&client_cert);
}
/*---------------------------------------------------------------------------*/
static void
cert_request_callback(struct simple_udp_connection *c,
                      const uip_ipaddr_t *sender_addr,
                      uint16_t sender_port,
                      const uip_ipaddr_t *receiver_addr,
                      uint16_t receiver_port,
                      const uint8_t *data,
                      uint16_t datalen)
{

  request_handler_t handler;

  uint8_t type = *(data);
  switch(type) {
  case GROUP_DESCRIPTOR_REQUEST:
    handler = ce_request_handler;
    break;

  case SERVER_CERT_REQUEST:
    handler = rp_public_cert_request_handler;
    break;

  default:
    LOG_ERR("Invalid message type, skiped\n");
    return;
  }

  handler(sender_addr, sender_port, data, datalen);
}
/*---------------------------------------------------------------------------*/
int
start_group_descriptors_server()
{
  simple_udp_register(&cert_exch, GROUP_SEC_SERVER_PORT, NULL,
                      GROUP_SEC_NODE_PORT, cert_request_callback);
  return 0;
}
/** @} */