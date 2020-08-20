/**
 * \file
 *         This file provides functionality needed for Randevou Point
 *
 * \author  Kamil Mańkowski
 *
 */

#include "contiki.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include "net/ipv6/multicast/secure/sec_multicast.h"
#include "net/packetbuf.h"
#include "net/ipv6/simple-udp.h"

#include "rp.h"
#include "certexch.h"
#include "common.h"

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"
#include "tmp_debug.h"

#define REQUEST_LEN_MIN 2 + 32
#define MAX_ANSWER_LENGTH 1000

static struct simple_udp_connection cert_exch;
static struct sec_certificate propagated_certs[CERTEXCH_MAX_PROPAGATED_CERTS];
static uint32_t first_free = 0;
static uint8_t buffer[MAX_ANSWER_LENGTH];
static uint8_t second_buffer[MAX_ANSWER_LENGTH];

/*---------------------------------------------------------------------------*/
static struct sec_certificate *
find_certificate(uip_ip6addr_t *addr)
{
  for(uint32_t i = 0; i < first_free; ++i) {
    if(uip_ip6addr_cmp(&propagated_certs[i].group_addr, addr)) {
      return &propagated_certs[i];
    }
  }
  return NULL;
}
/*---------------------------------------------------------------------------*/
/* Decode cert to chain of byte: ADDR | MODE | FLAGS | <descriptor> */
/* Descriptor depends of MODE and basically is a chain of fields */
/*---------------------------------------------------------------------------*/
static int
encode_cert_to_byte(struct sec_certificate *cert, uint8_t *buff, uint32_t *size)
{
  uint32_t result_size = 0;

  /* Copy header */
  if(result_size + sizeof(uip_ip6addr_t) + 2 > *size) {
    return -1;
  }
  memcpy(buff, &cert->group_addr, sizeof(uip_ip6addr_t) + 2);
  result_size += sizeof(uip_ip6addr_t) + 2;

  /* Copy descriptor depends of mode */
  switch(cert->mode) {
  case SEC_MODE_AES_CBC:
    if(result_size + sizeof(struct secure_descriptor) > *size) {
      return 1;
    }
    memcpy(buff + result_size, cert->secure_descriptor, sizeof(struct secure_descriptor));
    result_size += sizeof(struct secure_descriptor);
    break;

  case SEC_MODE_RSA_PUB:
    ;
    struct rsa_public_descriptor *desc = cert->secure_descriptor;
    if(result_size + desc->n_length + desc->e_length + 2 * sizeof(size_t) > *size) {
      return -1;
    }

    memcpy(buff + result_size, desc, 2 * sizeof(size_t));
    result_size += 2 * sizeof(size_t);

    memcpy(buff + result_size, desc->n, desc->n_length);
    result_size += desc->n_length;

    memcpy(buff + result_size, desc->e, desc->e_length);
    result_size += desc->e_length;
    break;

  default:
    return -2;
  }

  *size = result_size;
  return 0;
}
/*---------------------------------------------------------------------------*/
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
  buffer[0] = CE_RP_PUB_ANSWER;
  if(certexch_encode_cert(buffer + 2, &out_size, certexch_own_pub_cert()) != 0) {
    PRINTF("Failed encoding RP PUB\n");
    return;
  }
  buffer[1] = out_size;
  PRINTF("CertExch: Sending RP pub answer to ");
  PRINT6ADDR(sender_addr);
  PRINTF("\n");
  simple_udp_sendto(&cert_exch, buffer, out_size + 2, sender_addr);
}
/*---------------------------------------------------------------------------*/
static void
ce_request_handler(const uip_ipaddr_t *sender_addr,
                   uint16_t sender_port,
                   const uint8_t *data,
                   uint16_t datalen)
{
  struct sec_certificate *cert;
  struct ce_certificate client_cert;
  if(datalen < REQUEST_LEN_MIN) {
    PRINTF("CertExch: Invalid message, skipped\n");
    return;
  }

  uint8_t cert_len = data[1];
  if(certexch_decode_cert(&client_cert, data + (datalen - cert_len), cert_len) != 0) {
    PRINTF("Decoding client cert failed\n");
    return;
  }

  if (certexch_verify_cert(&client_cert) != 0){
    PRINTF("Failed verify client cert\n");
    return;
  }

  uint8_t tmp[32];
  uint32_t out_size = sizeof(tmp);
  if(certexch_decode_data(tmp, &out_size, data + 2, datalen - cert_len - 2, &client_cert) != 0) {
    PRINTF("Decripting failed\n");
    return;
  }

  uip_ip6addr_t mcast_addr;
  memcpy(&mcast_addr, tmp + 2, sizeof(uip_ip6addr_t));

  PRINTF("CertExch: GOT REQUEST FOR: ");
  PRINT6ADDR(&mcast_addr);
  PRINTF("\n");

  cert = find_certificate(&mcast_addr);
  if(cert == NULL) {
    PRINTF("CertExch: Requested cert not found\n");
    return;
  }
  PRINTF("CertExch: Sending cert answer to ");
  PRINT6ADDR(sender_addr);
  PRINTF("\n");

  out_size = sizeof(second_buffer);
  memset(second_buffer, 0, out_size);
  if(encode_cert_to_byte(cert, second_buffer, &out_size) != 0) {
    PRINTF("Encoding cert failed\n");
    return;
  }
  out_size = certexch_count_padding(out_size);
  // TODO: set padding to buffer
  uint32_t response_len = sizeof(buffer) - 1;
  if (certexch_encode_data(buffer+1, &response_len, second_buffer, out_size, &client_cert) != 0){
    PRINTF("Encrypt response failed\n");
    return;
  }

  buffer[0] = CERT_EXCHANGE_ANSWER;
  response_len += 1;
  simple_udp_sendto(&cert_exch, buffer, response_len, sender_addr);
  free_ce_certificate(&client_cert);
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
  case CERT_EXCHANGE_REQUEST:
    handler = ce_request_handler;
    break;

  case CE_RP_PUB_REQUEST:
    handler = rp_public_cert_request_handler;
    break;

  default:
    PRINTF("Invalid message type, skiped\n");
    return;
  }

  handler(sender_addr, sender_port, data, datalen);
}
/*---------------------------------------------------------------------------*/
int
init_cert_server()
{
  simple_udp_register(&cert_exch, RP_CERT_SERVER_PORT, NULL,
                      CERT_ANSWER_PORT, cert_request_callback);
  return 0;
}
/*---------------------------------------------------------------------------*/
int
propagate_certificate(struct sec_certificate *cert)
{
  /* TODO: check if cert for given addr not exists yet */
  if(first_free >= CERTEXCH_MAX_PROPAGATED_CERTS) {
    return -1;
  }
  if(copy_certificate(&propagated_certs[first_free++], cert) != 0) {
    PRINTF("CertExch: cannot copy cert for propagation\n");
  }
  PRINTF("CertExch: Propagate cert for ");
  PRINT6ADDR(&cert->group_addr);
  PRINTF("\n");
  return 0;
}