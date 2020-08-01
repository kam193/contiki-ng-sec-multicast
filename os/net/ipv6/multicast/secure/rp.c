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

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"
#include "tmp_debug.h"

#define REQUEST_LEN 1 + 16
#define MAX_ANSWER_LENGTH 1000

static struct simple_udp_connection cert_exch;
static struct sec_certificate propagated_certs[CERTEXCH_MAX_PROPAGATED_CERTS];
static uint32_t first_free = 0;
static uint8_t buffer[MAX_ANSWER_LENGTH];

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
static int
send_requested_cert(struct sec_certificate *cert, const uip_ip6addr_t *dest)
{
  uint32_t size = sizeof(buffer);
  memset(buffer, 0, size);

  if(encode_cert_to_byte(cert, buffer + 1, &size) != 0) {
    PRINTF("Encoding cert failed\n");
    return -1;
  }
  buffer[0] = CERT_EXCHANGE_ANSWER;
  size += 1;
  simple_udp_sendto(&cert_exch, buffer, size, dest);
  return 0;
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
  static struct sec_certificate *cert;
  uint8_t flags = *(data);
  if(!(flags & CERT_EXCHANGE_REQUEST) || datalen != REQUEST_LEN) {
    PRINTF("CertExch: Invalid message, skipped\n");
    return;
  }

  uip_ip6addr_t mcast_addr;
  memcpy(&mcast_addr, data + 1, sizeof(uip_ip6addr_t));

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
  send_requested_cert(cert, sender_addr);
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