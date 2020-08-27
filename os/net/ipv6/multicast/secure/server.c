
#include "contiki.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include "net/ipv6/multicast/secure/sec_multicast.h"
#include "net/packetbuf.h"
#include "net/ipv6/simple-udp.h"
#include "os/lib/heapmem.h"
#include "lib/random.h"

#include "remote_engine.h"
#include "common_engine.h"
#include "encryptions.h"
#include "authorization.h"
#include "common.h"
#include "server.h"

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"
#include "tmp_debug.h"

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
  buffer[0] = CE_RP_PUB_ANSWER;
  if(auth_encode_cert(buffer + 2, &out_size, auth_own_pub_cert()) != 0) {
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
  device_cert_t client_cert;
  if(datalen < REQUEST_LEN_MIN) {
    PRINTF("CertExch: Invalid message, skipped\n");
    return;
  }

  uint8_t cert_len = data[1];
  if(auth_decode_cert(&client_cert, data + (datalen - cert_len), cert_len) != 0) {
    PRINTF("Decoding client cert failed\n");
    return;
  }

  if(auth_verify_cert(&client_cert) != 0) {
    PRINTF("Failed verify client cert\n");
    return;
  }

  uint8_t tmp[32];
  uint32_t out_size = sizeof(tmp);
  if(auth_decrypt_data(tmp, &out_size, data + 2, datalen - cert_len - 2, &client_cert) != 0) {
    PRINTF("Decripting failed\n");
    return;
  }

  uip_ip6addr_t mcast_addr;
  memcpy(&mcast_addr, tmp + TIMESTAMP_SIZE, sizeof(uip_ip6addr_t));

  unsigned long request_timestamp;
  memcpy(&request_timestamp, tmp, TIMESTAMP_SIZE);
  PRINTF("CertExch: GOT REQUEST FOR: ");
  PRINT6ADDR(&mcast_addr);
  PRINTF("\n");

  if(get_group_secure_description(&mcast_addr, &cert) != 0) {
    PRINTF("CertExch: Requested cert not found\n");
    return;
  }
  PRINTF("CertExch: Sending cert answer to ");
  PRINT6ADDR(sender_addr);
  PRINTF("\n");

  out_size = sizeof(second_buffer);
  memset(second_buffer, 0, out_size);
  if(encode_cert_to_byte(cert, request_timestamp, second_buffer, &out_size) != 0) {
    PRINTF("Encoding cert failed\n");
    return;
  }
  out_size = auth_count_padding(out_size);
  /* TODO: set padding to buffer */
  uint32_t response_len = sizeof(buffer) - 1;
  if(auth_encrypt_data(buffer + 1, &response_len, second_buffer, out_size, &client_cert) != 0) {
    PRINTF("Encrypt response failed\n");
    return;
  }

  buffer[0] = CERT_EXCHANGE_ANSWER;
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