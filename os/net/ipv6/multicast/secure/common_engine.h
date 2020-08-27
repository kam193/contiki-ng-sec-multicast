/* TODO: HEADER */

#ifndef COMMON_ENGINE_H_
#define COMMON_ENGINE_H_

#include "contiki.h"
#include <stdint.h>

#include "net/ipv6/uip.h"

/* Encoding types */

#define SEC_MODE_NONE         0 /* TODO: implement */
#define SEC_MODE_AES_CBC      1

/* Certificate exchange constants */

#ifndef RP_CERT_SERVER_PORT
#define RP_CERT_SERVER_PORT 5050
#endif

#ifndef CERT_ANSWER_PORT
#define CERT_ANSWER_PORT 6060
#endif

#define CERT_EXCHANGE_REQUEST 1
#define CERT_EXCHANGE_ANSWER  2
#define CE_RP_PUB_REQUEST     3
#define CE_RP_PUB_ANSWER      4

#define TIMESTAMP_SIZE        4

/* Structures */

struct sec_certificate {    // group_security_descriptor
  uip_ip6addr_t group_addr;
  uint8_t mode;
  uint32_t valid_until;
  void *secure_descriptor;  // key_descriptor
};
// typdef

/* Helper functions */

int copy_certificate(struct sec_certificate *dest, struct sec_certificate *src); //-> copy_sec_descriptor

#endif