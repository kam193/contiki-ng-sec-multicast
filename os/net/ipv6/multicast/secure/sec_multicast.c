/**
 * \file
 *         This file shows the implementations of additional security layer
 *         for multicast communication.
 *
 * \author  Kamil Mańkowski
 *
 */

#include "contiki.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include "net/ipv6/multicast/secure/sec_multicast.h"
#include "net/packetbuf.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>

#include "engine.h"

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"
#include "tmp_debug.h"

static unsigned char buffer[120];

extern uint16_t uip_slen;

static void
init()
{
  SEC_MULTICAST_BASE_DRIVER.init();
}
/*---------------------------------------------------------------------------*/
static void
out(void)
{
  uint32_t data_len;
  int ret;

  memset(buffer, 0, sizeof(buffer));
  data_len = sizeof(buffer);
  ret = encrypt_message(&UIP_IP_BUF->destipaddr, &(uip_buf[UIP_IPUDPH_LEN]), uip_len - UIP_IPUDPH_LEN, buffer, &data_len);
  if(ret == 0) {
    /* Updata packet and length -> TODO: safe (check size) */
    memcpy(&uip_buf[UIP_IPUDPH_LEN], buffer, data_len);
    uip_slen = data_len;
    uip_len = UIP_IPUDPH_LEN + data_len;
    uipbuf_set_len_field(UIP_IP_BUF, uip_len - UIP_IPH_LEN);
    UIP_UDP_BUF->udplen = UIP_HTONS(data_len + UIP_UDPH_LEN);
    /* TODO: checksum */
  } else if(ret == ERR_GROUP_NOT_KNOWN) {
    PRINTF("Cert for out packet needed. Caching.\n");
    if(cache_out_packet() == ERR_LIMIT_EXCEEDED) {
      PRINTF("Waiting queue limit exceeded, packet dropped\n");
    } else {
      get_certificate_for(&UIP_IP_BUF->destipaddr);
      uip_slen = 0;
      uipbuf_clear();
      return;
    }
  } else {
    PRINTF("Encryption failed.\n");
  }

  SEC_MULTICAST_BASE_DRIVER.out();
}
/*---------------------------------------------------------------------------*/
static uint8_t
in()
{
  uint32_t data_len;
  int ret;
  uint8_t decision;

  decision = SEC_MULTICAST_BASE_DRIVER.in();

  if(decision == UIP_MCAST6_ACCEPT) {
    data_len = sizeof(buffer);
    ret = decrypt_message(&UIP_IP_BUF->destipaddr, &uip_buf[UIP_IPUDPH_LEN], uip_len - UIP_IPUDPH_LEN, buffer, &data_len);

    if(ret == 0) {
      memcpy(&uip_buf[UIP_IPUDPH_LEN], buffer, data_len);
      uip_slen = data_len;
      uip_len = UIP_IPUDPH_LEN + data_len;
      uipbuf_set_len_field(UIP_IP_BUF, uip_len - UIP_IPH_LEN);
      UIP_UDP_BUF->udplen = UIP_HTONS(data_len + UIP_UDPH_LEN);
      /* TODO: checksum */
    } else if(ret == ERR_GROUP_NOT_KNOWN) {
      PRINTF("Cert needed. Cache and request\n");
      if(queue_in_packet() == ERR_LIMIT_EXCEEDED) {
        PRINTF("Waiting IN queue limit exceeded, packet dropped\n");
      } else {
        get_certificate_for(&UIP_IP_BUF->destipaddr);
      }
      return UIP_MCAST6_DROP;
    } else {
      PRINTF("Decryption failed (%d).\n", ret);
    }
  }

  return decision;
}
/*---------------------------------------------------------------------------*/
const struct uip_mcast6_driver sec_multicast_driver = {
  "SEC_MULTICAST",
  init,
  out,
  in,
};
/*---------------------------------------------------------------------------*/
