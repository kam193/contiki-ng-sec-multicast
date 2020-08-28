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
#include "end_device.h"

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"
#include "tmp_debug.h"

static unsigned char buffer[UIP_BUFSIZE];
extern uint16_t uip_slen;

static void
recalculate_udp_checksum()
{
  UIP_UDP_BUF->udpchksum = 0;

#if UIP_UDP_CHECKSUMS
  UIP_UDP_BUF->udpchksum = ~(uip_udpchksum());
  if(UIP_UDP_BUF->udpchksum == 0) {
    UIP_UDP_BUF->udpchksum = 0xffff;
  }
#endif /* UIP_UDP_CHECKSUMS */
}
/*---------------------------------------------------------------------------*/
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
  memset(buffer, 0, sizeof(buffer));
  data_len = sizeof(buffer);

  if(process_outcomming_packet(&UIP_IP_BUF->destipaddr, &(uip_buf[UIP_IPUDPH_LEN]), uip_len - UIP_IPUDPH_LEN, buffer, &data_len) == 0) {
    memcpy(&uip_buf[UIP_IPUDPH_LEN], buffer, data_len);
    uip_slen = data_len;
    uip_len = UIP_IPUDPH_LEN + data_len;
    uipbuf_set_len_field(UIP_IP_BUF, uip_len - UIP_IPH_LEN);
    UIP_UDP_BUF->udplen = UIP_HTONS(data_len + UIP_UDPH_LEN);
    recalculate_udp_checksum();
  } else {
    uip_slen = 0;
    uipbuf_clear();
    return;
  }

  SEC_MULTICAST_BASE_DRIVER.out();
}
/*---------------------------------------------------------------------------*/
static uint8_t
in()
{
  uint32_t data_len;
  uint8_t decision;

  decision = SEC_MULTICAST_BASE_DRIVER.in();

  if(decision == UIP_MCAST6_ACCEPT) {
    data_len = sizeof(buffer);

    if(process_incoming_packet(&UIP_IP_BUF->destipaddr, &uip_buf[UIP_IPUDPH_LEN], uip_len - UIP_IPUDPH_LEN, buffer, &data_len) == PROCESS_UPPER) {
      memcpy(&uip_buf[UIP_IPUDPH_LEN], buffer, data_len);
      uip_slen = data_len;
      uip_len = UIP_IPUDPH_LEN + data_len;
      uipbuf_set_len_field(UIP_IP_BUF, uip_len - UIP_IPH_LEN);
      UIP_UDP_BUF->udplen = UIP_HTONS(data_len + UIP_UDPH_LEN);
      recalculate_udp_checksum();
    } else {
      return UIP_MCAST6_DROP;
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
