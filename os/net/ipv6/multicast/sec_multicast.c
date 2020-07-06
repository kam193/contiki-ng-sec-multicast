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
#include "net/ipv6/multicast/sec_multicast.h"
#include "net/packetbuf.h"

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"

/* static char buffer[120]; / * max payload * / */

static void
init()
{
  SEC_MULTICAST_BASE_DRIVER.init();
}
/*---------------------------------------------------------------------------*/
static void
out(void)
{
  uint32_t secret = 123;
  uint32_t i;
  uint32_t data_len;

  data_len = uip_len - UIP_IPUDPH_LEN;

  for(i = 0; i < data_len; i++) {
    uip_buf[UIP_IPUDPH_LEN + i] = (uip_buf[UIP_IPUDPH_LEN + i]) ^ secret;
  }

  SEC_MULTICAST_BASE_DRIVER.out();
}
/*---------------------------------------------------------------------------*/
static uint8_t
in()
{
  uint32_t secret = 123;
  uint32_t i;
  uint32_t data_len;
  uint8_t decision;

  /* PRINTF("INPUT DATA: "); */
  /* for(i = 0; i < data_len; i++) { */
  /*   PRINTF("%u", uip_buf[UIP_IPUDPH_LEN + i]); */
  /* } */
  /* PRINTF("\n"); */

  decision = SEC_MULTICAST_BASE_DRIVER.in();

  /* Decrypt message before processing to upper layers */
  if(decision == UIP_MCAST6_ACCEPT) {
    data_len = uip_len - UIP_IPUDPH_LEN;
    for(i = 0; i < data_len; i++) {
      uip_buf[UIP_IPUDPH_LEN + i] = (uip_buf[UIP_IPUDPH_LEN + i]) ^ secret;
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
