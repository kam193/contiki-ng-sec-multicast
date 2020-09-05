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
 * \addtogroup sec-multicast
 * @{
 */
/**
 * \file
 * Contains the implementation of the multicast security layer. This catches
 * the in/out packages and pass to the local security engine, and after
 * processing it call selected multicast engine to out packet or let
 * system processing.
 *
 * \author Kamil Mańkowski <kam193@wp.pl>
 *
 */
#include "contiki.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include "net/ipv6/multicast/secure/sec_multicast.h"
#include "net/packetbuf.h"

#include "engine.h"

#include "sys/log.h"
#define LOG_MODULE  "sec_multicast"
#define LOG_LEVEL   LOG_LEVEL_SEC_MULTICAST

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
#endif
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

  LOG_DBG("Out packet detected.\n");

  if(process_outcomming_packet(&UIP_IP_BUF->destipaddr, &uip_buf[UIP_IPUDPH_LEN] + uip_ext_len, uip_len - UIP_IPUDPH_LEN - uip_ext_len, buffer, &data_len) == 0) {
    memcpy(&uip_buf[UIP_IPUDPH_LEN] + uip_ext_len, buffer, data_len);
    uip_slen = data_len;
    uip_len = UIP_IPUDPH_LEN + data_len + uip_ext_len;
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
  LOG_DBG("In packet detected.\n");

  if(mark_packet_from_cache == 1) {
    LOG_DBG("Packet comes from cache!\n");
    mark_packet_from_cache = 0;
    decision = UIP_MCAST6_ACCEPT;
  } else {
    decision = SEC_MULTICAST_BASE_DRIVER.in();
    LOG_DBG("Engine decision: %d\n", decision);
  }

  if(decision == UIP_MCAST6_ACCEPT) {
    data_len = sizeof(buffer);

    if(process_incoming_packet(&UIP_IP_BUF->destipaddr, &uip_buf[UIP_IPUDPH_LEN] + uip_ext_len, uip_len - UIP_IPUDPH_LEN - uip_ext_len, buffer, &data_len) == PROCESS_UPPER) {
      memcpy(&uip_buf[UIP_IPUDPH_LEN] + uip_ext_len, buffer, data_len);
      uip_slen = data_len;
      uip_len = UIP_IPUDPH_LEN + data_len + uip_ext_len;
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
/** @} */