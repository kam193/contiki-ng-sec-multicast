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

#include "contiki.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include "net/ipv6/uip-ds6.h"

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"

#include "utils.h"

uip_ipaddr_t NETWORK_A = { { 0xFF, 0x1E, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x89, 0xA0, 0x0D } };
uip_ipaddr_t NETWORK_B = { { 0xFF, 0x1E, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x89, 0xAB, 0xCD } };

static char buf[MAX_PAYLOAD_LEN];

/*---------------------------------------------------------------------------*/
/* Receiving helpers */
/*---------------------------------------------------------------------------*/
uip_ds6_maddr_t *
join_mcast_group(const uip_ipaddr_t *maddr)
{
  uip_ds6_maddr_t *rv;
  uip_ipaddr_t tmp;
  const uip_ipaddr_t *default_prefix = uip_ds6_default_prefix();

  uip_ip6addr_copy(&tmp, default_prefix);
  uip_ds6_set_addr_iid(&tmp, &uip_lladdr);
  uip_ds6_addr_add(&tmp, 0, ADDR_AUTOCONF);

  rv = uip_ds6_maddr_add(maddr);

  if(rv) {
    SIMPRINTF("Joined multicast group ");
    PRINT6ADDR(&uip_ds6_maddr_lookup(maddr)->ipaddr);
    PRINTF("\n");
  }
  return rv;
}
/*---------------------------------------------------------------------------*/
void
tcpip_handler(void)
{
  if(uip_newdata()) {
    SIMPRINTF("Got: %.*s\n", uip_len, (unsigned char *)uip_appdata);
  }
  return;
}
/*---------------------------------------------------------------------------*/
/* Sending helpers */
/*---------------------------------------------------------------------------*/
void
multicast_send(struct uip_udp_conn *connection, const char message[], size_t len)
{
  SIMPRINTF("Sending message to ");
  PRINT6ADDR(&connection->ripaddr);
  PRINTF("\n");
  memset(buf, 0, MAX_PAYLOAD_LEN);
  memcpy(buf, message, len);
  uip_udp_packet_send(connection, buf, len);
}
/*---------------------------------------------------------------------------*/
void
prepare_mcast(uip_ipaddr_t *addr, struct uip_udp_conn **connection)
{
  *connection = udp_new(addr, UIP_HTONS(MCAST_SINK_UDP_PORT), NULL);
}