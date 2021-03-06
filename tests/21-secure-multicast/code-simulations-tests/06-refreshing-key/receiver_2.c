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
#include "net/ipv6/multicast/secure/engine.h"
#include "net/ipv6/multicast/secure/end_device.h"
#include "sys/clock.h"

#include "../certs.h"
#include "../utils.h"

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"

static struct uip_udp_conn *sink_conn;

/* An access to the non-public function due to not possible clock set */
group_security_descriptor_t *get_certificate(uip_ip6addr_t *group_addr);

static group_security_descriptor_t tmp;

/*---------------------------------------------------------------------------*/
PROCESS(receivrer, "Multicast Receiver NETWORK A");
AUTOSTART_PROCESSES(&receivrer);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(receivrer, ev, data)
{
  static struct etimer timer;
  PROCESS_BEGIN();

  if(join_mcast_group(&NETWORK_A) == NULL) {
    SIMPRINTF("Failed to join multicast group\n");
    FAIL_NOT_0(0);
  }

  sink_conn = udp_new(NULL, UIP_HTONS(0), NULL);
  udp_bind(sink_conn, UIP_HTONS(MCAST_SINK_UDP_PORT));

  FAIL_NOT_0(auth_import_ca_cert(&ca));
  FAIL_NOT_0(auth_import_own_cert(&c4_private_cert));
  FAIL_NOT_0(get_root_cert());

  WAIT_UNTIL_ROOT_CERT();

  PROCESS_YIELD_UNTIL(ev == tcpip_event);
  tcpip_handler();

  /*clock_set_seconds(clock_seconds() - 5); - this function is not supported in the simulator */

  /* Now do a magic to reuse the same key in the future */
  group_security_descriptor_t *cert = get_certificate(&NETWORK_A);
  FAIL_NOT_0(copy_group_descriptor(&tmp, cert));

  etimer_set(&timer, (cert->valid_until - clock_seconds() + 1) * CLOCK_SECOND);
  tmp.valid_until = clock_seconds() + 20;
  PROCESS_YIELD_UNTIL(etimer_expired(&timer));
  import_group_security_descriptor(&tmp);

  etimer_set(&timer, 20 * CLOCK_SECOND);

  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      tcpip_handler();
    } else if (ev == PROCESS_EVENT_TIMER && etimer_expired(&timer))
    {
      SIMPRINTF("Timeout\n");
      break;
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
