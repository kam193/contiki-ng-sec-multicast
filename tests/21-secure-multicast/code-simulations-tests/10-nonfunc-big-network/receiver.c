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

#include "../certs.h"
#include "../utils.h"

#include "../simconf.h"

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"

static struct uip_udp_conn *connection;
static clock_time_t current, tmp;

/*---------------------------------------------------------------------------*/
PROCESS(receiver, "Multicast Receiver NETWORK A");
AUTOSTART_PROCESSES(&receiver);
/*---------------------------------------------------------------------------*/
void
test_handler(void)
{
  current = clock_time();
  if(uip_newdata()) {
    if(uip_len != EXPECTED_LENGTH || memcmp(uip_appdata, guard, sizeof(guard))) {
      PRINTF("[--failed--]\n");
      return;
    }

    memcpy(&tmp, uip_appdata + sizeof(guard), sizeof(tmp));
    PRINTF("[--got--] %d (%d -> %d)\n", current - tmp, tmp, current);
  }
  return;
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(receiver, ev, data)
{
  static struct etimer timer;
  PROCESS_BEGIN();

  if(join_mcast_group(&NETWORK_A) == NULL) {
    SIMPRINTF("Failed to join multicast group\n");
    FAIL_NOT_0(0);
  }

  connection = udp_new(NULL, UIP_HTONS(0), NULL);
  udp_bind(connection, UIP_HTONS(MCAST_SINK_UDP_PORT));

  FAIL_NOT_0(auth_import_ca_cert(&ca));
  FAIL_NOT_0(auth_import_own_cert(&c3_private_cert));

  uint8_t pause = random_rand()%2000;
  etimer_set(&timer, pause);
  PROCESS_YIELD_UNTIL(etimer_expired(&timer));

  FAIL_NOT_0(get_root_cert());

  WAIT_UNTIL_ROOT_CERT();

  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      test_handler();
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
