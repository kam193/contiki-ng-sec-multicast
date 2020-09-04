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

#include "../certs.h"
#include "../utils.h"

#include "../simconf.h"

#include <string.h>

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"

static struct uip_udp_conn *sink_conn;
static clock_time_t current, tmp;

/*---------------------------------------------------------------------------*/
PROCESS(mcast_sink_process, "Multicast Receiver NETWORK A");
AUTOSTART_PROCESSES(&mcast_sink_process);
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
PROCESS_THREAD(mcast_sink_process, ev, data)
{
  PROCESS_BEGIN();

  if(join_mcast_group(&NETWORK_A) == NULL) {
    SIMPRINTF("Failed to join multicast group\n");
    FAIL_NOT_0(0);
  }

  sink_conn = udp_new(NULL, UIP_HTONS(0), NULL);
  udp_bind(sink_conn, UIP_HTONS(MCAST_SINK_UDP_PORT));

  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      test_handler();
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
