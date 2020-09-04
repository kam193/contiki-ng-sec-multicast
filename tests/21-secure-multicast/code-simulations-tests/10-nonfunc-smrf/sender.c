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

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"

static struct uip_udp_conn *mcast_net_1;
static char buffer[EXPECTED_LENGTH];
static clock_time_t current;

/*---------------------------------------------------------------------------*/
PROCESS(sender, "Multicast Sender Network A");
AUTOSTART_PROCESSES(&sender);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(sender, ev, data)
{
  static uint32_t sent_messages = 0;
  PROCESS_BEGIN();

  static struct etimer timer;

  prepare_mcast(&NETWORK_A, &mcast_net_1);
  
  etimer_set(&timer, START_DELAY * CLOCK_SECOND);
  while(1) {
    PROCESS_YIELD();
    if(etimer_expired(&timer)) {
      
      memcpy(buffer, guard, sizeof(guard));
      current = clock_time();
      memcpy(buffer+sizeof(guard), &current, sizeof(current));

      multicast_send(mcast_net_1, buffer, sizeof(buffer));
      PRINTF("[--note--] Send on %d\n", current);
      ++sent_messages;

      if(sent_messages >= MESSAGES) {
        break;
      }
      etimer_set(&timer, PAUSE * CLOCK_SECOND);
    }
  }

  SIMPRINTF("[DONE]\n");

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
