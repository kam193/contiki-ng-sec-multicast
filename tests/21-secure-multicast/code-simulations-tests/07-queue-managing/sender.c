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

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"

static struct uip_udp_conn *mcast_net_1;

#define START_DELAY 30

/*---------------------------------------------------------------------------*/
PROCESS(sender, "Multicast Sender Network A");
AUTOSTART_PROCESSES(&sender);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(sender, ev, data)
{
  PROCESS_BEGIN();

  static struct etimer timer;

  prepare_mcast(&NETWORK_A, &mcast_net_1);

  FAIL_NOT_0(auth_import_ca_cert(&ca));
  FAIL_NOT_0(auth_import_own_cert(&c2_private_cert));
  FAIL_NOT_0(get_root_cert());

  WAIT_UNTIL_ROOT_CERT();

  /* Send a few packets to overflow queue */
  for(int i = 0; i < SEC_MAX_QUEUE_SIZE + 2; ++i) {
    multicast_send(mcast_net_1, "this_is_test", 12);
  }
  SIMPRINTF("Queue overflowed.\n");

  // Now wait until queue is empty by retry limit
  etimer_set(&timer, 10 * CLOCK_SECOND);
  PROCESS_YIELD_UNTIL(etimer_expired(&timer));

  /* Now send packets that be sent */
  for(int i = 0; i < SEC_MAX_QUEUE_SIZE + 2; ++i) {
    multicast_send(mcast_net_1, "this_is_test", 12);
  }
  SIMPRINTF("DONE\n");

  while(1) {
    PROCESS_YIELD();
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
