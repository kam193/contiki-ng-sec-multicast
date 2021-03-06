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

static struct uip_udp_conn *sink_conn;

static uint8_t alternative_ca_pub[] = { 0x4, 0xae, 0xe, 0x47, 0x9e, 0xe1, 0x95, 0xed, 0x1e, 0x66, 0xa8, 0x49, 0x35, 0xfd, 0xd0, 0xec, 0x4b, 0x6f, 0xd, 0xff, 0x85, 0xed, 0xdf, 0xec, 0x92, 0x43, 0x19, 0x2, 0x56, 0x48, 0x9b, 0xa3, 0x45 };
static ca_cert_t alternative_ca = { sizeof(alternative_ca_pub), alternative_ca_pub };

static uint8_t alt_pub[] = { 0x4, 0xf1, 0xfb, 0xaf, 0xae, 0x5e, 0x3c, 0x1, 0x8c, 0x69, 0x43, 0xb6, 0xa1, 0xb2, 0x85, 0xb, 0xe1, 0xd8, 0xd, 0x83, 0x5e, 0x9b, 0xcb, 0xc5, 0xe, 0x4e, 0x1b, 0xa7, 0x1f, 0xf8, 0xc3, 0x2e, 0x1c, 0x7b, 0xc4, 0xab, 0x60, 0xa8, 0x56, 0x17, 0x19 };
static uint8_t alt_priv[] = { 0x79, 0x73, 0xed, 0x3d, 0xe4, 0xc7, 0x96, 0x3e, 0xe7, 0x16, 0x8, 0xd2, 0x5, 0xeb, 0x78, 0x65, 0xd8, 0xa7, 0xa5, 0x4a };
static uint8_t alt_signature[] = { 0x30, 0x25, 0x2, 0x10, 0x2f, 0x9a, 0x12, 0xbb, 0x1a, 0x15, 0x89, 0xee, 0x83, 0x56, 0x6e, 0x24, 0xa9, 0x62, 0xf9, 0xa8, 0x2, 0x11, 0, 0x81, 0x54, 0x8e, 0xb0, 0xa0, 0x46, 0x93, 0x32, 0xc8, 0x7a, 0x19, 0xad, 0xee, 0x9e, 0x2b, 0xcd };

static device_cert_t alt_private_cert = { .owner_addr = { 0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x04, 0x4, 0x4, 0x4 },
                                          .flags = CERT_NODE_PUB,
                                          .pub_len = sizeof(alt_pub),
                                          .priv_len = sizeof(alt_priv),
                                          .signature_len = sizeof(alt_signature),
                                          .pub = alt_pub,
                                          .priv = alt_priv,
                                          .signature = alt_signature };

/*---------------------------------------------------------------------------*/
PROCESS(receiver, "Multicast Receiver NETWORK A with the wrong cert");
AUTOSTART_PROCESSES(&receiver);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(receiver, ev, data)
{
  PROCESS_BEGIN();

  if(join_mcast_group(&NETWORK_A) == NULL) {
    SIMPRINTF("Failed to join multicast group\n");
    FAIL_NOT_0(0);
  }

  sink_conn = udp_new(NULL, UIP_HTONS(0), NULL);
  udp_bind(sink_conn, UIP_HTONS(MCAST_SINK_UDP_PORT));

  /* First, use a proper CA to get root cert */
  FAIL_NOT_0(auth_import_ca_cert(&ca));
  FAIL_NOT_0(get_root_cert());

  static struct etimer timer;
  WAIT_UNTIL_ROOT_CERT();

  /* Now use a second CA and incorrect own cert */
  FAIL_NOT_0(auth_import_ca_cert(&alternative_ca));
  FAIL_NOT_0(auth_import_own_cert(&alt_private_cert));
  SIMPRINTF("Set alternative certificate\n");

  /* Timeout of waiting for messages */
  etimer_set(&timer, 100 * CLOCK_SECOND);

  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      tcpip_handler();
    } else if(ev == PROCESS_EVENT_TIMER && etimer_expired(&timer)) {
      SIMPRINTF("Timeout expired.\n");
      break;
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
