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

#ifndef UTILS_H_
#define UTILS_H_

#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/multicast/uip-mcast6.h"

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"

#define FAIL() PRINTF("[CRITICAL]\n"); PROCESS_EXIT();
#define FAIL_NOT_0(expr) if((expr) != 0) { FAIL(); }

#define SIMPRINTF(...) PRINTF("[SIMULATION] "); PRINTF(__VA_ARGS__);

#define MAX_PAYLOAD_LEN 120
#define MCAST_SINK_UDP_PORT 3001

#define WAIT_UNTIL_ROOT_CERT() do { \
    static struct etimer _cert_waiting_timer; \
    while(1) \
    { \
      if(is_root_cert()) { \
        PRINTF("We have the root cert!\n"); \
        break; \
      } \
      etimer_set(&_cert_waiting_timer, 200); \
      PROCESS_YIELD_UNTIL(etimer_expired(&_cert_waiting_timer)); \
    } \
} while(0); \

uip_ds6_maddr_t *join_mcast_group(const uip_ipaddr_t *maddr);
void tcpip_handler(void);

void prepare_mcast(uip_ipaddr_t *addr, struct uip_udp_conn **connection);
void multicast_send(struct uip_udp_conn *connection, const char message[], size_t len);

extern uip_ipaddr_t NETWORK_A;
extern uip_ipaddr_t NETWORK_B;

#endif