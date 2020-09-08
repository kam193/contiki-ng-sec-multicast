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
 * 
 * This file based on the examples/multicast/root.c
 */

#include "contiki.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include "net/ipv6/multicast/secure/authorization.h"
#include "net/ipv6/multicast/secure/remote_engine.h"
#include "net/ipv6/multicast/secure/server.h"
#include "net/routing/routing.h"

#include "../certs.h"
#include "../utils.h"

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"

/*---------------------------------------------------------------------------*/
PROCESS(root_process, "ROOT");
AUTOSTART_PROCESSES(&root_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(root_process, ev, data)
{
  PROCESS_BEGIN();

  FAIL_NOT_0(auth_import_ca_cert(&ca));
  FAIL_NOT_0(auth_import_own_cert(&rp_private_cert));

  NETSTACK_ROUTING.root_start();

  FAIL_NOT_0(start_group_descriptors_server());

  SIMPRINTF("Root initialized\n");

  while(1) {
    PROCESS_YIELD();
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
