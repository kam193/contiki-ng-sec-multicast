/*
 * Copyright (c) 2020, Kamil Mańkowski
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
#include "os/net/ipv6/multicast/secure/authorization.h"
#include "os/net/ipv6/multicast/secure/engine.h"

#include <stdio.h>

#include "certs.h"

#define EXT_SETUP_FUNCTION setup
#define EXT_TEARDOWN_FUNCTION teardown
#include "ext-ut.h"

static char module[] = "ENGINE";

static uint8_t buffer[100];

/*---------------------------------------------------------------------------*/
void
setup()
{
  auth_import_ca_cert(&ca);
  auth_import_own_cert(&c2_private_cert);
}
/*---------------------------------------------------------------------------*/
void
teardown()
{
  /* auth_free_service(); */
}
/*---------------------------------------------------------------------------*/
PROCESS(run_tests, "Unit tests for engine module");
AUTOSTART_PROCESSES(&run_tests);
/*---------------------------------------------------------------------------*/
UNIT_TEST_REGISTER(cache_incoming, "Cache incoming packets");
UNIT_TEST(cache_incoming)
{
  UNIT_TEST_BEGIN();

  uint8_t msg[] = "nothing";
  uint32_t len = sizeof(buffer);

  for(int i = 0; i < SEC_MAX_QUEUE_SIZE; ++i) {
    UNIT_TEST_ASSERT(process_incoming_packet(&NETWORK_NOT_SUPPORTED, msg, sizeof(msg), buffer, &len) == DROP_PACKET);
  }

  UNIT_TEST_END();
}
/*---------------------------------------------------------------------------*/
UNIT_TEST_REGISTER(cache_outcomming, "Cache outcomming packets");
UNIT_TEST(cache_outcomming)
{
  UNIT_TEST_BEGIN();

  uint8_t msg[] = "nothing";
  uint32_t len = sizeof(buffer);

  for(int i = 0; i < SEC_MAX_QUEUE_SIZE; ++i) {
    UNIT_TEST_ASSERT(process_outcomming_packet(&NETWORK_NOT_SUPPORTED, msg, sizeof(msg), buffer, &len) == DROP_PACKET);
  }

  UNIT_TEST_END();
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(run_tests, ev, data)
{
  PROCESS_BEGIN();
  register_module_name(module, sizeof(module));

  printf("\n\t RUN UNIT TESTS for %s\n\n", module);

  EXT_UT_RUN(cache_incoming);
  EXT_UT_RUN(cache_outcomming);

  printf("[=check-me=] %s DONE\n", module);

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
