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
/*---------------------------------------------------------------------------*/
#include "contiki.h"
#include "os/net/ipv6/multicast/secure/authorization.h"

#include <stdio.h>

#include "certs.h"

#define EXT_SETUP_FUNCTION setup
#define EXT_TEARDOWN_FUNCTION teardown
#include "ext-ut.h"

static char module[] = "AUTHORIZATION";

/* TODO: setup & teardown */
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
  auth_free_service();
}
/*---------------------------------------------------------------------------*/
PROCESS(run_tests, "Unit tests for authorization module");
AUTOSTART_PROCESSES(&run_tests);
/*---------------------------------------------------------------------------*/
UNIT_TEST_REGISTER(importing_ca, "Importing CA and work before it");
UNIT_TEST(importing_ca)
{
  UNIT_TEST_BEGIN();

  ASSERT_0(auth_import_ca_cert(&ca));
  ASSERT_TRUE(is_auth_ca_cert());

  auth_free_service();
  ASSERT_FALSE(is_auth_ca_cert());
  UNIT_TEST_ASSERT(auth_verify_cert(&c2_private_cert) == ERR_NOT_INITIALIZED);

  /* TODO: not init for any method that use CA or so */

  UNIT_TEST_END();
}
/*---------------------------------------------------------------------------*/
UNIT_TEST_REGISTER(cert_verification, "Verify cert authentication");
UNIT_TEST(cert_verification)
{
  UNIT_TEST_BEGIN();

  ASSERT_0(auth_verify_cert(&rp_private_cert));
  ASSERT_0(auth_verify_cert(&c2_private_cert));

  UNIT_TEST_ASSERT(auth_verify_cert(&alt_private_cert) == ERR_VERIFY_FAILED);

  UNIT_TEST_END();
}
/*---------------------------------------------------------------------------*/
UNIT_TEST_REGISTER(free_service, "Free service");
UNIT_TEST(free_service)
{
  UNIT_TEST_BEGIN();

  auth_free_service();
  ASSERT_FALSE(is_auth_ca_cert());
  UNIT_TEST_ASSERT(auth_own_pub_cert() == NULL);

  UNIT_TEST_END();
}
/*---------------------------------------------------------------------------*/
/* UNIT_TEST_REGISTER(test_example_failed, "Example failing unit test"); */
/* UNIT_TEST(test_example_failed) */
/* { */
/*   uint32_t value = 1; */

/*   UNIT_TEST_BEGIN(); */

/*   UNIT_TEST_ASSERT(value == 0); */

/*   UNIT_TEST_END(); */
/* } */
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(run_tests, ev, data)
{
  PROCESS_BEGIN();
  register_module_name(module, sizeof(module));

  printf("\n\t RUN UNIT TESTS for %s\n\n", module);

  EXT_UT_RUN(cert_verification);
  EXT_UT_RUN(importing_ca);
  EXT_UT_RUN(free_service);

  printf("[=check-me=] %s DONE\n", module);

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
