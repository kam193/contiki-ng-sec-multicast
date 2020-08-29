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
#include "ext-ut.h"

static char module[] = "AUTHORIZATION";

#include <stdio.h>
/*---------------------------------------------------------------------------*/
PROCESS(run_tests, "Unit tests for authorization module");
AUTOSTART_PROCESSES(&run_tests);
/*---------------------------------------------------------------------------*/
UNIT_TEST_REGISTER(test_example, "Example unit test");
UNIT_TEST(test_example)
{
  uint32_t value = 1;

  UNIT_TEST_BEGIN();

  UNIT_TEST_ASSERT(value == 1);
  
  UNIT_TEST_END();
}
/*---------------------------------------------------------------------------*/
UNIT_TEST_REGISTER(test_example_failed, "Example failing unit test");
UNIT_TEST(test_example_failed)
{
  uint32_t value = 1;

  UNIT_TEST_BEGIN();

  UNIT_TEST_ASSERT(value == 0);
  
  UNIT_TEST_END();
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(run_tests, ev, data)
{
  PROCESS_BEGIN();
  register_module_name(module, sizeof(module));

  printf("\n\t RUN UNIT TESTS for %s\n\n", module);

  UNIT_TEST_RUN(test_example);
  UNIT_TEST_RUN(test_example_failed);

  printf("[=check-me=] %s DONE\n", module);

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
