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

#ifndef EXT_UT_H_
#define EXT_UT_H_

#include "contiki.h"
#include "services/unit-test/unit-test.h"

#define ASSERT_0(expr) UNIT_TEST_ASSERT((expr) == 0);
#define ASSERT_TRUE(expr) UNIT_TEST_ASSERT((expr) == true);
#define ASSERT_FALSE(expr) UNIT_TEST_ASSERT((expr) == false);

#ifdef EXT_SETUP_FUNCTION
#define EXT_SETUP() EXT_SETUP_FUNCTION();
void EXT_SETUP_FUNCTION();
#else
#define EXT_SETUP()
#endif

#ifdef EXT_TEARDOWN_FUNCTION
#define EXT_TEARDOWN() EXT_TEARDOWN_FUNCTION();
void EXT_TEARDOWN_FUNCTION();
#else
#define EXT_TEARDOWN()
#endif

#define EXT_UT_RUN(name) do { \
    EXT_SETUP(); \
    UNIT_TEST_RUN(name); \
    EXT_TEARDOWN(); \
} while(0);

#define MAX_MODULE_NAME 99

void register_module_name(const char *name, int len);

extern uip_ipaddr_t NETWORK_A;
extern uip_ipaddr_t NETWORK_NOT_SUPPORTED;

#endif