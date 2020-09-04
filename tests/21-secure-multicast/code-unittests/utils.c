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

#include <stdio.h>
#include <memory.h>

#include "net/ipv6/uip-ds6.h"

#include "ext-ut.h"

static char module_name[MAX_MODULE_NAME + 1] = { 0 };

uip_ipaddr_t NETWORK_A = { { 0xFF, 0x1E, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x89, 0xA0, 0x0D } };
uip_ipaddr_t NETWORK_NOT_SUPPORTED = { { 0xFF, 0x1E, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x89, 0xA1, 0x1D } };

void
register_module_name(const char *name, int len)
{
  memset(module_name, 0, MAX_MODULE_NAME + 1);
  memcpy(module_name, name, MIN(len, MAX_MODULE_NAME));
}
void
print_test_report(const unit_test_t *utp)
{
  printf("[=check-me=] %s: %s... ", module_name, utp->descr);
  if(utp->result == unit_test_failure) {
    printf("FAILED at line %u\n", utp->exit_line);
  } else {
    printf("SUCCEEDED\n");
  }
}