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
/**
 * \addtogroup sec-multicast-engine
 * @{
 */
/**
 * \file
 * This file provides functionality needed for the engine on server
 *
 * \author Kamil Mańkowski <kam193@wp.pl>
 *
 */

#include "contiki.h"
#include "contiki-net.h"

#include "remote_engine.h"

#include "common_engine.h"
#include "authorization.h"
#include "helpers.h"

#include "sys/log.h"
#define LOG_MODULE  "sec_multicast"
#define LOG_LEVEL   LOG_LEVEL_SEC_MULTICAST

#define MAX_ANSWER_LENGTH 1000

struct secured_group {
  bool occupied;
  uint16_t refresh_period_sec;
  group_security_descriptor_t key_descriptor;
};
typedef struct secured_group secured_group_t;

secured_group_t groups[SEC_MAX_SECURED_GROUPS];
static size_t free_group_places = SEC_MAX_SECURED_GROUPS;

/*---------------------------------------------------------------------------*/
/* KEY GENERATION HELPERS */
/*---------------------------------------------------------------------------*/
static int
recreate_group_key(secured_group_t *group_descriptor)
{
  const secure_mode_driver_t *driver = get_mode_driver(group_descriptor->key_descriptor.mode);
  if(driver == NULL) {
    return ERR_UNSUPPORTED_MODE;
  }
  CHECK_0(driver->refresh_key(&group_descriptor->key_descriptor));

  group_descriptor->key_descriptor.valid_until = clock_seconds() + group_descriptor->refresh_period_sec;
  LOG_DBG("Group key for ");
  LOG_6ADDR(LOG_LEVEL_DBG, &group_descriptor->key_descriptor.group_addr);
  LOG_DBG(" recreated\n");
  return 0;
}
/*---------------------------------------------------------------------------*/
group_security_descriptor_t *
sec_default_drop(const uip_ip6addr_t *addr)
{
  return NULL;
}
/*---------------------------------------------------------------------------*/
secured_group_t *
find_group_descriptor(const uip_ip6addr_t *addr)
{
  if(free_group_places == SEC_MAX_SECURED_GROUPS) {
    return NULL;
  }
  for(size_t i = 0; i < SEC_MAX_SECURED_GROUPS; ++i) {
    if(groups[i].occupied == true && uip_ip6addr_cmp(addr, &groups[i].key_descriptor.group_addr)) {
      return &groups[i];
    }
  }
  return NULL;
}
/*---------------------------------------------------------------------------*/
/* Get current secure descriptor of the group, ready to use */
int
get_group_security_descriptor(const uip_ipaddr_t *group_addr, group_security_descriptor_t **cert_ptr)
{
  secured_group_t *descriptor;
  if((descriptor = find_group_descriptor(group_addr)) == NULL) {
    *cert_ptr = SEC_DEFAULT_ACTION(group_addr);
    if(*cert_ptr != NULL) {
      LOG_DBG("Default action created a descriptor.\n");
      return 0;
    }
    return ERR_OTHER;
  }

  if(descriptor->key_descriptor.valid_until == 0 ||
     descriptor->key_descriptor.valid_until <= clock_seconds()) {
    CHECK_0(recreate_group_key(descriptor));
  }

  *cert_ptr = &descriptor->key_descriptor;
  return 0;
}
/*---------------------------------------------------------------------------*/
/* Decode cert to chain of byte: ADDR | MODE | VALID_UNTIL | <descriptor> */
/* Descriptor depends of MODE and basically is a chain of fields */
/*---------------------------------------------------------------------------*/
int
encode_security_descriptor_to_bytes(group_security_descriptor_t *cert, uint32_t requestor_time, uint8_t *buff, uint32_t *size)
{
  uint32_t result_size = 0, descriptor_size = 0;
  const secure_mode_driver_t *driver = get_mode_driver(cert->mode);
  if(driver == NULL) {
    return ERR_UNSUPPORTED_MODE;
  }

  /* Copy header */
  if(result_size + sizeof(uip_ip6addr_t) + 1 > *size) {
    return -1;
  }
  memcpy(buff, &cert->group_addr, sizeof(uip_ip6addr_t) + 1);
  result_size += sizeof(uip_ip6addr_t) + 1;

  /* Copy time translated to requestor time */
  *(uint32_t *)(buff + result_size) = (requestor_time + (cert->valid_until - clock_seconds()));
  result_size += sizeof(uint32_t);

  /* Copy descriptor depends of mode */
  descriptor_size = *size - result_size;
  CHECK_0(driver->descriptor_to_bytes(cert, buff + result_size, &descriptor_size));

  *size = result_size + descriptor_size;
  return 0;
}
/*---------------------------------------------------------------------------*/
/* KEY DESCRIPTORS INITIALIZERS */
/*---------------------------------------------------------------------------*/
/* Create key descriptor for group */
int
init_key_descriptor(group_security_descriptor_t *descriptor, uip_ip6addr_t *maddr, uint16_t mode)
{
  uip_ip6addr_copy(&descriptor->group_addr, maddr);
  descriptor->mode = mode;

  const secure_mode_driver_t *driver = get_mode_driver(mode);
  if(driver == NULL) {
    return ERR_UNSUPPORTED_MODE;
  }
  return driver->init_descriptor(descriptor);
}
/* Let's RP manage given group:which group, which mode and when refreshing key */
int
register_group_security(uip_ip6addr_t *maddr, uint16_t mode, uint16_t key_refresh_period)
{
  if(find_group_descriptor(maddr) != NULL) {
    return ERR_GROUP_EXISTS;
  }
  if(free_group_places == 0) {
    return ERR_LIMIT_EXCEEDED;
  }
  for(size_t i = 0; i < SEC_MAX_SECURED_GROUPS; ++i) {
    if(groups[i].occupied == true) {
      continue;
    }
    free_group_places--;
    groups[i].occupied = true;
    groups[i].key_descriptor.valid_until = 0;
    groups[i].refresh_period_sec = key_refresh_period;
    init_key_descriptor(&groups[i].key_descriptor, maddr, mode);
    LOG_INFO("Set security config for group ");
    LOG_6ADDR(LOG_LEVEL_INFO, maddr);
    LOG_INFO("\n");
    return 0;
  }
  return ERR_OTHER;
}
/** @} */