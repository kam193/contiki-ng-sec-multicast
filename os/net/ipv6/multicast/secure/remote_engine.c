/**
 * \file
 *         This file provides functionality needed for Randevou Point
 *
 * \author  Kamil Mańkowski
 *
 */

#include "contiki.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include "net/ipv6/multicast/secure/sec_multicast.h"
#include "net/packetbuf.h"
#include "net/ipv6/simple-udp.h"
#include "os/lib/heapmem.h"
#include "lib/random.h"

#include "remote_engine.h"
#include "common_engine.h"
#include "encryptions.h"
#include "authorization.h"
#include "helpers.h"

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"
#include "tmp_debug.h"

#define MAX_ANSWER_LENGTH 1000

struct secured_group {
  bool occupied;
  uint16_t refresh_period_sec;
  struct sec_certificate key_descriptor;
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

  /* group_descriptor->last_refresh_sec = clock_seconds(); */
  group_descriptor->key_descriptor.valid_until = clock_seconds() + group_descriptor->refresh_period_sec;
  PRINTF("Group key for ");
  PRINT6ADDR(&group_descriptor->key_descriptor.group_addr);
  PRINTF(" recreated\n");
  return 0;
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
get_group_secure_description(const uip_ipaddr_t *group_addr, struct sec_certificate **cert_ptr)
{
  secured_group_t *descriptor;
  if((descriptor = find_group_descriptor(group_addr)) == NULL) {
    /* TODO: default behaviour */
    *cert_ptr = NULL;
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
encode_cert_to_byte(struct sec_certificate *cert, uint32_t requestor_time, uint8_t *buff, uint32_t *size)
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
init_key_descriptor(struct sec_certificate *descriptor, uip_ip6addr_t *maddr, uint16_t mode)
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
secure_group(uip_ip6addr_t *maddr, uint16_t mode, uint16_t key_refresh_period)
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
    PRINTF("Now secure group ");
    PRINT6ADDR(maddr);
    PRINTF("\n");
    return 0;
  }
  return ERR_OTHER;
}
