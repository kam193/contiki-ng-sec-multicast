/**
 * \file
 *         Headers for RP functions
 *
 * \author  Kamil Mańkowski
 *
 */

#ifndef RP_H_
#define RP_H_

#include "engine.h"

#ifndef CERTEXCH_MAX_PROPAGATED_CERTS
#define CERTEXCH_MAX_PROPAGATED_CERTS 3
#endif

#ifndef SEC_MAX_SECURED_GROUPS
#define SEC_MAX_SECURED_GROUPS 10
#endif

int init_cert_server();
int secure_group(uip_ip6addr_t *maddr, uint16_t mode, uint16_t key_refresh_period);
int get_group_secure_description(const uip_ipaddr_t *group_addr, struct sec_certificate **cert_ptr);
/* TODO: rewrite / stop secured group */

#endif