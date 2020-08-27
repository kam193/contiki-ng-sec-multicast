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

#ifndef SEC_MAX_SECURED_GROUPS
#define SEC_MAX_SECURED_GROUPS 10
#endif

int encode_cert_to_byte(struct sec_certificate *cert, uint32_t requestor_time, uint8_t *buff, uint32_t *size);
int secure_group(uip_ip6addr_t *maddr, uint16_t mode, uint16_t key_refresh_period); /* register_group_security(...) */
int get_group_secure_description(const uip_ipaddr_t *group_addr, struct sec_certificate **cert_ptr); /* get_group_security_descriptor(...) */
/* TODO: overwrite / stop secured group */

#endif