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
int propagate_certificate(struct sec_certificate *cert);
int secure_group(uip_ip6addr_t *maddr, uint16_t mode, uint16_t key_refresh_period);
/* TODO: stop propagating */

#endif