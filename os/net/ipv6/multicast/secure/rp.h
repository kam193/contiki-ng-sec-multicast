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

int init_cert_server();
int propagate_certificate(struct sec_certificate* cert);
// TODO: stop propagating

#endif