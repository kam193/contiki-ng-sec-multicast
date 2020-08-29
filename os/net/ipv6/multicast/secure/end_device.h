/**
 * \file
 *    Headers for Authorization and Communication Service (end device
 *    communication part).
 *
 *
 * \author  Kamil Mańkowski
 *
 */

#ifndef END_DEVICE_H_
#define END_DEVICE_H_

#include "net/ipv6/uip.h"
#include "authorization.h"

bool is_root_cert();
void free_root_cert();
int get_rp_cert(); /* -> private? */

void init_communication_service();
int send_request_group_key(const uip_ip6addr_t *mcast_addr);

int certexch_import_rp_cert(const device_cert_t *cert);
const device_cert_t *certexch_rp_pub_cert();

#endif