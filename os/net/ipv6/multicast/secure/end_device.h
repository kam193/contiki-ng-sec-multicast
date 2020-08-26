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

/* Certificate Exchange */

int get_certificate_for(uip_ip6addr_t *mcast_addr); //-> private
int get_rp_cert(); // -> private? 

#endif