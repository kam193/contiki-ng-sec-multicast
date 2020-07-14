/**
 * \file    Header for secure multicast layer
 *         
 *
 * \author  Kamil Mańkowski
 *         
 */

#ifndef SEC_MULTICAST_H_
#define SEC_MULTICAST_H_

#include "contiki.h"
#include <stdint.h>

// By default use SMRF
#ifndef SEC_MULTICAST_BASE_DRIVER
#define RPL_WITH_MULTICAST     1
#define SEC_MULTICAST_BASE_DRIVER smrf_driver
#endif

const struct uip_mcast6_driver SEC_MULTICAST_BASE_DRIVER;

#endif /* SEC_MULTICAST_H_ */
