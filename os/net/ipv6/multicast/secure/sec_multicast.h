/**
 * \file
 *      Header for secure multicast layer
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
#define SEC_MULTICAST_BASE_DRIVER smrf_driver

#if UIP_MCAST6_ENGINE && UIP_MCAST6_ENGINE == UIP_MCAST6_ENGINE_SEC
#define RPL_WITH_MULTICAST     1
#endif
#endif

extern struct uip_mcast6_driver SEC_MULTICAST_BASE_DRIVER;

#endif /* SEC_MULTICAST_H_ */
