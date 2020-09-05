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

#ifndef BASE_CONF_H_
#define BASE_CONF_H_

#include "net/ipv6/multicast/uip-mcast6-engines.h"

#ifdef MCAST_ONLY_DEVICE    /* For devices without multicast security */
#define UIP_MCAST6_CONF_ENGINE UIP_MCAST6_ENGINE_SMRF

/* For MPL use: */
/* #define UIP_MCAST6_CONF_ENGINE UIP_MCAST6_ENGINE_MPL */
/* #define RPL_WITH_MULTICAST     0 */
/* #define MPL_CONF_DOMAIN_SET_SIZE 3 */

#else
#define UIP_MCAST6_CONF_ENGINE UIP_MCAST6_ENGINE_SEC

/* For MPL use: */
/* #define SEC_MULTICAST_BASE_DRIVER mpl_driver */
/* #define RPL_WITH_MULTICAST     0 */
/* #define MPL_CONF_DOMAIN_SET_SIZE 3 */
/* REMEMBER to patch os/net/ipv6/uip6.c in about 857 line */
/* the command "#if UIP_MCAST6_ENGINE == UIP_MCAST6_ENGINE_MPL" */
#endif

#define LOG_CONF_LEVEL_SEC_MULTICAST LOG_LEVEL_ERR
#define LOG_CONF_LEVEL_RPL LOG_LEVEL_DBG

#endif
