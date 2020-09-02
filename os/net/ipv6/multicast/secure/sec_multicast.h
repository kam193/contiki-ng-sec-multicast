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
/**
 * \addtogroup uip-multicast
 * @{
 */
/**
 * \defgroup sec-multicast Secure Multicast Layer
 *
 *  Additional layer that implement a solution for secure
 *  transport multicast data.
 *
 * @{
 */
/**
 * \file
 * This file declare a multicast engine used to act as security
 * layer. The real multicast engine can be configured.
 *
 * \author
 *      Kamil Mańkowski  <kam193@wp.pl>
 *
 */

#ifndef SEC_MULTICAST_H_
#define SEC_MULTICAST_H_

#include "contiki.h"

/**
 * \brief Configure the multicast engine used in the underlay.
 * 
 * If not set in the configuration, the SMRF is used.
 *
 */
#ifndef SEC_MULTICAST_BASE_DRIVER

#define SEC_MULTICAST_BASE_DRIVER smrf_driver
#if UIP_MCAST6_ENGINE && UIP_MCAST6_ENGINE == UIP_MCAST6_ENGINE_SEC
#define RPL_WITH_MULTICAST     1
#endif

#endif

extern const struct uip_mcast6_driver SEC_MULTICAST_BASE_DRIVER;

#endif /* SEC_MULTICAST_H_ */
/** @} */
/** @} */
