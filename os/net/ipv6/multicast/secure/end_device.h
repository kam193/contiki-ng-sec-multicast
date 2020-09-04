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
 * \addtogroup sec-multicast-auth
 * @{
 */
/**
 * \file
 * Headers for Authorization and Communication Service (node part)
 *
 * \author Kamil Mańkowski <kam193@wp.pl>
 *
 */

#ifndef END_DEVICE_H_
#define END_DEVICE_H_

#include "net/ipv6/uip.h"
#include "authorization.h"

#define KEY_REQUEST_DATA_SIZE (TIMESTAMP_SIZE + sizeof(uip_ip6addr_t))

/**
 * \name End device authorization and communication features
 * @{
 */
/**
 * \brief Is server certificate set
 * 
 * \return true 
 * \return false 
 */
bool is_root_cert();

/** Remove current server certificate */
void free_root_cert();

/**
 * \brief Start requesting server certificate. 
 * This not guarantee getting the certificate. * 
 * \return int 0 when the requesting is started
 */
int get_root_cert();

/**
 * \brief Initialize the service
 * Register listening to the server answers 
 */
void init_communication_service();

/**
 * \brief Send a request for a group security descriptor
 * 
 * \param mcast_addr 
 * \return int 
 */
int send_request_group_key(const uip_ip6addr_t *mcast_addr);
/** @} */

#endif
/** @} */