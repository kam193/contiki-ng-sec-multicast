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
 * \addtogroup sec-multicast-engine
 * @{
 */
/**
 * \file
 * Headers for the engine on server
 *
 * \author Kamil Mańkowski <kam193@wp.pl>
 *
 */

#ifndef REMOTE_ENGINE_H_
#define REMOTE_ENGINE_H_

#include "common_engine.h"

/**
 * \name Server engine configuration
 * @{
 */
#ifndef SEC_MAX_SECURED_GROUPS
#define SEC_MAX_SECURED_GROUPS 10
#endif
/** @} */

/**
 * \name Server part group security management.
 * @{
 */
int encode_security_descriptor_to_bytes(group_security_descriptor_t *cert, uint32_t requestor_time, uint8_t *buff, uint32_t *size);
int register_group_security(uip_ip6addr_t *maddr, uint16_t mode, uint16_t key_refresh_period);
int get_group_security_descriptor(const uip_ipaddr_t *group_addr, group_security_descriptor_t **cert_ptr);
/** @} */

/* TODO: overwrite / stop secured group */

#endif
/** @} */