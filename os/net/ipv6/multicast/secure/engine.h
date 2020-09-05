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
 * Header for providing secure functions for messages. This is
 * Local Secure Functions Module
 *
 * \author Kamil Mańkowski <kam193@wp.pl>
 *
 */

#ifndef ENGINE_H_
#define ENGINE_H_

#include "contiki.h"
#include <stdint.h>

#include "net/ipv6/uip.h"
#include "errors.h"
#include "common_engine.h"
#include "aes_cbc.h"
#include "none_mode.h"

/**
 * \name Node configuration
 * @{
 */
#ifndef SEC_MAX_GROUP_DESCRIPTORS
#define SEC_MAX_GROUP_DESCRIPTORS 3
#endif

#ifndef SEC_MAX_QUEUE_SIZE
#define SEC_MAX_QUEUE_SIZE 5
#endif

#ifndef SEC_QUEUE_RETRY_TIME
#define SEC_QUEUE_RETRY_TIME 3000
#endif

#ifndef SEC_QUEUE_MAX_RETRY
#define SEC_QUEUE_MAX_RETRY 5
#endif

#ifndef SEC_MODE_DRIVERS_LIST
#define SEC_MODE_DRIVERS_PTR_LIST &aes_cbc_driver, &none_driver
#endif
/** @} */

/**
 * \name Packet processing
 * @{
 */
#define PROCESS_UPPER   0
#define DROP_PACKET     1

int process_incoming_packet(uip_ip6addr_t *dest_addr, uint8_t *message, uint16_t message_len, uint8_t *out_buffer, uint32_t *out_len);
int process_outcomming_packet(uip_ip6addr_t *dest_addr, uint8_t *message, uint16_t message_len, uint8_t *out_buffer, uint32_t *out_len);
/** @} */

/**
 * \name Group security descriptors management.
 * @{
 */
int decode_bytes_to_security_descriptor(group_security_descriptor_t *cert, const uint8_t *data, uint16_t size);
int import_group_security_descriptor(group_security_descriptor_t *certificate);
/** @} */

extern int mark_packet_from_cache;

/* TODO: general init engine */

#endif
/** @} */
