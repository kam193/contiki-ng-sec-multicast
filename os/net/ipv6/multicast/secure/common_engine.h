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
 * \addtogroup sec-multicast
 * @{
 */
/**
 * \defgroup sec-multicast-engine Group Security Engine
 *
 *  Engine responsible for manage and apply group security
 *
 * @{
 */ 
/**
 * \file
 * Common group secure engine functions
 *
 * \author Kamil Mańkowski <kam193@wp.pl>
 *
 */

#ifndef COMMON_ENGINE_H_
#define COMMON_ENGINE_H_

#include "contiki.h"
#include <stdint.h>

#include "net/ipv6/uip.h"

/**
 * \name Security modes
 * @{ 
 */
#define SEC_MODE_NONE         0 /* TODO: implement */
#define SEC_MODE_AES_CBC      1
/** @}  */

/* Certificate exchange constants */

/**
 * \name Configuration
 * @{ 
 */
/**
 * Port on the server. Default 5050
 */ 
#ifndef GROUP_SEC_SERVER_PORT
#define GROUP_SEC_SERVER_PORT 5050
#endif

/**
 * Port on the node. Default 6060
 */
#ifndef GROUP_SEC_NODE_PORT
#define GROUP_SEC_NODE_PORT 6060
#endif
/** @}  */

/**
 * \brief Store group security details.
 * Aliased as \ref group_security_descriptor_t
 */
struct group_security_descriptor {
  uip_ip6addr_t group_addr;
  uint8_t mode;
  uint32_t valid_until;
  void *key_descriptor;
};
typedef struct group_security_descriptor group_security_descriptor_t; /**< Alias to struct group_security_descriptor */

/**
 * \brief A driver to handle specific securing mode, e.g. AES-CBC.
 * Aliased as \ref secure_mode_driver_t
 */
struct secure_mode_driver {
  uint8_t mode;
  int (*init_descriptor) (group_security_descriptor_t *descriptor);
  int (*refresh_key) (group_security_descriptor_t *key_descriptor);
  int (*copy_descriptor) (group_security_descriptor_t *dest, group_security_descriptor_t *src);
  void (*free_descriptor) (group_security_descriptor_t *descriptor);

  int (*descriptor_to_bytes) (group_security_descriptor_t *cert, uint8_t *buff, uint32_t *size);
  int (*descriptor_from_bytes) (group_security_descriptor_t *cert, const uint8_t *data, uint16_t size);

  int (*encrypt) (group_security_descriptor_t *cert, unsigned char *message, uint16_t message_len, unsigned char *out_buffer, uint32_t *out_len);
  int (*decrypt) (group_security_descriptor_t *cert, unsigned char *message, uint16_t message_len, unsigned char *out_buffer, uint32_t *out_len);
};
typedef struct secure_mode_driver secure_mode_driver_t; /**< Alias to the struct secure_mode_driver */

/** Deep copy of a descriptor */
int copy_group_descriptor(group_security_descriptor_t *dest, group_security_descriptor_t *src);

/**
 * \brief Get the mode driver object
 * 
 * \param mode 
 * \return const secure_mode_driver_t* Pointer to the driver or NULL if not exists
 */
const secure_mode_driver_t *get_mode_driver(uint8_t mode);

#endif
/** @} */
/** @} */