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
 *  No security mode implementation
 *
 * \author Kamil Mańkowski <kam193@wp.pl>
 *
 */
#include "common_engine.h"
#include "helpers.h"
#include "errors.h"

#include "sys/log.h"
#define LOG_MODULE  "sec_multicast"
#define LOG_LEVEL   LOG_LEVEL_SEC_MULTICAST
/*---------------------------------------------------------------------------*/
static int
init(group_security_descriptor_t *group_descriptor)
{
  group_descriptor->key_descriptor = NULL;
  return 0;
}
/*---------------------------------------------------------------------------*/
static int
refresh(group_security_descriptor_t *group_descriptor)
{
  return 0;
}
/*---------------------------------------------------------------------------*/
static void
free_descriptor(group_security_descriptor_t *group_descriptor)
{
  /* No need to free anything */
}
/*---------------------------------------------------------------------------*/
static int
copy_descriptor(group_security_descriptor_t *dest, group_security_descriptor_t *src)
{
  dest->key_descriptor = NULL;
  return 0;
}
/*---------------------------------------------------------------------------*/
static int
descr_to_bytes(group_security_descriptor_t *cert, uint8_t *buff, uint32_t *size)
{
  *size = 0;
  return 0;
}
/*---------------------------------------------------------------------------*/
static int
bytes_to_descriptor(group_security_descriptor_t *cert, const uint8_t *data, uint16_t size)
{
  cert->key_descriptor = NULL;
  return 0;
}
/*---------------------------------------------------------------------------*/
static int
encrypt_decrypt(group_security_descriptor_t *cert, const uint8_t *message, uint16_t message_len, uint8_t *out_buffer, uint32_t *out_len)
{
  if(*out_len < message_len) {
    return ERR_MEMORY;
  }
  memcpy(out_buffer, message, message_len);
  *out_len = message_len;
  return 0;
}
/*---------------------------------------------------------------------------*/
/**
 * \name No security mode
 * @{
 */
const secure_mode_driver_t none_driver = {
  .mode = SEC_MODE_NONE,
  .init_descriptor = init,
  .refresh_key = refresh,
  .copy_descriptor = copy_descriptor,
  .free_descriptor = free_descriptor,

  .descriptor_to_bytes = descr_to_bytes,
  .descriptor_from_bytes = bytes_to_descriptor,

  .encrypt = encrypt_decrypt,
  .decrypt = encrypt_decrypt,
};
/*---------------------------------------------------------------------------*/
/** @} */

/** @} */