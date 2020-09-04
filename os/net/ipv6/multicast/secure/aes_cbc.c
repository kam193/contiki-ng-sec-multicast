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
 *  AES-CBC-128 mode implementation
 *
 * \author Kamil Mańkowski <kam193@wp.pl>
 *
 */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>

#include "aes_cbc.h"

#include "common_engine.h"
#include "helpers.h"
#include "errors.h"

#include "sys/log.h"
#define LOG_MODULE  "sec_multicast"
#define LOG_LEVEL   LOG_LEVEL_SEC_MULTICAST

uint32_t return_code = 0;
extern uint8_t buffer[UIP_BUFSIZE];

/*---------------------------------------------------------------------------*/
/* AES helpers                                                               */
/*---------------------------------------------------------------------------*/
static int
count_aes_padded_size(uint8_t size)
{
  uint8_t padded_size = (size / 16) * 16;
  if(padded_size < size) {
    padded_size += 16;
  }
  return padded_size;
}
static int
aes_cbc_encrypt(group_security_descriptor_t *cert, const uint8_t *message, uint16_t message_len, uint8_t *out_buffer, uint32_t *out_len)
{
  aes_cbc_descriptor_t *current_descriptor = cert->key_descriptor;
  uint8_t vi[16];
  generate_random_chars(vi, 16);

  Aes encryption_engine;
  if((return_code = wc_AesSetKey(&encryption_engine, current_descriptor->aes_key,
                                 AES_BLOCK_SIZE, vi, AES_ENCRYPTION)) != 0) {
    return return_code;
  }

  uint16_t padded_size = count_aes_padded_size(message_len + sizeof(uint16_t));
  if(padded_size + sizeof(vi) > sizeof(buffer) || padded_size + sizeof(vi) > *out_len) {
    return ERR_LIMIT_EXCEEDED;
  }

  /* We need to store a message in encoded data in case of padding */
  memcpy(buffer, &message_len, sizeof(uint16_t));
  memcpy(buffer + sizeof(uint16_t), message, message_len);

  for(size_t i = message_len + sizeof(uint16_t); i < padded_size; ++i) {
    buffer[i] = RANDOM_CHAR();
  }

  if((return_code = wc_AesCbcEncrypt(&encryption_engine, out_buffer, buffer, padded_size)) != 0) {
    return return_code;
  }

  memcpy(out_buffer + padded_size, vi, sizeof(vi));
  *out_len = padded_size + sizeof(vi);
  return 0;
}
/*---------------------------------------------------------------------------*/
static int
aes_cbc_decrypt(group_security_descriptor_t *cert, const uint8_t *message,
                uint16_t message_len, uint8_t *out_buffer, uint32_t *out_len)
{
  uint32_t max_length = *out_len - sizeof(uint16_t);
  aes_cbc_descriptor_t *current_descriptor = cert->key_descriptor;
  uint8_t vi[16];

  if(message_len <= sizeof(vi)) {
    return ERR_INCORRECT_DATA;
  }
  memcpy(vi, message + (message_len - sizeof(vi)), sizeof(vi));

  Aes encryption_engine;
  if((return_code = wc_AesSetKey(&encryption_engine, current_descriptor->aes_key,
                                 AES_BLOCK_SIZE, vi, AES_DECRYPTION)) != 0) {
    return return_code;
  }

  if((return_code = wc_AesCbcDecrypt(&encryption_engine, out_buffer, message, message_len - sizeof(vi))) != 0) {
    return return_code;
  }

  /* Get len of original message and remove it from the packet */
  uint16_t original_length = *(uint16_t *)(out_buffer);
  memmove(out_buffer, out_buffer + sizeof(uint16_t), MIN(original_length, max_length));
  *out_len = MIN(original_length, max_length);
  return 0;
}
/*---------------------------------------------------------------------------*/
static int
aes_cbc_bytes_to_descriptor(group_security_descriptor_t *cert, const uint8_t *data, uint16_t size)
{
  if(sizeof(aes_cbc_descriptor_t) > size) {
    return ERR_INCORRECT_DATA;
  }
  cert->key_descriptor = malloc(sizeof(aes_cbc_descriptor_t));
  if(cert->key_descriptor == NULL) {
    return ERR_MEMORY;
  }
  memcpy(cert->key_descriptor, data, sizeof(aes_cbc_descriptor_t));
  return 0;
}
/*---------------------------------------------------------------------------*/
static int
aes_cbc_copy_descriptor(group_security_descriptor_t *dest, group_security_descriptor_t *src)
{
  dest->key_descriptor = malloc(sizeof(aes_cbc_descriptor_t));
  if(dest->key_descriptor == NULL) {
    return ERR_MEMORY;
  }
  memcpy(dest->key_descriptor, src->key_descriptor, sizeof(aes_cbc_descriptor_t));
  return 0;
}
/*---------------------------------------------------------------------------*/
/* Functions used on coordinator */
/*---------------------------------------------------------------------------*/
static int
init_aes_cbc_descriptor(group_security_descriptor_t *descriptor)
{
  descriptor->key_descriptor = malloc(sizeof(aes_cbc_descriptor_t));
  if(descriptor->key_descriptor == NULL) {
    return ERR_MEMORY;
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
static int
aes_cbc_descriptor_to_bytes(group_security_descriptor_t *cert, uint8_t *buff, uint32_t *size)
{
  if(sizeof(aes_cbc_descriptor_t) > *size) {
    return ERR_RESULT_TOO_LONG;
  }
  memcpy(buff, cert->key_descriptor, sizeof(aes_cbc_descriptor_t));
  *size = sizeof(aes_cbc_descriptor_t);
  return 0;
}
/*---------------------------------------------------------------------------*/
static int
aes_cbc_refresh_key(group_security_descriptor_t *key_descriptor)
{
  aes_cbc_descriptor_t *key_desc = key_descriptor->key_descriptor;
  generate_random_chars(key_desc->aes_key, sizeof(key_desc->aes_key));
  return 0;
}
/*---------------------------------------------------------------------------*/
/**
 * \name AES-CBC-128 support
 * @{
 */
const secure_mode_driver_t aes_cbc_driver = {
  .mode = SEC_MODE_AES_CBC,
  .init_descriptor = init_aes_cbc_descriptor,
  .refresh_key = aes_cbc_refresh_key,
  .copy_descriptor = aes_cbc_copy_descriptor,
  .free_descriptor = NULL,

  .descriptor_to_bytes = aes_cbc_descriptor_to_bytes,
  .descriptor_from_bytes = aes_cbc_bytes_to_descriptor,

  .encrypt = aes_cbc_encrypt,
  .decrypt = aes_cbc_decrypt,
};
/** @} */

/** @} */
