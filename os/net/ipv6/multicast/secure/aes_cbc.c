
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>

#include "aes_cbc.h"
#include "common_engine.h"
#include "helpers.h"
#include "errors.h"

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"
#include "tmp_debug.h"

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
int
aes_cbc_encrypt(group_security_descriptor_t *cert, unsigned char *message, uint16_t message_len, unsigned char *out_buffer, uint32_t *out_len)
{
  struct secure_descriptor *current_descriptor = cert->key_descriptor;
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
int
aes_cbc_decrypt(group_security_descriptor_t *cert, unsigned char *message,
                uint16_t message_len, unsigned char *out_buffer, uint32_t *out_len)
{
  uint32_t max_length = *out_len - sizeof(uint16_t);
  struct secure_descriptor *current_descriptor = cert->key_descriptor;
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
int
aes_cbc_bytes_to_descriptor(group_security_descriptor_t *cert, const uint8_t *data, uint16_t size)
{
  if(sizeof(struct secure_descriptor) > size) {
    return ERR_INCORRECT_DATA;
  }
  cert->key_descriptor = malloc(sizeof(struct secure_descriptor));
  if(cert->key_descriptor == NULL) {
    return ERR_MEMORY;
  }
  memcpy(cert->key_descriptor, data, sizeof(struct secure_descriptor));
  return 0;
}
/*---------------------------------------------------------------------------*/
int
aes_cbc_copy_descriptor(group_security_descriptor_t *dest, group_security_descriptor_t *src)
{
  dest->key_descriptor = malloc(sizeof(struct secure_descriptor));
  if(dest->key_descriptor == NULL) {
    return ERR_MEMORY;
  }
  memcpy(dest->key_descriptor, src->key_descriptor, sizeof(struct secure_descriptor));
  return 0;
}
/*---------------------------------------------------------------------------*/
/* Functions used on coordinator */
/*---------------------------------------------------------------------------*/
int
init_aes_cbc_descriptor(group_security_descriptor_t *descriptor)
{
  descriptor->key_descriptor = malloc(sizeof(struct secure_descriptor));
  if(descriptor->key_descriptor == NULL) {
    return ERR_MEMORY;
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
int
aes_cbc_descriptor_to_bytes(group_security_descriptor_t *cert, uint8_t *buff, uint32_t *size)
{
  if(sizeof(struct secure_descriptor) > *size) {
    return ERR_RESULT_TOO_LONG;
  }
  memcpy(buff, cert->key_descriptor, sizeof(struct secure_descriptor));
  *size = sizeof(struct secure_descriptor);
  return 0;
}
/*---------------------------------------------------------------------------*/
int
aes_cbc_refresh_key(group_security_descriptor_t *key_descriptor)
{
  struct secure_descriptor *key_desc = key_descriptor->key_descriptor;
  generate_random_chars(key_desc->aes_key, sizeof(key_desc->aes_key));
  generate_random_chars(key_desc->aes_vi, sizeof(key_desc->aes_vi));
  return 0;
}
/*---------------------------------------------------------------------------*/
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